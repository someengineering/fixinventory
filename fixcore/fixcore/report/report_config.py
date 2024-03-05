from __future__ import annotations

import logging
from typing import List, Optional, Dict, ClassVar

from attr import define, field

from fixcore.config import ConfigEntity
from fixcore.model.typed_model import from_js
from fixcore.report import (
    ReportSeverity,
    CheckConfigRoot,
    ReportCheck,
    Benchmark,
    Remediation,
    BenchmarkConfigRoot,
    ReportConfigRoot,
)
from fixcore.types import Json
from fixlib.core.model_export import dataclasses_to_fixcore_model
from fixcompliance import benchmarks_from_files, checks_from_files

log = logging.getLogger(__name__)


@define
class ReportCheckConfig:
    kind: ClassVar[str] = "fix_core_report_check"
    name: str = field(
        metadata={
            "description": "Name of this check. Must be unique within the provider and service.",
            "Example": "unused_elastic_ip",
        }
    )
    title: str = field(metadata={"description": "Title of the check."})
    result_kinds: List[str] = field(
        metadata={"description": "Resulting kind this check will emit. Example: aws_ec2_instance"}
    )
    categories: List[str] = field(metadata={"description": "Categories of the check. Example: ['security', 'cost']"})
    severity: ReportSeverity = field(metadata={"description": "Severity of the check."})
    risk: str = field(metadata={"description": "What is the risk associated with related resources."})
    detect: Dict[str, str] = field(
        metadata={
            "description": "Defines possible detection methods.\n"
            "`fix` defines a Fix search, `fix_cmd` a Fix CLI command.\n "
            "At least one of `fix` or `fix_cmd` must be defined.\n"
            "Additional keys can be defined on top."
        }
    )
    remediation: Remediation = field(metadata={"description": "Remediation action for the check."})
    default_values: Optional[Json] = field(
        default=None,
        metadata={"description": "Default values for the check. Will be merged with the values from the config."},
    )
    url: Optional[str] = field(default=None, metadata={"description": "URL that documents the check."})
    related: Optional[List[str]] = field(default=None, metadata={"description": "List of related checks."})
    internal_notes: Optional[str] = field(default=None, metadata={"description": "Internal notes for the check."})


@define
class ReportCheckCollectionConfig:
    kind: ClassVar[str] = CheckConfigRoot
    provider: str = field(metadata={"description": "Cloud provider of all checks."})
    service: str = field(metadata={"description": "Cloud provider service of all checks."})
    checks: List[ReportCheckConfig] = field(factory=list, kw_only=True, metadata={"description": "List of checks."})

    @staticmethod
    def from_files() -> Dict[str, Json]:
        return checks_from_files()

    @staticmethod
    def from_config(cfg: ConfigEntity) -> List[ReportCheck]:
        return ReportCheckCollectionConfig.from_json(cfg.config[CheckConfigRoot])

    @staticmethod
    def from_json(js: Json) -> List[ReportCheck]:
        def report_check(pdr: str, svc: str, check: Json) -> ReportCheck:
            cr = check.copy()
            cr["provider"] = pdr
            cr["service"] = svc
            cr["id"] = f"{pdr}_{svc}_{check['name']}"
            # handle legacy result_kind
            if "result_kind" in cr and "result_kinds" not in cr:
                cr["result_kinds"] = [cr.pop("result_kind")]
            return from_js(cr, ReportCheck)

        pdr = js["provider"]
        svc = js["service"]
        return [report_check(pdr, svc, check) for check in js["checks"]]


@define
class CheckCollectionConfig:
    kind: ClassVar[str] = "fix_core_report_check_collection"
    title: str = field(metadata={"description": "Title of the benchmark or report check collection."})
    description: str = field(metadata={"description": "Description of the benchmark."})
    documentation: Optional[str] = field(default=None, kw_only=True, metadata={"description": "Documentation URL."})
    checks: Optional[List[str]] = field(
        default=None, kw_only=True, metadata={"description": "List of checks to perform."}
    )
    children: Optional[List[CheckCollectionConfig]] = field(
        default=None, kw_only=True, metadata={"description": "Nested collections."}
    )

    def is_valid(self, checks: Dict[str, ReportCheck]) -> bool:
        return (
            not (self.children and self.checks)
            and all(c in checks for c in self.checks or [])  # pylint: disable=not-an-iterable
            and all(c.is_valid(checks) for c in self.children or [])  # pylint: disable=not-an-iterable
        )


@define
class BenchmarkConfig(CheckCollectionConfig):
    kind: ClassVar[str] = BenchmarkConfigRoot

    id: str = field(metadata={"description": "Unique ID of the benchmark."})
    framework: str = field(metadata={"description": "Framework the benchmark is based on."})
    version: str = field(metadata={"description": "Version of the benchmark."})
    clouds: Optional[List[str]] = field(
        default=None,
        metadata={
            "description": "List of applicable cloud providers. "
            "If the benchmark is not cloud specific, the value would be null."
        },
    )

    @staticmethod
    def from_files() -> Dict[str, Json]:
        return benchmarks_from_files()

    @staticmethod
    def from_config(cfg: ConfigEntity) -> Benchmark:
        # Benchmark and BenchmarkConfig are structurally identical.
        # If Benchmark needs to change, the config is here to have a migration path.
        return from_js(cfg.config[BenchmarkConfigRoot], Benchmark)


@define
class ReportConfig:
    kind: ClassVar[str] = ReportConfigRoot

    ignore_checks: Optional[List[str]] = field(default=None, metadata={"description": "List of checks to ignore."})
    ignore_accounts: Optional[List[str]] = field(default=None, metadata={"description": "List of accounts to ignore."})
    override_values: Optional[Json] = field(
        default=None,
        metadata={"description": "Default values for the report. Will be merged with the values from the config."},
    )

    def check_allowed(self, check_id: str) -> bool:
        return not self.ignore_checks or check_id not in self.ignore_checks


def config_model() -> List[Json]:
    config_classes = {ReportCheckCollectionConfig, BenchmarkConfig, ReportConfig}
    return dataclasses_to_fixcore_model(config_classes, use_optional_as_required=True)
