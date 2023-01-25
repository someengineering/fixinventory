from __future__ import annotations

import json
import logging
import os
from os.path import basename
from typing import List, Optional, Dict, ClassVar

from attr import define, field

from resotocore.config import ConfigEntity
from resotocore.model.typed_model import from_js
from resotocore.report import (
    ReportSeverity,
    CheckConfigRoot,
    ReportCheck,
    Benchmark,
    Remediation,
    BenchmarkConfigRoot,
)
from resotocore.types import Json
from resotolib.core.model_export import dataclasses_to_resotocore_model

log = logging.getLogger(__name__)


@define
class ReportCheckConfig:
    kind: ClassVar[str] = "resoto_core_report_check"
    name: str = field(
        metadata={
            "description": "Name of this check. Must be unique within the provider and service.",
            "Example": "unused_elastic_ip",
        }
    )
    title: str = field(metadata={"description": "Title of the check."})
    result_kind: str = field(metadata={"description": "Resulting kind this check will emit. Example: aws_ec2_instance"})
    categories: List[str] = field(metadata={"description": "Categories of the check. Example: ['security', 'cost']"})
    severity: ReportSeverity = field(metadata={"description": "Severity of the check."})
    risk: str = field(metadata={"description": "What is the risk associated with related resources."})
    detect: Dict[str, str] = field(
        metadata={
            "description": "Defines possible detection methods.\n"
            "`resoto` defines a Resoto search, `resoto_cmd` a Resoto CLI command.\n "
            "At least one of `resoto` or `resoto_cmd` must be defined.\n"
            "Additional keys can be defined on top."
        }
    )
    remediation: Remediation = field(metadata={"description": "Remediation action for the check."})
    default_values: Optional[Json] = field(
        default=None,
        metadata={"description": "Default values for the check. Will be merged with the values from the config."},
    )
    url: Optional[str] = field(default=None, metadata={"description": "URL that documents the check."})
    related: List[str] = field(factory=list, metadata={"description": "List of related checks."})
    internal_notes: Optional[str] = field(default=None, metadata={"description": "Internal notes for the check."})


@define
class ReportCheckCollectionConfig:
    kind: ClassVar[str] = CheckConfigRoot
    provider: str = field(metadata={"description": "Cloud provider of all checks."})
    service: str = field(metadata={"description": "Cloud provider service of all checks."})
    checks: List[ReportCheckConfig] = field(factory=list, kw_only=True, metadata={"description": "List of checks."})

    @staticmethod
    def from_files() -> Dict[str, Json]:
        # load the checks from the report directory
        static_path = os.path.abspath(os.path.dirname(__file__) + "/../static/report/checks")
        result = {}
        if os.path.exists(static_path):
            for provider in (d.path for d in os.scandir(static_path) if d.is_dir()):
                for service in (d.path for d in os.scandir(provider) if d.is_file() and d.name.endswith(".json")):
                    with open(service, "rt", encoding="utf-8") as f:
                        result[basename(service).rsplit(".", maxsplit=1)[0]] = json.load(f)
        return result

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
            return from_js(cr, ReportCheck)

        pdr = js["provider"]
        svc = js["service"]
        return [report_check(pdr, svc, check) for check in js["checks"]]


@define
class CheckCollectionConfig:
    kind: ClassVar[str] = "resoto_core_report_check_collection"
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

    @staticmethod
    def from_files() -> Dict[str, Json]:
        # load the benchmarks from the report directory
        static_path = os.path.abspath(os.path.dirname(__file__) + "/../static/report/benchmark")
        result = {}
        if os.path.exists(static_path):
            for provider in (d.path for d in os.scandir(static_path) if d.is_dir()):
                for path in (d.path for d in os.scandir(provider) if d.is_file() and d.name.endswith(".json")):
                    with open(path, "rt", encoding="utf-8") as f:
                        result[basename(path).rsplit(".", maxsplit=1)[0]] = json.load(f)
        return result

    @staticmethod
    def from_config(cfg: ConfigEntity) -> Benchmark:
        # Benchmark and BenchmarkConfig are structurally identical.
        # If Benchmark needs to change, the config is here to have a migration path.
        return from_js(cfg.config[BenchmarkConfigRoot], Benchmark)


def config_model() -> List[Json]:
    config_classes = {ReportCheckCollectionConfig, BenchmarkConfig}
    return dataclasses_to_resotocore_model(config_classes, allow_unknown_props=False)
