from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Optional, Dict, ClassVar

from attr import define, field

from resotocore.ids import ConfigId
from resotocore.model.typed_model import from_js
from resotocore.types import Json
from resotolib.core.model_export import dataclasses_to_resotocore_model
from resotolib.json import from_json

log = logging.getLogger(__name__)

ValuesConfigId = ConfigId("resoto.report.values")
CheckConfigPrefix = "resoto.report.check."
CheckConfigRoot = "report_check"
BenchmarkConfigPrefix = "resoto.report.benchmark."
BenchmarkConfigRoot = "report_benchmark"


class ReportSeverity(Enum):
    kind: ClassVar[str] = "resoto_core_report_check_severity"
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


@define
class Remediation:
    kind: ClassVar[str] = "resoto_core_report_check_remediation"
    text: str = field(metadata={"description": "Textual description of the remediation."})
    url: str = field(metadata={"description": "URL that documents the remediation action."})
    action: Optional[Dict[str, str]] = field(
        default=None,
        metadata={
            "description": "Remediation actions with tool as key.\n"
            "Example tools: resoto_cmd, awscli, gcloud, terraform"
        },
    )


@define
class ReportCheck:
    kind: ClassVar[str] = "report_check"
    id: str = field(
        metadata={
            "description": "Unique ID of the check. Suggested format: <provider>_<service>_<name>\n",
            "Example": "aws_ec2_unused_elastic_ip",
        }
    )
    provider: str = field(metadata={"description": "Cloud provider of the service to check. Example: aws"})
    service: str = field(metadata={"description": "Service name by the provider. Example: ec2"})
    title: str = field(metadata={"description": "Title of the check."})
    result_kind: str = field(metadata={"description": "Resulting kind this check will emit. Example: aws_ec2_instance"})
    categories: List[str] = field(metadata={"description": "Categories of the check. Example: ['security', 'cost']"})
    severity: ReportSeverity = field(metadata={"description": "Severity of the check."})
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

    def environment(self, values: Json) -> Json:
        return {**self.default_values, **values} if self.default_values else values

    @staticmethod
    def from_files() -> List[ReportCheck]:
        def report_check(pdr: str, svc: str, check: Json) -> ReportCheck:
            check["provider"] = pdr
            check["service"] = svc
            check["id"] = f"{pdr}_{svc}_{check['name']}"
            return from_js(check, ReportCheck)

        def from_file(path: str) -> List[ReportCheck]:
            with open(path, "rt", encoding="utf-8") as f:
                js = json.load(f)
                pdr = js["provider"]
                svc = js["service"]
                return [report_check(pdr, svc, check) for check in js["checks"]]

        # TODO: define final path and add to Manifest
        static_path = os.path.abspath(os.path.dirname(__file__) + "/../../../report/checks")
        result = []
        for provider in (d.path for d in os.scandir(static_path) if d.is_dir()):
            for service in (d.path for d in os.scandir(provider) if d.is_file() and d.name.endswith(".json")):
                result.extend(from_file(service))
        return result


@define
class CheckCollection:
    kind: ClassVar[str] = "resoto_core_report_check_collection"
    title: str = field(metadata={"description": "Title of the benchmark or report check collection."})
    description: str = field(metadata={"description": "Description of the benchmark."})
    documentation: Optional[str] = field(default=None, kw_only=True, metadata={"description": "Documentation URL."})
    checks: Optional[List[str]] = field(
        default=None, kw_only=True, metadata={"description": "List of checks to perform."}
    )
    children: Optional[List[CheckCollection]] = field(
        default=None, kw_only=True, metadata={"description": "Nested collections."}
    )

    def is_valid(self, checks: Dict[str, ReportCheck]) -> bool:
        return (
            not (self.children and self.checks)
            and all(c in checks for c in self.checks or [])  # pylint: disable=not-an-iterable
            and all(c.is_valid(checks) for c in self.children or [])  # pylint: disable=not-an-iterable
        )

    def nested_checks(self) -> List[str]:
        result: List[str] = []
        if self.checks:
            result.extend(c for c in self.checks)  # pylint: disable=not-an-iterable
        if self.children:
            for child in self.children:  # pylint: disable=not-an-iterable
                result.extend(child.nested_checks())
        return result


@define
class Benchmark(CheckCollection):
    kind: ClassVar[str] = "report_benchmark"

    id: str = field(metadata={"description": "Unique ID of the benchmark."})
    framework: str = field(metadata={"description": "Framework the benchmark is based on."})
    version: str = field(metadata={"description": "Version of the benchmark."})

    @staticmethod
    def from_files(checks: Dict[str, ReportCheck]) -> List[Benchmark]:
        def from_file(path: str) -> Benchmark:
            with open(path, "rt", encoding="utf-8") as f:
                js = json.load(f)
                return from_json(js, Benchmark)

        # TODO: define final path and add to Manifest
        static_path = os.path.abspath(os.path.dirname(__file__) + "/../../../report/benchmark")
        result = []
        for provider in (d.path for d in os.scandir(static_path) if d.is_dir()):
            for path in (d.path for d in os.scandir(provider) if d.is_file() and d.name.endswith(".json")):
                benchmark = from_file(path)
                if benchmark.is_valid(checks):
                    result.append(benchmark)
                else:
                    raise ValueError(f"Invalid benchmark {benchmark.title} in {path}")
        return result


@define
class CheckResult:
    check: ReportCheck
    passed: bool
    number_of_resources_failing: int


@define
class CheckCollectionResult:
    title: str
    description: str
    documentation: Optional[str] = field(default=None, kw_only=True)
    checks: List[CheckResult] = field(factory=list, kw_only=True)
    children: List[CheckCollectionResult] = field(factory=list, kw_only=True)
    passed: bool = field(default=False, kw_only=True)
    number_of_resources_failing: int = field(default=0, kw_only=True)


@define
class BenchmarkResult(CheckCollectionResult):
    framework: str
    version: str


class Inspector(ABC):
    """
    The inspector is able to perform benchmarks or a set of checks.
    Benchmarks and checks are maintained via the configuration registry.
    A complete graph can be checked against either a pre-defined benchmark or from a selected set of checks.
    """

    @abstractmethod
    async def list_checks(
        self,
        provider: Optional[str] = None,
        service: Optional[str] = None,
        category: Optional[str] = None,
        kind: Optional[str] = None,
        check_ids: Optional[List[str]] = None,
    ) -> List[ReportCheck]:
        """
        List all inspection checks matching the given criteria.
        If no criteria is given, all checks are returned.

        :param provider: the provider of the check (e.g. aws, gcp, k8s, ...)
        :param service: the service inside the provider (e.g. ec2, lambda, ...)
        :param category: the category of the check (e.g. security, compliance, cost ...)
        :param kind: the resulting kind of the check (e.g. aws_ec2_instance, kubernetes_pod, ...)
        :param check_ids: the list of check ids to return
        :return: the list of matching checks
        """

    @abstractmethod
    async def perform_benchmark(self, benchmark_name: str, graph: str) -> BenchmarkResult:
        """
        Perform a benchmark by given name on the content of a graph with given name.

        :param benchmark_name: the name of the benchmark to perform (e.g. aws_cis_1_5_0)
        :param graph: the name of the graph to perform the benchmark on (e.g. resoto)
        :return: the result of the benchmark
        """

    @abstractmethod
    async def perform_checks(
        self,
        graph: str,
        provider: Optional[str] = None,
        service: Optional[str] = None,
        category: Optional[str] = None,
        kind: Optional[str] = None,
    ) -> BenchmarkResult:
        """
        Perform a benchmark by selecting all checks matching the given criteria.

        :param graph: the name of the graph to perform the checks on (e.g. resoto)
        :param provider: the provider of the check (e.g. aws, gcp, k8s, ...)
        :param service: the service inside the provider (e.g. ec2, lambda, ...)
        :param category: the category of the check (e.g. security, compliance, cost ...)
        :param kind: the resulting kind of the check (e.g. aws_ec2_instance, kubernetes_pod, ...)
        :return: the result of this benchmark
        """


def config_model() -> List[Json]:
    config_classes = {ReportCheck, Benchmark}
    return dataclasses_to_resotocore_model(config_classes, allow_unknown_props=False)
