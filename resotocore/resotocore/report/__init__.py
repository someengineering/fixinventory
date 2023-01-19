from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Optional, Dict, ClassVar

from attr import define, field

from resotocore.ids import ConfigId
from resotocore.types import Json

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
    id: str
    provider: str
    service: str
    title: str
    result_kind: str
    categories: List[str]
    severity: ReportSeverity
    risk: str
    detect: Dict[str, str]
    remediation: Remediation
    default_values: Optional[Json] = None
    url: Optional[str] = None
    related: List[str] = field(factory=list)

    def environment(self, values: Json) -> Json:
        return {**self.default_values, **values} if self.default_values else values


@define
class CheckCollection:
    title: str
    description: str
    documentation: Optional[str]
    checks: Optional[List[str]]
    children: Optional[List[CheckCollection]]

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
    id: str
    framework: str
    version: str


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
