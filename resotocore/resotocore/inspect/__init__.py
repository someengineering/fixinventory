from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Optional, Dict

from attr import define, field

from resotocore.types import Json
from resotolib.json import from_json

log = logging.getLogger(__name__)


class InspectionSeverity(Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


@define
class Remediation:
    action: Dict[str, str]
    text: str
    url: str


@define
class InspectionCheck:
    id: str
    provider: str
    service: str
    title: str
    kind: str
    categories: List[str]
    severity: InspectionSeverity
    detect: Dict[str, str]
    remediation: Remediation
    url: Optional[str] = None
    related: List[str] = field(factory=list)

    @staticmethod
    def from_files() -> List[InspectionCheck]:
        def inspection(pdr: str, svc: str, check: Json) -> InspectionCheck:
            return InspectionCheck(
                id=f'{pdr}_{svc}_{check["name"]}',
                provider=pdr,
                service=svc,
                kind=check["kind"],
                title=check["title"],
                categories=check["categories"],
                severity=InspectionSeverity(check["severity"]),
                detect=check["detect"],
                remediation=Remediation(
                    action=check["remediation"].get("action", {}),
                    text=check["remediation"]["text"],
                    url=check["remediation"]["url"],
                ),
                url=check.get("url"),
                related=check.get("related", []),
            )

        def from_file(path: str) -> List[InspectionCheck]:
            with open(path, "rt", encoding="utf-8") as f:
                js = json.load(f)
                pdr = js["provider"]
                svc = js["service"]
                return [inspection(pdr, svc, check) for check in js["checks"]]

        # TODO: define final path and add to Manifest
        static_path = os.path.abspath(os.path.dirname(__file__) + "/../../../report/checks")
        result = []
        for provider in (d.path for d in os.scandir(static_path) if d.is_dir()):
            for service in (d.path for d in os.scandir(provider) if d.is_file() and d.name.endswith(".json")):
                result.extend(from_file(service))
        return result


@define
class CheckCollection:
    title: str
    description: str
    documentation: Optional[str] = field(default=None, kw_only=True)
    checks: Optional[List[str]] = field(default=None, kw_only=True)
    children: Optional[List[CheckCollection]] = field(default=None, kw_only=True)

    def is_valid(self, inspections: Dict[str, InspectionCheck]) -> bool:
        return (
            not (self.children and self.checks)
            and all(c in inspections for c in self.checks or [])  # pylint: disable=not-an-iterable
            and all(c.is_valid(inspections) for c in self.children or [])  # pylint: disable=not-an-iterable
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

    @staticmethod
    def from_files(inspections: Dict[str, InspectionCheck]) -> List[Benchmark]:
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
                if benchmark.is_valid(inspections):
                    result.append(benchmark)
                else:
                    raise ValueError(f"Invalid benchmark {benchmark.title} in {path}")
        return result


@define
class CheckResult:
    check: InspectionCheck
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
    An inspector is able to maintain a set of checks.
    Checks can be assembled into a benchmark that is also maintained in the inspector.
    A complete graph can be checked against either a pre-defined benchmark or from a selected set of checks.
    """

    @abstractmethod
    async def get_check(self, uid: str) -> Optional[InspectionCheck]:
        """
        Get a single inspection check by its unique identifier.
        :param uid: the identifier of the inspection check
        :return: the inspection check or None if not found
        """

    @abstractmethod
    async def list_checks(
        self,
        provider: Optional[str] = None,
        service: Optional[str] = None,
        category: Optional[str] = None,
        kind: Optional[str] = None,
        check_ids: Optional[List[str]] = None,
    ) -> List[InspectionCheck]:
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
    async def update_check(self, inspection: InspectionCheck) -> InspectionCheck:
        """
        Create or update an inspection check.

        :param inspection: the check to create or update.
        :return: the persisted check
        """

    @abstractmethod
    async def delete_check(self, uid: str) -> None:
        """
        Delete an inspection check by its unique identifier.

        :param uid: the unique identifier of the check to delete
        """

    @abstractmethod
    async def perform_benchmark(self, benchmark: str, graph: str) -> BenchmarkResult:
        """
        Perform a benchmark by given name on the content of a graph with given name.

        :param benchmark: the name of the benchmark to perform (e.g. aws_cis_1_5_0)
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
