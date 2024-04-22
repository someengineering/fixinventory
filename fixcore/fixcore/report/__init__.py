from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from enum import Enum
from functools import reduce, total_ordering
from typing import List, Optional, Dict, ClassVar, AsyncIterator, cast, Set, Tuple, Any

from attr import define, field, evolve

from fixcore.ids import ConfigId, GraphName
from fixcore.model.typed_model import to_js
from fixcore.types import Json
from fixcore.util import uuid_str, if_set, partition_by

log = logging.getLogger(__name__)

# config ids
FixReportConfig = ConfigId("fix.report.config")
FixReportBenchmark = ConfigId("fix.report.benchmark")
FixReportCheck = ConfigId("fix.report.check")

# config keys and prefixes
CheckConfigRoot = "report_check"
BenchmarkConfigRoot = "report_benchmark"
ReportConfigRoot = "report_config"


_ReportSeverityPriority: Dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_ReportSeverityScore: Dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@total_ordering
class ReportSeverity(Enum):
    kind: ClassVar[str] = "fix_core_report_check_severity"
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def prio(self) -> int:
        return _ReportSeverityPriority[self.value]

    @property
    def score(self) -> int:
        return _ReportSeverityScore[self.value]

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, ReportSeverity):
            return self.prio < other.prio
        return NotImplemented

    @staticmethod
    def from_name(name: str) -> ReportSeverity:
        return ReportSeverity[name]


@define
class SecurityIssue:
    check: str
    severity: ReportSeverity
    opened_at: Optional[str] = None
    benchmark: Optional[str] = None
    benchmarks: Set[str] = field(factory=set)

    def __attrs_post_init__(self) -> None:
        if self.benchmark:
            self.benchmarks.add(self.benchmark)

    def diff(self, other: SecurityIssue) -> Tuple[Optional[SecurityIssue], Optional[SecurityIssue]]:
        """
        Diff two security issues and return the differences as a tuple of (vulnerable, compliant).
        """
        if self.severity != other.severity:  # different severity: the whole issue either improved or got worse
            return (other, None) if self.severity < other.severity else (None, other)
        elif self.benchmarks != other.benchmarks:  # same severity but different benchmarks: compute diff
            add = other.benchmarks - self.benchmarks
            delete = self.benchmarks - other.benchmarks
            return evolve(self, benchmarks=add) if add else None, evolve(self, benchmarks=delete) if delete else None
        else:  # same severity and same benchmarks: no change
            return None, None

    def to_json(self) -> Json:
        return {
            "check": self.check,
            "severity": self.severity.value,
            "opened_at": self.opened_at,
            "benchmarks": list(self.benchmarks),
        }


@define
class Remediation:
    kind: ClassVar[str] = "fix_core_report_check_remediation"
    text: str = field(metadata={"description": "Textual description of the remediation."})
    url: str = field(metadata={"description": "URL that documents the remediation action."})
    action: Optional[Dict[str, str]] = field(
        default=None,
        metadata={
            "description": "Remediation actions with tool as key.\n" "Example tools: fix_cmd, awscli, gcloud, terraform"
        },
    )


@define
class ReportCheck:
    id: str
    provider: str
    service: str
    title: str
    result_kinds: List[str]
    categories: List[str]
    severity: ReportSeverity
    risk: str
    detect: Dict[str, str]
    remediation: Remediation
    default_values: Optional[Json] = None
    url: Optional[str] = None
    related: Optional[List[str]] = None

    def environment(self, override_values: Optional[Json] = None) -> Json:
        return {**(self.default_values or {}), **(override_values or {})}

    def to_node(self) -> Json:
        reported = to_js(self)
        # backward compatibility
        reported["result_kind"] = self.result_kinds[0]
        return dict(id=self.id, kind="report_check", type="node", reported=reported)


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
    clouds: Optional[List[str]] = None

    def to_node(self) -> Json:
        reported = to_js(self)
        return dict(id=self.id, kind="benchmark", type="node", reported=reported)


@define
class CheckResult:
    check: ReportCheck
    number_of_resources_failing_by_account: Dict[str, int]
    resources_failing_by_account: Dict[str, List[Json]]
    node_id: str = field(init=False, factory=uuid_str)

    @property
    def number_of_resources_failing(self) -> int:
        return reduce(lambda a, b: a + b, self.number_of_resources_failing_by_account.values(), 0)

    def has_failed(self) -> bool:
        return self.number_of_resources_failing > 0

    def to_node(self) -> Json:
        reported = to_js(self.check, strip_attr="kind")
        reported["kind"] = "report_check_result"
        reported["name"] = self.check.title
        reported["number_of_resources_failing"] = self.number_of_resources_failing
        if self.number_of_resources_failing_by_account:
            reported["number_of_resources_failing_by_account"] = self.number_of_resources_failing_by_account
            reported["resources_failing_by_account"] = self.resources_failing_by_account
        return dict(id=self.node_id, kind="report_check_result", type="node", reported=reported)

    @staticmethod
    def from_node(js: Json) -> CheckResult:
        reported = cast(Json, js["reported"])
        return CheckResult(
            check=ReportCheck(
                id=reported["id"],
                provider=reported["provider"],
                service=reported["service"],
                title=reported["title"],
                result_kinds=reported["result_kinds"],
                categories=reported["categories"],
                severity=ReportSeverity(reported["severity"]),
                risk=reported["risk"],
                detect=reported["detect"],
                remediation=Remediation(**reported["remediation"]),
                default_values=reported.get("default_values"),
                url=reported.get("url"),
                related=reported.get("related", []),
            ),
            number_of_resources_failing_by_account=reported.get("number_of_resources_failing_by_account", {}),
            resources_failing_by_account=reported.get("resources_failing_by_account", {}),
        )


@define
class CheckCollectionResult:
    title: str
    description: str
    documentation: Optional[str] = field(default=None, kw_only=True)
    checks: List[CheckResult] = field(factory=list, kw_only=True)
    children: List[CheckCollectionResult] = field(factory=list, kw_only=True)
    node_id: str = field(init=False, factory=uuid_str)

    def to_node(self) -> Json:
        return dict(
            id=self.node_id,
            type="node",
            reported=dict(
                kind="report_check_collection",
                name=self.title,
                title=self.title,
                description=self.description,
                documentation=self.documentation,
            ),
        )

    @staticmethod
    def from_node(js: Json) -> CheckCollectionResult:
        reported = cast(Json, js["reported"])
        return CheckCollectionResult(
            title=reported["title"],
            description=reported["description"],
            documentation=reported.get("documentation"),
        )

    def is_empty(self) -> bool:
        return not self.checks and not self.children

    def has_failed(self) -> bool:
        return any(c.has_failed() for c in self.checks) or any(c.has_failed() for c in self.children)

    def has_failed_for_account(self, account: str) -> bool:
        return any(account in c.number_of_resources_failing_by_account for c in self.checks) or any(
            c.has_failed_for_account(account) for c in self.children
        )

    def passing_failing_checks_for_account(self, account: str) -> Tuple[List[CheckResult], List[CheckResult]]:
        passing_child_checks, failing_child_checks = reduce(
            lambda pf, el: (pf[0] + el[0], pf[1] + el[1]),
            [c.passing_failing_checks_for_account(account) for c in self.children],
            (cast(List[CheckResult], []), cast(List[CheckResult], [])),
        )

        failing_checks, passing_checks = partition_by(
            lambda c: account in c.number_of_resources_failing_by_account, self.checks
        )
        return passing_checks + passing_child_checks, failing_checks + failing_child_checks

    def passing_failing_checks_count_for_account(self, account: str) -> Tuple[int, int]:
        passing, failing = reduce(
            lambda pf, el: (pf[0] + el[0], pf[1] + el[1]),
            [c.passing_failing_checks_count_for_account(account) for c in self.children],
            (0, 0),
        )

        all_checks = len(self.checks)
        failing_count = sum(1 for c in self.checks if account in c.number_of_resources_failing_by_account)
        return passing + all_checks - failing_count, failing + failing_count

    def filter_result(
        self, filter_failed: bool = False, failed_for_account: Optional[str] = None
    ) -> CheckCollectionResult:
        return evolve(
            self,
            checks=[
                c
                for c in self.checks
                if (not filter_failed or c.has_failed())
                and (failed_for_account is None or failed_for_account in c.number_of_resources_failing_by_account)
            ],
            children=[
                c.filter_result(filter_failed, failed_for_account)
                for c in self.children
                if (not filter_failed or c.has_failed())
                and (c.checks or c.children)
                and (failed_for_account is None or c.has_failed_for_account(failed_for_account))
            ],
        )

    def check_results(self) -> List[CheckResult]:
        return self.checks + [c for child in self.children for c in child.check_results()]

    def failing_accounts(self) -> Set[str]:
        return {account for result in self.check_results() for account in result.number_of_resources_failing_by_account}


@define
class BenchmarkResult(CheckCollectionResult):
    framework: str
    version: str
    id: str
    accounts: Optional[List[str]] = field(default=None)
    only_failed: bool = field(default=False)
    severity: Optional[ReportSeverity] = field(default=None)

    def to_node(self) -> Json:
        node = super().to_node()
        reported = node["reported"]
        reported["id"] = self.id
        reported["framework"] = self.framework
        reported["version"] = self.version
        reported["kind"] = "report_benchmark"
        reported["accounts"] = self.accounts
        reported["only_failed"] = self.only_failed
        reported["severity"] = if_set(self.severity, lambda s: s.value)
        return node

    @staticmethod
    def from_node(js: Json) -> BenchmarkResult:
        reported = cast(Json, js["reported"])
        return BenchmarkResult(
            id=reported["id"],
            framework=reported["framework"],
            version=reported["version"],
            title=reported["title"],
            description=reported["description"],
            documentation=reported.get("documentation"),
            accounts=reported["accounts"],
            only_failed=reported["only_failed"],
            severity=if_set(reported.get("severity"), ReportSeverity),
        )

    def to_graph(self, only_checks: bool = False) -> List[Json]:
        result = []

        def visit_check_collection(collection: CheckCollectionResult) -> None:
            if not only_checks:
                result.append(collection.to_node())
            for check in collection.checks:
                result.append(check.to_node())
                if not only_checks:
                    result.append(
                        {"from": collection.node_id, "to": check.node_id, "type": "edge", "edge_type": "default"}
                    )
            for child in collection.children:
                visit_check_collection(child)
                if not only_checks:
                    result.append(
                        {"from": collection.node_id, "to": child.node_id, "type": "edge", "edge_type": "default"}
                    )

        visit_check_collection(self)
        return result

    def score_for(self, account: str) -> int:
        failing: Dict[ReportSeverity, int] = defaultdict(int)
        available: Dict[ReportSeverity, int] = defaultdict(int)

        def available_failing(check: CheckCollectionResult) -> None:
            for result in check.checks:
                available[result.check.severity] += 1
                failing[result.check.severity] += (
                    1 if result.number_of_resources_failing_by_account.get(account, 0) else 0
                )
            for child in check.children:
                available_failing(child)

        available_failing(self)  # walk the benchmark hierarchy
        missing = sum(severity.score * count for severity, count in failing.items())
        total = sum(severity.score * count for severity, count in available.items())
        return int((max(0, total - missing) * 100) // total) if total > 0 else 100


class Inspector(ABC):
    """
    The inspector is able to perform benchmarks or a set of checks.
    Benchmarks and checks are maintained via the configuration registry.
    A complete graph can be checked against either a pre-defined benchmark or from a selected set of checks.
    """

    @abstractmethod
    async def list_benchmarks(self) -> List[Benchmark]:
        pass

    @abstractmethod
    async def benchmark(self, bid: str) -> Optional[Benchmark]:
        pass

    @abstractmethod
    async def list_checks(
        self,
        *,
        provider: Optional[str] = None,
        service: Optional[str] = None,
        category: Optional[str] = None,
        kind: Optional[str] = None,
        check_ids: Optional[List[str]] = None,
        ignore_checks: Optional[List[str]] = None,
    ) -> List[ReportCheck]:
        """
        List all inspection checks matching the given criteria.
        If no criteria is given, all checks are returned.

        :param provider: the provider of the check (e.g. aws, gcp, k8s, ...)
        :param service: the service inside the provider (e.g. ec2, lambda, ...)
        :param category: the category of the check (e.g. security, compliance, cost ...)
        :param kind: the resulting kind of the check (e.g. aws_ec2_instance, kubernetes_pod, ...)
        :param check_ids: the list of check ids to return
        :param ignore_checks: ignore checks listed here
        :return: the list of matching checks
        """

    @abstractmethod
    async def load_benchmarks(
        self,
        graph: GraphName,
        benchmark_names: List[str],
        *,
        accounts: Optional[List[str]] = None,
        severity: Optional[ReportSeverity] = None,
        only_failing: bool = False,
    ) -> Dict[str, BenchmarkResult]:
        pass

    @abstractmethod
    async def perform_benchmarks(
        self,
        graph: GraphName,
        benchmark_names: List[str],
        *,
        accounts: Optional[List[str]] = None,
        severity: Optional[ReportSeverity] = None,
        only_failing: bool = False,
        sync_security_section: bool = False,
        report_run_id: Optional[str] = None,
    ) -> Dict[str, BenchmarkResult]:
        """
        Perform a benchmark by given name on the content of a graph with given name.

        :param benchmark_names: The names of the benchmark to perform (e.g. aws_cis_1_5_0)
        :param graph: the name of the graph to perform the benchmark on (e.g. fix)
        :param accounts: the list of accounts to perform the benchmark on. If not given, all accounts are used.
        :param severity: Only include checks with given severity or higher
        :param only_failing: only include failing checks in the result
        :param sync_security_section: synchronize the security section of the graph with the benchmark result
        :param report_run_id: give this run a specific id (will be persisted in the security section)
        :return: the result of all benchmarks by name
        """

    @abstractmethod
    async def perform_checks(
        self,
        graph: GraphName,
        *,
        provider: Optional[str] = None,
        service: Optional[str] = None,
        category: Optional[str] = None,
        kind: Optional[str] = None,
        check_ids: Optional[List[str]] = None,
        accounts: Optional[List[str]] = None,
        severity: Optional[ReportSeverity] = None,
        only_failing: bool = False,
    ) -> BenchmarkResult:
        """
        Perform a benchmark by selecting all checks matching the given criteria.

        :param graph: the name of the graph to perform the checks on (e.g. fix)
        :param provider: the provider of the check (e.g. aws, gcp, k8s, ...)
        :param service: the service inside the provider (e.g. ec2, lambda, ...)
        :param category: the category of the check (e.g. security, compliance, cost ...)
        :param kind: the resulting kind of the check (e.g. aws_ec2_instance, kubernetes_pod, ...)
        :param check_ids: the ids of the checks to perform.
        :param accounts: the list of accounts to perform the benchmark on. If not given, all accounts are used.
        :param severity: only include checks with given severity or higher
        :param only_failing: only include failing checks in the result
        :return: the result of this benchmark
        """

    @abstractmethod
    async def list_failing_resources(
        self, graph: GraphName, check_uid: str, account_ids: Optional[List[str]] = None
    ) -> AsyncIterator[Json]:
        pass

    @abstractmethod
    async def validate_benchmark_config(self, cfg_id: ConfigId, json: Json) -> Optional[Json]:
        pass

    @abstractmethod
    async def validate_check_collection_config(self, json: Json) -> Optional[Json]:
        pass

    @abstractmethod
    async def delete_benchmark(self, bid: str) -> None:
        pass

    @abstractmethod
    async def update_benchmark(self, benchmark: Benchmark) -> Benchmark:
        pass

    @abstractmethod
    async def delete_check(self, check_id: str) -> None:
        pass

    @abstractmethod
    async def update_check(self, check: ReportCheck) -> ReportCheck:
        pass
