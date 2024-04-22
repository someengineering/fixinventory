from typing import AsyncGenerator, List, AsyncIterable

from aiostream import stream
from networkx import DiGraph
from rich._emoji_codes import EMOJI

from fixcore.model.resolve_in_graph import NodePath
from fixcore.report import BenchmarkResult, CheckCollectionResult, CheckResult
from fixcore.types import JsonElement
from fixcore.util import value_in_path

kind_reader = {
    "report_benchmark": BenchmarkResult.from_node,
    "report_check_collection": CheckCollectionResult.from_node,
    "report_check_result": CheckResult.from_node,
}
check_mark = EMOJI["white_check_mark"]
cross_mark = EMOJI["cross_mark"]


def render_benchmark_result(benchmark: BenchmarkResult, account: str) -> str:
    filtered = benchmark.filter_result(failed_for_account=account) if benchmark.only_failed else benchmark
    result = f"# Report for account {account}\n\n"
    result += f"Title: {benchmark.title}\n\n"
    result += f"Version: {benchmark.version}\n\n"
    passing, failing = benchmark.passing_failing_checks_count_for_account(account)
    if passing == 0:
        result += f"Summary: all {failing} checks failed\n\n"
    elif failing == 0:
        result += f"Summary: all {passing} checks passed\n\n"
    else:
        result += f"Summary: {passing} checks {check_mark} and {failing} checks {cross_mark}\n\n"
    # If there are no children, ignore the summary (same information will be available as part of the check result)
    if filtered.children:
        result += render_benchmark_summary(filtered, account)
        result += "\n\n"
    for check in filtered.checks:
        result += render_check_result(check, account)
    for collection in filtered.children:
        result += render_collection_result(collection, account, 2)
    return result


def render_benchmark_summary(benchmark: CheckCollectionResult, account: str) -> str:
    passing, failing = benchmark.passing_failing_checks_for_account(account)

    def render_result_list(name: str, icon: str, checks: List[CheckResult]) -> str:
        if checks:
            lr = f"## {name} \n\n"
            for check in sorted(checks, key=lambda x: -x.check.severity.prio):
                lr += f"- {icon} {check.check.severity.name}: {check.check.title}\n"
            return lr
        else:
            return ""

    result = render_result_list("Passed Checks", check_mark, passing)
    result += render_result_list("Failed Checks", cross_mark, failing)
    return result


def render_collection_result(collection: CheckCollectionResult, account: str, level: int) -> str:
    result = f"{'#' * level} {collection.title} "
    passing, failing = collection.passing_failing_checks_count_for_account(account)
    if passing == 0:
        result += f"(all checks {cross_mark})"
    elif failing == 0:
        result += f"(all checks {check_mark})"
    else:
        result += f"({passing} checks {check_mark}, {failing} checks {cross_mark})"
    result += f"\n\n{collection.description}\n\n"
    for check in collection.checks:
        result += render_check_result(check, account)
    for sub_collection in collection.children:
        result += render_collection_result(sub_collection, account, level + 1)
    return result


def render_check_result(check_result: CheckResult, account: str) -> str:
    check = check_result.check
    failed = account in check_result.number_of_resources_failing_by_account
    result = f"- {cross_mark if failed else check_mark} **{check.severity.name}**: {check.title}\n\n"
    if failed:
        kinds = ", ".join(f"`{k}`" for k in check.result_kinds)
        result += f"  - Risk: {check.risk}\n\n"
        result += f"  - There are {check_result.number_of_resources_failing_by_account[account]} {kinds} "
        result += "resources failing this check.\n\n"
        result += (
            f"  - Remediation: {check.remediation.text}. See [Link]({check.remediation.url}) for more details.\n\n"
        )
    return result


async def respond_benchmark_result(gen: AsyncIterable[JsonElement]) -> AsyncGenerator[str, None]:
    # step 1:  read graph
    graph = DiGraph()
    async with stream.iterate(gen).stream() as streamer:
        async for item in streamer:
            if isinstance(item, dict):
                type_name = item.get("type")
                if type_name == "node":
                    uid = value_in_path(item, NodePath.node_id)
                    reported = value_in_path(item, NodePath.reported)
                    kind = value_in_path(item, NodePath.reported_kind)
                    if uid and reported and kind and (reader := kind_reader.get(kind)):
                        graph.add_node(uid, data=reader(item))
                elif type_name == "edge":
                    from_node = value_in_path(item, NodePath.from_node)
                    to_node = value_in_path(item, NodePath.to_node)
                    if from_node and to_node:
                        graph.add_edge(from_node, to_node)
                else:
                    raise AttributeError(f"Expect json object but got: {type(item)}: {item}")
            else:
                raise AttributeError(f"Expect json object but got: {type(item)}: {item}")

    # step 2: read benchmark result from graph
    def traverse(node_id: str, collection: CheckCollectionResult) -> None:
        for sub_id in graph.successors(node_id):
            node = graph.nodes[sub_id]
            collection_node = node["data"]
            if isinstance(collection_node, CheckCollectionResult):
                collection.children.append(collection_node)
                traverse(sub_id, collection_node)
            elif isinstance(collection_node, CheckResult):
                collection.checks.append(collection_node)

    results: List[BenchmarkResult] = []
    for nid, data in graph.nodes(data=True):
        if isinstance(data.get("data"), BenchmarkResult):
            br = data["data"]
            traverse(nid, br)
            results.append(br)

    # step 3: benchmark result to markdown
    for result in results:
        # use accounts defined on the cmd line, otherwise fall back to accounts with failing checks
        accounts = result.accounts or result.failing_accounts()
        for account in accounts:
            yield render_benchmark_result(result, account)
