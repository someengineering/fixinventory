from typing import AsyncIterator, AsyncGenerator, Optional

from networkx import DiGraph

from resotocore.cli.model import CLIContext
from resotocore.console_renderer import ConsoleRenderer
from resotocore.model.resolve_in_graph import NodePath
from resotocore.report import BenchmarkResult, CheckCollectionResult, CheckResult
from resotocore.types import JsonElement
from resotocore.util import value_in_path

kind_reader = {
    "report_benchmark": BenchmarkResult.from_node,
    "report_check_collection": CheckCollectionResult.from_node,
    "report_check_result": CheckResult.from_node,
}


def render_benchmark_result(benchmark: BenchmarkResult, account: str) -> str:
    filtered = benchmark.filter_result(failed_for_account=account) if benchmark.only_failed else benchmark
    result = f"# Report for account {account}\n"
    result += f"- Title: {benchmark.title}\n"
    result += f"- Version: {benchmark.version}\n"
    passing, failing = benchmark.passing_failing_checks_for_account(account)
    result += f"- Summary: {passing} checks passed and {failing} checks failed\n"
    for check in filtered.checks:
        result += render_check_result(check, account, 2)
    for collection in filtered.children:
        result += render_collection_result(collection, account, 2)
    return result


def render_collection_result(collection: CheckCollectionResult, account: str, level: int) -> str:
    result = f"{'#' * level} {collection.title}\n\n"
    result += f"{collection.description}\n\n"
    passing, failing = collection.passing_failing_checks_for_account(account)
    result += f"{passing} checks passed and {failing} checks failed\n\n"
    for check in collection.checks:
        result += render_check_result(check, account, level + 1)
    for sub_collection in collection.children:
        result += render_collection_result(sub_collection, account, level + 1)
    return result


def render_check_result(check_result: CheckResult, account: str, level: int) -> str:
    check = check_result.check
    result = f"{'#' * level} {check.title}\n\n"
    result += f"Severity: **{check.severity.name}**\n\n"
    result += f"Risk: **{check.risk}**\n\n"
    if account in check_result.number_of_resources_failing_by_account:
        result += "Result: **Failed**\n\n"
        result += f"There are {check_result.number_of_resources_failing_by_account[account]} `{check.result_kind}` "
        result += "resources failing this check.\n\n"
        result += f"Remediation: {check.remediation.text}. See [Link]({check.remediation.url}) for more details.\n\n"
    else:
        result += "Result: **Passed**\n\n"
    return result


async def respond_benchmark_result(gen: AsyncIterator[JsonElement], ctx: CLIContext) -> AsyncGenerator[str, None]:
    # step 1:  read graph
    graph = DiGraph()
    async for item in gen:
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

    result: Optional[BenchmarkResult] = None
    for nid, data in graph.nodes(data=True):
        if isinstance(data.get("data"), BenchmarkResult):
            br = data["data"]
            traverse(nid, br)
            result = br

    # step 3: benchmark result to markdown
    renderer = ctx.console_renderer or ConsoleRenderer.default_renderer()
    if result:
        # use accounts defined on the cmd line, otherwise fall back to accounts with failing checks
        accounts = result.accounts or result.failing_accounts()
        for account in accounts:
            account_result = render_benchmark_result(result, account)
            res = renderer.render(account_result)
            yield res
