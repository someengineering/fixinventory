import pytest
from aiostream import stream

from resotocore.cli.model import CLIContext
from resotocore.console_renderer import ConsoleRenderer
from resotocore.report import Benchmark
from resotocore.report.benchmark_renderer import respond_benchmark_result
from resotocore.report.inspector_service import InspectorService


@pytest.mark.asyncio
async def test_benchmark_renderer(
    inspector_service: InspectorService, test_benchmark: Benchmark, console_renderer: ConsoleRenderer
) -> None:
    bench_result = await inspector_service.perform_benchmark("ns", "test")
    context = CLIContext(console_renderer=console_renderer)
    render_result = [elem async for elem in respond_benchmark_result(stream.iterate(bench_result.to_graph()), context)]
    assert len(render_result) == 0
