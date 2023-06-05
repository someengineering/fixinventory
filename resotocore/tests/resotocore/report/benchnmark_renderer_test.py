import pytest
from aiostream import stream

from resotocore.report import Benchmark
from resotocore.report.benchmark_renderer import respond_benchmark_result
from resotocore.report.inspector_service import InspectorService
from resotocore.ids import GraphName


@pytest.mark.asyncio
async def test_benchmark_renderer(inspector_service: InspectorService, test_benchmark: Benchmark) -> None:
    bench_result = await inspector_service.perform_benchmark(GraphName("ns"), "test")
    render_result = [elem async for elem in respond_benchmark_result(stream.iterate(bench_result.to_graph()))]
    assert len(render_result) == 1
    assert (
        render_result[0]
        == "# Report for account sub_root\n\nTitle: test\n\nVersion: 1.5\n\nSummary: all 2 checks failed\n\n## Failed Checks \n\n- ❌ medium: Test\n- ❌ medium: Test\n\n\n## Section 1 (all checks ❌)\n\nTest section.\n\n- ❌ **medium**: Test\n\n  - Risk: Some risk\n\n  - There are 11 `foo` resources failing this check.\n\n  - Remediation: Some remediation text. See [Link](https://example.com) for more details.\n\n## Section 2 (all checks ❌)\n\nTest section.\n\n- ❌ **medium**: Test\n\n  - Risk: Some risk\n\n  - There are 11 `foo` resources failing this check.\n\n  - Remediation: Some remediation text. See [Link](https://example.com) for more details.\n\n"  # noqa: E501
    )

    # only render checks
    check_result = bench_result.to_graph(True)
    assert len(check_result) == 2
    for c in check_result:
        assert c["kind"] == "report_check_result"
