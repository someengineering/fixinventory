import pytest
from aiostream import stream

from fixcore.report.benchmark_renderer import respond_benchmark_result
from fixcore.report.inspector_service import InspectorService
from fixcore.ids import GraphName


@pytest.mark.asyncio
async def test_benchmark_renderer(inspector_service: InspectorService) -> None:
    bench_results = await inspector_service.perform_benchmarks(GraphName("ns"), ["test"])
    bench_result = bench_results["test"]
    render_result = [elem async for elem in respond_benchmark_result(stream.iterate(bench_result.to_graph()))]
    assert len(render_result) == 1
    assert (
        render_result[0]
        == "# Report for account sub_root\n\nTitle: test_benchmark\n\nVersion: 1.5\n\nSummary: all 2 checks failed\n\n## Failed Checks \n\n- ❌ critical: cmd\n- ❌ medium: search\n\n\n## Section 1 (all checks ❌)\n\nSome description\n\n- ❌ **medium**: search\n\n  - Risk: Some serious risk\n\n  - There are 10 `foo` resources failing this check.\n\n  - Remediation: Fix it now. See [Link](https://example.test) for more details.\n\n## Section 2 (all checks ❌)\n\nSome description\n\n- ❌ **critical**: cmd\n\n  - Risk: Some other risk.\n\n  - There are 10 `foo` resources failing this check.\n\n  - Remediation: Fix it. See [Link](https://example.link) for more details.\n\n"  # noqa: E501
    )

    # only render checks
    check_result = bench_result.to_graph(True)
    assert len(check_result) == 2
    for c in check_result:
        assert c["kind"] == "report_check_result"
