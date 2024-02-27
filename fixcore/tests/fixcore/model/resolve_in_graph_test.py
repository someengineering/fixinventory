from fixcore.model.resolve_in_graph import GraphResolver


def test_resolved_ancestors() -> None:
    assert GraphResolver.resolved_ancestors == {
        "account": "refs.account_id",
        "cloud": "refs.cloud_id",
        "region": "refs.region_id",
        "zone": "refs.zone_id",
    }
