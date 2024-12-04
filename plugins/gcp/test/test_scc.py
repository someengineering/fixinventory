from functools import partial
from typing import Any

from fix_plugin_gcp.resources.base import GraphBuilder
from fix_plugin_gcp.resources.compute import GcpFirewall
from fix_plugin_gcp.resources.scc import GcpSccFinding
from .random_client import roundtrip


class DefaultDict(dict):
    # for random location name we use the default global location
    def __init__(self, default_value: Any, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.default_value = default_value

    def get(self, key, default=None):
        if key in self:
            return super().get(key, default)
        return self.default_value


def test_gcp_scc_findings(random_builder: GraphBuilder) -> None:
    firewall = roundtrip(GcpFirewall, random_builder)
    random_builder.region_by_name = DefaultDict(random_builder.fallback_global_region)
    GcpSccFinding.collect_resources(random_builder)

    partial(random_builder.after_collect_actions[0], id=firewall.id)()  # type: ignore

    assert len(firewall._assessments) > 0
    assert len(firewall._assessments[0].findings) > 0
    assert firewall._assessments[0].findings[0].severity is not None
