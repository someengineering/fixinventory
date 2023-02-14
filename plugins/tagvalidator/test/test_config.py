from datetime import timedelta

from resotolib.baseresources import Cloud, BaseRegion, BaseAccount, BaseInstance
from resotolib.config import Config
from resoto_plugin_tagvalidator import TagValidatorPlugin
from resotolib.graph import Graph


def test_config() -> None:
    config = Config("dummy", "dummy")
    TagValidatorPlugin.add_config(config)
    Config.init_default_config()
    assert Config.plugin_tagvalidator.enabled is False
    assert Config.plugin_tagvalidator.dry_run is False
    assert Config.plugin_tagvalidator.validate(Config.plugin_tagvalidator) is True


class TestAccount(BaseAccount):
    def delete(self, graph: Graph) -> bool:
        return False


class TestRegion(BaseRegion):
    def delete(self, graph: Graph) -> bool:
        return False


class TestInstance(BaseInstance):
    def delete(self, graph: Graph) -> bool:
        return False


class WorkerConfig:
    def __init__(self) -> None:
        self.timeout = timedelta(seconds=60)


def test_invalid() -> None:
    cfg = Config("dummy", "dummy")
    Config.running_config.data["resotoworker"] = WorkerConfig()
    TagValidatorPlugin.add_config(cfg)

    # add_config(cfg)
    Config.init_default_config()
    plugin = TagValidatorPlugin()

    graph = Graph()
    cloud = Cloud(id="aws")
    region = TestRegion(id="eu-central-1", cloud=cloud)
    account_eng = TestAccount(id="123465706934")
    account_sales = TestAccount(id="123453451782")

    si = TestInstance(id="i-1", cloud=cloud, account=account_sales, region=region, tags={"expiration": "4d"})
    ei = TestInstance(id="i-1", cloud=cloud, account=account_eng, region=region)
    wr = TestInstance(id="i-1", cloud=cloud, account=account_sales, region=region, tags={"expiration": "smthg"})
    assert plugin.invalid_expiration(graph, si, "6d") is None  # expiration is ok
    assert plugin.invalid_expiration(graph, si, "2h") == "2h"  # expiration is too long
    assert plugin.invalid_expiration(graph, ei, "2h") == "2h"  # no expiration tag
    assert plugin.invalid_expiration(graph, wr, "2h") == "2h"  # expiration can not be parsed
