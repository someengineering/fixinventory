from datetime import timedelta

from resotolib.config import Config
from resoto_plugin_cleanup_untagged import CleanupUntaggedPlugin


def test_config():
    config = Config("dummy", "dummy")
    CleanupUntaggedPlugin.add_config(config)
    Config.init_default_config()
    assert Config.plugin_cleanup_untagged.enabled is False
    assert Config.plugin_cleanup_untagged.validate(Config.plugin_cleanup_untagged) is True


class WorkerConfig:
    def __init__(self) -> None:
        self.timeout = timedelta(seconds=60)


def test_create_command():
    cfg = Config("dummy", "dummy")
    CleanupUntaggedPlugin.add_config(cfg)
    Config.running_config.data["resotoworker"] = WorkerConfig()
    Config.init_default_config()
    assert CleanupUntaggedPlugin().create_command(Config.plugin_cleanup_untagged.config) == (
        "search /metadata.protected == false and /metadata.phantom == false and /metadata.cleaned == false and "
        'is(["aws_ec2_instance", "aws_ec2_volume", "aws_vpc", "aws_cloudformation_stack", "aws_elb", '
        '"aws_alb", "aws_alb_target_group", "aws_eks_cluster", "aws_eks_nodegroup", '
        '"example_instance", "example_network"]) '
        'and not(has_key(tags, ["owner", "expiration"])) '
        'and ((/ancestors.cloud.id == "aws" and /ancestors.account.id == "068564737731" and age > 7d) '
        'or (/ancestors.cloud.id == "aws" and /ancestors.account.id == "575584959047" and age > 2h) '
        'or (/ancestors.cloud.id == "example" and /ancestors.account.id == "Example Account" and age > 2h)) | '
        'clean "Missing one or more of required tags owner, expiration and age more than threshold"'
    )
