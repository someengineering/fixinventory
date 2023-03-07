from resotolib.proc import num_default_threads
from resotolib.config import Config
from resoto_plugin_aws import AWSCollectorPlugin
from resoto_plugin_aws.configuration import AwsConfig


def test_default_config() -> None:
    config = Config("dummy", "dummy")
    AWSCollectorPlugin.add_config(config)
    Config.init_default_config()
    assert Config.aws.access_key_id is None
    assert Config.aws.secret_access_key is None
    assert Config.aws.role is None
    assert Config.aws.role_override is False
    assert Config.aws.account is None
    assert Config.aws.region is None
    assert Config.aws.scrape_org is False
    assert Config.aws.fork_process is True
    assert Config.aws.scrape_exclude_account == []
    assert Config.aws.assume_current is False
    assert Config.aws.do_not_scrape_current is False
    assert Config.aws.account_pool_size == num_default_threads()
    assert len(Config.aws.collect) == 0
    assert len(Config.aws.no_collect) == 0


def test_session() -> None:
    config = AwsConfig("test", "test", "test")
    # direct session
    assert config.sessions()._session("1234", aws_role=None) == config.sessions()._session("1234", aws_role=None)
    # no test for sts session, since this requires sts setup


def test_shared_tasks_per_key() -> None:
    config = AwsConfig(
        "test", "test", "test", resource_pool_tasks_per_service_default=20, resource_pool_tasks_per_service={"test": 3}
    )
    config.resource_pool_tasks_per_service["sagemaker"] = 6  # predefined
    tpk = config.shared_tasks_per_key(["eu-central-1"])
    assert tpk("eu-central-1:foo") == 20  # default
    assert tpk("eu-central-1:sagemaker") == 6  # predefined
    assert tpk("eu-central-1:test") == 3  # defined in config
