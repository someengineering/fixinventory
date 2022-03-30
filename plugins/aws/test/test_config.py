from resotolib.config import Config
from resoto_plugin_aws import AWSCollectorPlugin


def test_args():
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
    assert Config.aws.fork is True
    assert Config.aws.scrape_exclude_account is None
    assert Config.aws.assume_current is False
    assert Config.aws.do_not_scrape_current is False
    assert Config.aws.account_pool_size == 5
    assert Config.aws.region_pool_size == 20
    assert len(Config.aws.collect) == 0
    assert len(Config.aws.no_collect) == 0
