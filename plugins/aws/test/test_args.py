from resotolib.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_aws import AWSPlugin


def test_args():
    arg_parser = get_arg_parser()
    AWSPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.aws_access_key_id is None
    assert ArgumentParser.args.aws_secret_access_key is None
    assert ArgumentParser.args.aws_role is None
    assert ArgumentParser.args.aws_role_override is False
    assert ArgumentParser.args.aws_account is None
    assert ArgumentParser.args.aws_region is None
    assert ArgumentParser.args.aws_scrape_org is False
    assert len(ArgumentParser.args.aws_scrape_exclude_account) == 0
    assert ArgumentParser.args.aws_assume_current is False
    assert ArgumentParser.args.aws_dont_scrape_current is False
    assert ArgumentParser.args.aws_account_pool_size == 5
    assert ArgumentParser.args.aws_region_pool_size == 20
