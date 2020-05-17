from cloudkeeper.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_tag_aws_ctime import TagAWSCtimePlugin


def test_args():
    arg_parser = get_arg_parser()
    TagAWSCtimePlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.tag_aws_ctime is False
