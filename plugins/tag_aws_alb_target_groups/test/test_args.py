from cloudkeeper.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_tag_aws_alb_target_groups import TagAWSAlbTargetGroupsPlugin


def test_args():
    arg_parser = get_arg_parser()
    TagAWSAlbTargetGroupsPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.tag_aws_alb_target_groups is False
