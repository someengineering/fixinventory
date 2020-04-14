from cloudkeeper.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_tagvalidator import TagValidatorPlugin


def test_args():
    arg_parser = get_arg_parser()
    TagValidatorPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.tagvalidator_config is None
    assert ArgumentParser.args.tagvalidator_dry_run is False
