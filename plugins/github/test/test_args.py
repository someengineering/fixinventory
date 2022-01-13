from resotolib.args import get_arg_parser, ArgumentParser
from resoto_plugin_github import GithubCollectorPlugin


def test_args():
    arg_parser = get_arg_parser()
    GithubCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.github_access_token is None
