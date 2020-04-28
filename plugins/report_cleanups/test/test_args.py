from cloudkeeper.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_report_cleanups import ReportCleanupsPlugin


def test_args():
    arg_parser = get_arg_parser()
    ReportCleanupsPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.report_cleanups_path is None
    assert ArgumentParser.args.report_cleanups_format == 'json'
    assert len(ArgumentParser.args.report_cleanups_add_attr) == 0
