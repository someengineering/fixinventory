from cloudkeeper.args import get_arg_parser, ArgumentParser
from cloudkeeper.web import WebServer
from cloudkeeper.graph import GraphContainer
from cloudkeeper.processor import Processor
from cloudkeeper.pluginloader import PluginLoader
from cloudkeeper.event import add_args as event_add_args


def test_args():
    arg_parser = get_arg_parser()
    WebServer.add_args(arg_parser)
    GraphContainer.add_args(arg_parser)
    Processor.add_args(arg_parser)
    PluginLoader.add_args(arg_parser)
    event_add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.interval == 3600
