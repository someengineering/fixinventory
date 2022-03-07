from resotolib import graph
from resotolib.args import get_arg_parser, ArgumentParser
from resoto_plugin_digitalocean import DigitalOceanCollectorPlugin
import resoto_digitalocean_openapi_client
from resoto_plugin_digitalocean.client import StreamingWrapper
from resoto_plugin_digitalocean.collector import DigitalOceanTeamCollector
from resoto_plugin_digitalocean.resources import DigitalOceanTeam
import os
import json
import re
from resotolib.graph import sanitize


def _test_args():
    arg_parser = get_arg_parser()
    DigitalOceanCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.digitalocean_region is None

def test_api_call():

    
    access_token = os.environ['DO_TOKEN']
    

    
    client = StreamingWrapper(access_token)

    projects = client.list_projects()
    print('all projects')
    print(re.sub("'", '"', str(projects)))

    assert False


def test_collector():

    arg_parser = get_arg_parser()
    DigitalOceanCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()

    plugin_instance = DigitalOceanCollectorPlugin()
    plugin_instance.collect()

    sanitize(plugin_instance.graph)
    assert plugin_instance.graph.is_dag_per_edge_type()

    graph_export = f"{list(plugin_instance.graph.export_iterator())}"

    graph_export = re.sub("b'", "", graph_export)
    graph_export = re.sub(r"\\n'", "", graph_export)


    print(graph_export)

    assert False