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


def test_args():
    arg_parser = get_arg_parser()
    DigitalOceanCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.digitalocean_region is None

def atest_api_call():

    
    access_token = os.environ['DO_TOKEN']
    

    
    client = StreamingWrapper(access_token)

    projects = client.list_kubernetes_clusters()
    print('all k8s clusters')
    print(projects)

    # print('project team')
    # print(projects[0]['owner_uuid'])



    assert False

def test_collect():

    access_token = os.environ['DO_TOKEN']

    client = StreamingWrapper(access_token)

    projects = client.list_projects()
    team_id = str(projects[0]['owner_id'])
    team = DigitalOceanTeam(id = team_id, tags={})

    collector = DigitalOceanTeamCollector(team, client) 


    collector.collect()

    graph_export = f"{list(collector.graph.export_iterator())}"

    graph_export = re.sub("b'", "", graph_export)
    graph_export = re.sub(r"\\n'", "", graph_export)


    print(graph_export)

    assert False
