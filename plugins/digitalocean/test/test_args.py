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

    configuration = resoto_digitalocean_openapi_client.Configuration(
        access_token = os.environ['DO_TOKEN']
    )

    with resoto_digitalocean_openapi_client.ApiClient(configuration) as api_client:
        client = StreamingWrapper(api_client)

        try:
            # projects = client.list_projects()
            # print('all projects list')
            # print(projects)

            # print('project team')
            # print(projects[0]['owner_uuid'])


            print('volumes')
            print(client.list_vpcs())
        
            # for project in projects:
                # print(f"getting project {project['name']}")
                # resp = client.list_project_resources(project['id'])
                # print(resp)

            assert False
        except resoto_digitalocean_openapi_client.ApiException as e:
            print("Exception when calling ClickApplicationsApi->install_kubernetes: %s\n" % e)

def test_collect():

    configuration = resoto_digitalocean_openapi_client.Configuration(
        access_token = os.environ['DO_TOKEN']
    )

    with resoto_digitalocean_openapi_client.ApiClient(configuration) as api_client:
        client = StreamingWrapper(api_client)

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
