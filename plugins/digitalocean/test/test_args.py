from resotolib.args import get_arg_parser, ArgumentParser
from resoto_plugin_digitalocean import DigitalOceanCollectorPlugin
import resoto_digitalocean_client
from resoto_digitalocean_client.api import project_resources_api
from resoto_digitalocean_client.api import projects_api
from resoto_digitalocean_client.api import regions_api
import os

def test_args():
    arg_parser = get_arg_parser()
    DigitalOceanCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.digitalocean_region is None

def test_api_call():

    configuration = resoto_digitalocean_client.Configuration(
        access_token = os.environ['DO_TOKEN']
    )


    with resoto_digitalocean_client.ApiClient(configuration) as api_client:
        api_instance = project_resources_api.ProjectResourcesApi(api_client)
        projects_api_instance = projects_api.ProjectsApi(api_client)

        try:
            projects_api_respones = projects_api_instance.list_projects()

            print('all projects list')
            print(projects_api_respones)


            for project in projects_api_respones.get('projects', []):
                print(f"getting project {project['name']}")
                resp = api_instance.list_project_resources(project.get('id'))
                print(resp)

            print('default')
            api_response = api_instance.list_default_project_resources()
            print(api_response)
            assert False
        except resoto_digitalocean_client.ApiException as e:
            print("Exception when calling ClickApplicationsApi->install_kubernetes: %s\n" % e)