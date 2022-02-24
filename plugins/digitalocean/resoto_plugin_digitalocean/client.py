import resotolib.logging
from resoto_digitalocean_client.api import project_resources_api, projects_api, droplets_api
from resoto_digitalocean_client import ApiClient
from typing import Dict, List, Any
import logging

log = resotolib.logging.getLogger("resoto." + __name__)

# todo: support pagination and streaming
# todo: make it async
# todo: stream the response
class StreamingWrapper:

    log.setLevel(logging.DEBUG)

    def __init__(self, api_client: ApiClient) -> None:
        self.projects = projects_api.ProjectsApi(api_client)
        self.project_resources = project_resources_api.ProjectResourcesApi(api_client)
        self.droplets = droplets_api.DropletsApi(api_client)
    

    def list_projects(self) -> List[Dict[str, Any]]:
        response = self.projects.list_projects()
        log.debug(
            (
                "list_projects: "
                f"{response}"
            )
        )
        return response['projects']
    
    def list_project_resources(self, project_id: str) -> List[Dict[str, Any]]:
        response = self.project_resources.list_project_resources(project_id)
        log.debug(
            (
                f"list_project_resources {project_id}: "
                f"{response}"
            )
        )
        return response['resources']

    def list_droplets(self) -> List[Dict[str, Any]]:
        response = self.droplets.list_all_droplets()
        log.debug(
            (
                "list_droplets: "
                f"{response}"
            )
        )
        return response['droplets']
