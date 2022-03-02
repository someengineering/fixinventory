import resotolib.logging
from resoto_digitalocean_openapi_client.api import (
    project_resources_api, 
    projects_api, 
    droplets_api,
    regions_api,
    block_storage_api,
    databases_api,
    vpcs_api,
)
from resoto_digitalocean_openapi_client import ApiClient
from typing import Dict, List, Any
import logging

log = resotolib.logging.getLogger("resoto." + __name__)

# todo: support pagination and streaming
# todo: make it async
# todo: stream the response
class StreamingWrapper:

    def __init__(self, api_client: ApiClient) -> None:
        self.projects = projects_api.ProjectsApi(api_client)
        self.project_resources = project_resources_api.ProjectResourcesApi(api_client)
        self.droplets = droplets_api.DropletsApi(api_client)
        self.regions = regions_api.RegionsApi(api_client)
        self.volumes = block_storage_api.BlockStorageApi(api_client)
        self.databases = databases_api.DatabasesApi(api_client)
        self.vpc = vpcs_api.VPCsApi(api_client)
    

    def list_projects(self) -> List[Dict[str, Any]]:
        response = self.projects.list_projects()
        log.debug(
            (
                "list_projects: "
                f"{response}"
            )
        )
        return response.get('projects', [])
    
    def list_project_resources(self, project_id: str) -> List[Dict[str, Any]]:
        response = self.project_resources.list_project_resources(project_id)
        log.debug(
            (
                f"list_project_resources {project_id}: "
                f"{response}"
            )
        )
        return response.get('resources', [])

    def list_droplets(self) -> List[Dict[str, Any]]:
        response = self.droplets.list_all_droplets()
        log.debug(
            (
                "list_droplets: "
                f"{response}"
            )
        )
        return response.get('droplets', [])

    def list_regions(self) -> List[Dict[str, Any]]:
        response = self.regions.list_all_regions()
        log.debug(
            (
                "list_regions: "
                f"{response}"
            )
        )
        return response.get('regions', [])

    def list_volumes(self) -> List[Dict[str, Any]]:
        response = self.volumes.list_all_volumes()
        log.debug(
            (
                "list_volumes: "
                f"{response}"
            )
        )
        return response.get('volumes', [])

    def list_databases(self) -> List[Dict[str, Any]]:
        response = self.databases.list_database_clusters()
        log.debug(
            (
                "list_databases: "
                f"{response}"
            )
        )
        return response.get('databases', [])

    def list_vpcs(self) -> List[Dict[str, Any]]:
        response = self.vpc.list_vpcs()
        log.debug(
            (
                "list_vpcs: "
                f"{response}"
            )
        )
        return response.get('vpcs', [])