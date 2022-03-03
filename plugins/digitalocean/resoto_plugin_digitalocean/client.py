import resotolib.logging
import requests
from typing import Dict, List, Any


log = resotolib.logging.getLogger("resoto." + __name__)

do_api_endpoint = "https://api.digitalocean.com/v2"

# todo: support pagination and streaming
# todo: make it async
# todo: stream the response
class StreamingWrapper:

    def __init__(self, token: str) -> None:
        self.token = token


    def _make_request(self, path: str) -> Dict:
        headers = {
            'Authorization': f"Bearer {self.token}",
            'Content-Type': 'application/json',
        }
        response = requests.get(do_api_endpoint + path, headers=headers)
        log.debug(
            (
                f"DO request {path}: "
                f"{response}"
            )
        )
        return response.json()
    

    def list_projects(self) -> List[Dict[str, Any]]:
        response = self._make_request("/projects")
        return response.get('projects', [])
    
    def list_project_resources(self, project_id: str) -> List[Dict[str, Any]]:
        response = self._make_request(f"/projects/{project_id}/resources")
        return response.get('resources', [])

    def list_droplets(self) -> List[Dict[str, Any]]:
        response = self._make_request("/droplets")
        return response.get('droplets', [])

    def list_regions(self) -> List[Dict[str, Any]]:
        response = self._make_request("/regions")
        return response.get('regions', [])

    def list_volumes(self) -> List[Dict[str, Any]]:
        response = self._make_request("/volumes")
        return response.get('volumes', [])

    def list_databases(self) -> List[Dict[str, Any]]:
        response = self._make_request("/databases")
        return response.get('databases', [])

    def list_vpcs(self) -> List[Dict[str, Any]]:
        response = self._make_request("/vpcs")
        return response.get('vpcs', [])

    def list_kubernetes_clusters(self) -> List[Dict[str, Any]]:
        response = self._make_request("/kubernetes/clusters")
        return response.get('kubernetes_clusters', [])

    