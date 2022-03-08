import json
from typing import Dict, List, Any

import requests

import resotolib.logging

log = resotolib.logging.getLogger("resoto." + __name__)

Json = Dict[str, Any]


# todo: make it async
# todo: stream the response
class StreamingWrapper:
    def __init__(self, token: str) -> None:
        self.token = token

    def _make_request(self, path: str, payload_object_name: str) -> List[Json]:
        result = []
        do_api_endpoint = "https://api.digitalocean.com/v2"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

        url = f"{do_api_endpoint}{path}?page=1&per_page=200"
        log.debug(f"fetching {url}")

        json_response = requests.get(url, headers=headers).json()
        result.extend(json_response.get(payload_object_name, []))

        while json_response.get("links", {}).get("pages", {}).get("last", "") != url:
            url = json_response.get("links", {}).get("pages", {}).get("next", "")
            if url == "":
                break
            log.debug(f"fetching {url}")
            json_response = requests.get(url, headers=headers).json()
            result.extend(json_response.get(payload_object_name, []))

        log.debug(f"DO request {path}: " f"{json.dumps(result)}")
        return result

    def list_projects(self) -> List[Json]:
        return self._make_request("/projects", "projects")

    def list_project_resources(self, project_id: str) -> List[Json]:
        return self._make_request(f"/projects/{project_id}/resources", "resources")

    def list_droplets(self) -> List[Json]:
        return self._make_request("/droplets", "droplets")

    def list_regions(self) -> List[Json]:
        return self._make_request("/regions", "regions")

    def list_volumes(self) -> List[Json]:
        return self._make_request("/volumes", "volumes")

    def list_databases(self) -> List[Json]:
        return self._make_request("/databases", "databases")

    def list_vpcs(self) -> List[Json]:
        return self._make_request("/vpcs", "vpcs")

    def list_kubernetes_clusters(self) -> List[Json]:
        return self._make_request("/kubernetes/clusters", "kubernetes_clusters")

    def list_snapshots(self) -> List[Json]:
        return self._make_request("/snapshots", "snapshots")

    def list_load_balancers(self) -> List[Json]:
        return self._make_request("/load_balancers", "load_balancers")

    def list_floating_ips(self) -> List[Json]:
        return self._make_request("/floating_ips", "floating_ips")
