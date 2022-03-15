from typing import Dict, List, Any, Optional

import requests
import boto3

import resotolib.logging

log = resotolib.logging.getLogger("resoto." + __name__)

Json = Dict[str, Any]


# todo: make it async
# todo: stream the response
class StreamingWrapper:
    def __init__(
        self,
        token: str,
        spaces_access_key: Optional[str],
        spaces_secret_key: Optional[str],
    ) -> None:
        self.token = token
        self.spaces_access_key = spaces_access_key
        self.spaces_secret_key = spaces_secret_key
        if spaces_access_key and spaces_secret_key:
            self.session = boto3.session.Session()
        else:
            self.session = None

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
        payload = json_response.get(payload_object_name, [])
        result.extend(payload if isinstance(payload, list) else [payload])

        while json_response.get("links", {}).get("pages", {}).get("last", "") != url:
            url = json_response.get("links", {}).get("pages", {}).get("next", "")
            if url == "":
                break
            log.debug(f"fetching {url}")
            json_response = requests.get(url, headers=headers).json()
            payload = json_response.get(payload_object_name, [])
            result.extend(payload if isinstance(payload, list) else [payload])

        log.debug(f"DO request {path} returned {len(result)} items")
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

    def list_spaces(self, region_slug: str) -> List[Json]:
        if self.session is not None:
            client = self.session.client(
                "s3",
                endpoint_url=f"https://{region_slug}.digitaloceanspaces.com",
                # Find your endpoint in the control panel, under Settings. Prepend "https://".
                region_name=region_slug,  # Use the region in your endpoint.
                aws_access_key_id=self.spaces_access_key,
                # Access key pair. You can create access key pairs using the control panel or API.
                aws_secret_access_key=self.spaces_secret_key,
            )

            return client.list_buckets().get("Buckets", [])
        else:
            return []

    def list_apps(self) -> List[Json]:
        return self._make_request("/apps", "apps")

    def list_cdn_endpoints(self) -> List[Json]:
        return self._make_request("/cdn/endpoints", "endpoints")

    def list_certificates(self) -> List[Json]:
        return self._make_request("/certificates", "certificates")

    def get_registry_info(self) -> List[Json]:
        return self._make_request("/registry", "registry")

    def list_registry_repositories(self, registry_id: str) -> List[Json]:
        return self._make_request(
            f"/registry/{registry_id}/repositoriesV2", "repositories"
        )

    def list_registry_repository_tags(
        self, registry_id: str, repository_name: str
    ) -> List[Json]:
        return self._make_request(
            f"/registry/{registry_id}/repositories/{repository_name}/tags", "tags"
        )

    def list_ssh_keys(self) -> List[Json]:
        return self._make_request("/account/keys", "ssh_keys")

    def list_tags(self) -> List[Json]:
        return self._make_request("/tags", "tags")

    def list_domains(self) -> List[Json]:
        return self._make_request("/domains", "domains")

    def list_domain_records(self, domain_name: str) -> List[Json]:
        return self._make_request(f"/domains/{domain_name}/records", "domain_records")

    def list_firewalls(self) -> List[Json]:
        return self._make_request("/firewalls", "firewalls")
