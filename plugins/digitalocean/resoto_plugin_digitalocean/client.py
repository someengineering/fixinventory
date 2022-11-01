import logging
from attrs import define
from functools import lru_cache
from typing import List, Any, Optional, Union, TypeVar, Callable

import boto3
import requests
from botocore.exceptions import EndpointConnectionError, HTTPClientError
from retrying import retry as retry_decorator

from resoto_plugin_digitalocean.utils import RetryableHttpError
from resoto_plugin_digitalocean.utils import retry_on_error
from resotolib.config import Config
from resotolib.core.actions import CoreFeedback
from resotolib.types import Json

F = TypeVar("F", bound=Callable[..., Any])


def retry(func: F) -> F:
    return retry_decorator(  # type: ignore
        stop_max_attempt_number=10,
        wait_exponential_multiplier=3000,
        wait_exponential_max=300000,
        retry_on_exception=retry_on_error,
    )(func)


log = logging.getLogger("resoto." + __name__)

Failure = str


# todo: make it async
# todo: stream the response
class StreamingWrapper:
    def __init__(
        self,
        token: str,
        spaces_access_key: Optional[str],
        spaces_secret_key: Optional[str],
        core_feedback: Optional[CoreFeedback] = None,
    ) -> None:
        self.token = token
        self.spaces_access_key = spaces_access_key
        self.spaces_secret_key = spaces_secret_key
        self.core_feedback = core_feedback
        self.do_api_endpoint = "https://api.digitalocean.com/v2"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        if spaces_access_key and spaces_secret_key:
            self.session = boto3.session.Session()
        else:
            self.session = None

    def with_feedback(self, core_feedback: CoreFeedback) -> "StreamingWrapper":
        return StreamingWrapper(self.token, self.spaces_access_key, self.spaces_secret_key, core_feedback)

    def check_status_code(self, response: requests.Response) -> bool:
        status_code = response.status_code
        url = response.request.url
        method = response.request.method
        if status_code == 429:
            raise RetryableHttpError(f"Too many requests: {method} {url} {response.reason} {response.text}")
        if status_code // 100 == 5:
            msg = f"Server error: {method} {url} {response.reason} {response.text}"
            if self.core_feedback:
                self.core_feedback.error(msg, log)
            raise RetryableHttpError(msg)
        if status_code // 100 == 4:
            msg = f"Client error: {method} {url} {response.reason} {response.text}"
            if self.core_feedback:
                self.core_feedback.error(msg, log)
            return False
        if status_code // 100 == 2:
            log.debug(f"Success: {method} {url}")
            return True

        log.warning(f"unknown status code {status_code}: {method} {url} {response.reason} {response.text}")
        return False

    @retry
    def _fetch(self, path: str, payload_object_name: str) -> List[Json]:
        result: List[Json] = []

        url = f"{self.do_api_endpoint}{path}?page=1&per_page=200"
        log.debug(f"fetching {url}")

        def validate_status(response: requests.Response) -> requests.Response:
            if response.status_code == 429:
                raise RetryableHttpError(f"Too many requests: {response.reason} {response.text}")
            if response.status_code / 100 == 5:
                msg = f"Server error: {response.reason} {response.text}"
                if self.core_feedback:
                    self.core_feedback.error(msg, log)
                raise RetryableHttpError(msg)
            return response

        json_response = validate_status(requests.get(url, headers=self.headers, allow_redirects=True)).json()
        payload = json_response.get(payload_object_name, [])
        result.extend(payload if isinstance(payload, list) else [payload])

        while json_response.get("links", {}).get("pages", {}).get("last", "") != url:
            url = json_response.get("links", {}).get("pages", {}).get("next", "")
            if url == "":
                break
            log.debug(f"fetching {url}")
            json_response = validate_status(requests.get(url, headers=self.headers, allow_redirects=True)).json()
            payload = json_response.get(payload_object_name, [])
            result.extend(payload if isinstance(payload, list) else [payload])

        log.debug(f"DO request {path} returned {len(result)} items")
        return result

    @retry
    def delete(self, path: str, resource_id: Optional[str]) -> bool:
        resource_id_path = f"/{resource_id}" if resource_id else ""
        url = f"{self.do_api_endpoint}{path}{resource_id_path}"
        log.debug(f"deleting {url}")

        response = requests.delete(url, headers=self.headers, allow_redirects=True)

        status_code = response.status_code
        if status_code == 429:
            raise RetryableHttpError(f"Too many requests: {url} {response.reason} {response.text}")
        if status_code // 100 == 5:
            raise RetryableHttpError(f"Server error: {url} {response.reason} {response.text}")
        if status_code == 422 and path == "/floating_ips":
            is_being_unassighed = "The floating IP already has a pending event."
            if response.json().get("message") == is_being_unassighed:
                raise RetryableHttpError(f"floating_ip: {url} {response.reason} {response.text}")
        if status_code // 100 == 4:
            log.warning(f"Client error: DELETE {url} {response.reason} {response.text}")
            return False
        if status_code // 100 == 2:
            log.debug(f"deleted: {url}")
            return True

        log.warning(f"unknown status code {status_code}: {url} {response.reason} {response.text}")
        return False

    def get_team_id(self) -> str:
        return str(self._fetch("/projects", "projects")[0]["owner_id"])

    def list_projects(self) -> List[Json]:
        return self._fetch("/projects", "projects")

    def list_project_resources(self, project_id: str) -> List[Json]:
        return self._fetch(f"/projects/{project_id}/resources", "resources")

    def list_droplets(self) -> List[Json]:
        return self._fetch("/droplets", "droplets")

    def list_regions(self) -> List[Json]:
        return self._fetch("/regions", "regions")

    def list_volumes(self) -> List[Json]:
        return self._fetch("/volumes", "volumes")

    def list_databases(self) -> List[Json]:
        return self._fetch("/databases", "databases")

    def list_vpcs(self) -> List[Json]:
        return self._fetch("/vpcs", "vpcs")

    def list_kubernetes_clusters(self) -> List[Json]:
        return self._fetch("/kubernetes/clusters", "kubernetes_clusters")

    def list_snapshots(self) -> List[Json]:
        return self._fetch("/snapshots", "snapshots")

    def list_load_balancers(self) -> List[Json]:
        return self._fetch("/load_balancers", "load_balancers")

    def list_floating_ips(self) -> List[Json]:
        return self._fetch("/floating_ips", "floating_ips")

    @retry
    def unassign_floating_ip(self, floating_ip_id: str) -> bool:
        payload = '{"type":"unassign"}'
        url = f"{self.do_api_endpoint}/floating_ips/{floating_ip_id}/actions"
        response = requests.post(
            url,
            headers=self.headers,
            data=payload,
            allow_redirects=True,
        )

        return self.check_status_code(response)

    @retry
    def list_spaces(self, region_slug: str) -> List[Json]:
        if self.session is not None:
            try:
                resource = self.session.resource(
                    "s3",
                    endpoint_url=f"https://{region_slug}.digitaloceanspaces.com",
                    region_name=region_slug,
                    aws_access_key_id=self.spaces_access_key,
                    aws_secret_access_key=self.spaces_secret_key,
                )

                buckets: List[Json] = resource.meta.client.list_buckets().get("Buckets", [])
                return buckets
            except HTTPClientError:
                raise RetryableHttpError("DO Spaces: Too many requests")
            except EndpointConnectionError:
                return []
            except Exception as e:
                log.warning(f"Unknown exception when listing spaces, skipping. Exception: {e}")
                return []
        else:
            return []

    @retry
    def delete_space(self, region_slug: str, bucket_name: str) -> bool:
        if self.session is not None:
            try:
                s3 = self.session.resource(
                    "s3",
                    endpoint_url=f"https://{region_slug}.digitaloceanspaces.com",
                    region_name=region_slug,
                    aws_access_key_id=self.spaces_access_key,
                    aws_secret_access_key=self.spaces_secret_key,
                )

                def handle_response_code(result: Any) -> bool:
                    if not isinstance(result, list):
                        result = [result]
                    for message in result:
                        status_code = message.get("ResponseMetadata", {}).get("HTTPStatusCode")
                        if status_code // 100 == 5:
                            raise RetryableHttpError(
                                f"Server error: region: {region_slug}, bucket: {bucket_name}, msg: {message}"
                            )
                        if status_code == 429:
                            raise RetryableHttpError(
                                f"Too many requests: {region_slug}, bucket: {bucket_name}, msg: {message}"
                            )
                        if status_code // 100 == 4:
                            log.warning(f"Client error: region: {region_slug}, bucket: {bucket_name}, msg: {message}")
                            return False
                    return True

                s3_bucket = s3.Bucket(bucket_name)
                bucket_versioning = s3.BucketVersioning(bucket_name)
                object_deletion_result = None
                if bucket_versioning.status == "Enabled":
                    object_deletion_result = s3_bucket.object_versions.delete()
                else:
                    object_deletion_result = s3_bucket.objects.delete()

                handle_response_code(object_deletion_result)

                bucket_deletion_result = s3_bucket.delete()

                return handle_response_code(bucket_deletion_result)

            except RetryableHttpError as e:
                raise e
            except Exception as e:
                log.warning(f"Unknown exception when deleting space, skipping. Exception: {e}")
                return False
        else:
            return False

    def list_apps(self) -> List[Json]:
        return self._fetch("/apps", "apps")

    def list_cdn_endpoints(self) -> List[Json]:
        return self._fetch("/cdn/endpoints", "endpoints")

    def list_certificates(self) -> List[Json]:
        return self._fetch("/certificates", "certificates")

    def get_registry_info(self) -> List[Json]:
        return self._fetch("/registry", "registry")

    def list_registry_repositories(self, registry_id: str) -> List[Json]:
        return self._fetch(f"/registry/{registry_id}/repositoriesV2", "repositories")

    def list_registry_repository_tags(self, registry_id: str, repository_name: str) -> List[Json]:
        return self._fetch(f"/registry/{registry_id}/repositories/{repository_name}/tags", "tags")

    def list_ssh_keys(self) -> List[Json]:
        return self._fetch("/account/keys", "ssh_keys")

    def list_tags(self) -> List[Json]:
        return self._fetch("/tags", "tags")

    @retry
    def get_tag_count(self, tag_name: str) -> Union[Failure, None, int]:
        url = f"{self.do_api_endpoint}/tags/{tag_name}"
        response = requests.get(url, headers=self.headers, allow_redirects=True)
        if response.status_code == 404:
            return None
        if self.check_status_code(response):
            count: int = response.json().get("tag", {}).get("tag", {}).get("resources", {}).get("count", 0)
            return count
        return (
            f"get_tag_count call failed: status {response.status_code}, "
            f"reason: {response.reason}, payload: {response.text}"
        )

    @retry
    def create_tag(self, tag_name: str) -> bool:
        url = f"{self.do_api_endpoint}/tags"
        response = requests.post(url, headers=self.headers, json={"name": tag_name})
        return self.check_status_code(response)

    @retry
    def tag_resource(self, tag_name: str, resource_type: str, resource_id: str) -> bool:
        url = f"{self.do_api_endpoint}/tags/{tag_name}/resources"
        payload = {"resources": [{"resource_id": resource_id, "resource_type": resource_type}]}
        response = requests.post(url, headers=self.headers, json=payload, allow_redirects=True)

        return self.check_status_code(response)

    @retry
    def untag_resource(self, tag_name: str, resource_type: str, resource_id: str) -> bool:
        url = f"{self.do_api_endpoint}/tags/{tag_name}/resources"
        payload = {"resources": [{"resource_id": resource_id, "resource_type": resource_type}]}

        response = requests.delete(url, headers=self.headers, json=payload, allow_redirects=True)

        if response.status_code == 404:
            raise RuntimeError(f"Tag {tag_name} or {resource_type} {resource_id} not found.")
        return self.check_status_code(response)

    def list_domains(self) -> List[Json]:
        return self._fetch("/domains", "domains")

    def list_domain_records(self, domain_name: str) -> List[Json]:
        return self._fetch(f"/domains/{domain_name}/records", "domain_records")

    def list_firewalls(self) -> List[Json]:
        return self._fetch("/firewalls", "firewalls")

    def list_alert_policies(self) -> List[Json]:
        return self._fetch("/monitoring/alerts", "policies")


TeamId = str


@define()
class TeamCredentials:
    team_id: TeamId
    api_token: str
    spaces_access_key: str
    spaces_secret_key: str


@lru_cache(maxsize=256)
def get_team_credentials(team_id: TeamId, cache_invalidation_key: int) -> Optional[TeamCredentials]:
    # todo: do not use the global config
    tokens = Config.digitalocean.api_tokens
    spaces_keys = Config.digitalocean.spaces_access_keys

    spaces_keys = spaces_keys[: len(tokens)]
    spaces_keys.extend([":"] * (len(tokens) - len(spaces_keys)))
    for token, space_keys in zip(tokens, spaces_keys):
        splitted = space_keys.split(":")
        spaces_access_key, spaces_secret_key = splitted[0], splitted[1]
        client = StreamingWrapper(token, spaces_access_key, spaces_secret_key)
        token_team_id = client.get_team_id()
        if token_team_id == team_id:
            return TeamCredentials(token_team_id, token, spaces_access_key, spaces_secret_key)

    return None
