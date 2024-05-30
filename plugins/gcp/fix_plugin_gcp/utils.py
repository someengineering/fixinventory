import os
import socket
from datetime import datetime
from typing import Iterable, List, Union, Callable, Any, Dict, Optional

from google.oauth2 import service_account
from googleapiclient import discovery
from googleapiclient.discovery_cache.base import Cache as GoogleApiClientCache
from googleapiclient.errors import HttpError as GoogleApiClientHttpError
from retrying import retry
from tenacity import Retrying, stop_after_attempt, retry_if_exception_type

import fixlib.logger
from fixlib.baseresources import BaseResource
from fixlib.config import Config
from fixlib.core.actions import CoreFeedback
from fixlib.graph import Graph
from fixlib.lock import RWLock

log = fixlib.logger.getLogger("fix." + __name__)
fixlib.logger.getLogger("googleapiclient").setLevel(fixlib.logger.ERROR)


SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def retry_on_error(e):
    if isinstance(e, socket.timeout):
        log.debug("Got socket timeout - retrying")
        return True
    return False


class MemoryCache(GoogleApiClientCache):
    _cache = {}

    def get(self, url):
        return MemoryCache._cache.get(url)

    def set(self, url, content):
        MemoryCache._cache[url] = content


class Credentials:
    _credentials = {}
    _initialized = False
    _lock = RWLock()

    @staticmethod
    def load(feedback: Optional[CoreFeedback] = None):
        with Credentials._lock.write_access:
            if not Credentials._initialized:
                for sa_data in Config.gcp.service_account:
                    try:
                        log.debug("Loading credentials from %s", sa_data)
                        credentials = load_credentials(sa_data)
                        for project in list_credential_projects(credentials):
                            Credentials._credentials[project["id"]] = credentials
                    except Exception as e:
                        log.error("Unable to load credentials from %s", sa_data, exc_info=e)
                        if feedback is not None:
                            feedback.error(f"Unable to load credentials from {sa_data}: {e}")
                Credentials._initialized = True

    @staticmethod
    def get(project_id: str):
        Credentials.load()
        with Credentials._lock.read_access:
            return Credentials._credentials.get(project_id)

    @staticmethod
    def all(feedback: Optional[CoreFeedback] = None) -> Dict:
        Credentials.load(feedback)
        with Credentials._lock.read_access:
            return dict(Credentials._credentials)

    @staticmethod
    def reload():
        with Credentials._lock.write_access:
            Credentials._initialized = False
        Credentials.load()


def load_credentials(path: str):
    if len(path) == 0:
        return None
    file = os.path.expanduser(path)
    if os.path.isfile(file):
        return service_account.Credentials.from_service_account_file(file, scopes=SCOPES)
    else:
        raise ValueError(f"No credentials file found at {file}")


@retry(
    stop_max_attempt_number=10,
    wait_exponential_multiplier=3000,
    wait_exponential_max=300000,
    retry_on_exception=retry_on_error,
)
def gcp_client(service: str, version: str, credentials: str):
    client = discovery.build(service, version, credentials=credentials, cache=MemoryCache())
    return client


def list_credential_projects(credentials) -> List:
    ret = []
    try:
        client = gcp_client("cloudresourcemanager", "v1", credentials=credentials)
        projects = client.projects()
        for project in paginate(projects, "list", "projects"):
            ctime = project.get("createTime")
            if ctime is not None:
                ctime = iso2datetime(ctime)
            project_name = project.get("name")
            project_id = project.get("projectId", "")
            if project_id.startswith("sys-"):
                continue
            p = {
                "id": project_id,
                "name": project_name,
                "ctime": ctime,
            }
            ret.append(p)
    except GoogleApiClientHttpError:
        log.error("Unable to load projects from cloudresourcemanager - falling back to local credentials information")
        p = {
            "id": credentials.project_id,
            "name": credentials.project_id,
        }
        ret.append(p)
    return ret


def iso2datetime(ts: str) -> datetime:
    if ts is None:
        return
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    if ts is not None:
        return datetime.fromisoformat(ts)


def paginate(
    gcp_resource: Callable,
    method_name: str,
    items_name: str,
    subitems_name: str = None,
    exclude_region_resources: bool = False,
    **kwargs,
) -> Iterable:
    """Paginate GCP API list and aggregatedList results.

    Args:
        gcp_resource: GCP resource on which we do our paging
        method_name: list method to call. Usually `list` or `aggregatedList`
        items_name: Name of the key in our result that contains the list of items.
            Usually `items`
        subitems_name: When using aggregatedList this contains the actual items.
            Usually the same as the gcp_resource name. E.g. `disks` when requesting
            disks, `instances` when fetching instances, etc.
        exclude_region_resources: Regional resources have their own API and can be
            excluded from aggregatedList calls if so desired
    """
    next_method_name = method_name + "_next"
    method = getattr(gcp_resource, method_name)
    request = method(**kwargs)
    while request is not None:
        for attempt in Retrying(
            reraise=True,
            stop=stop_after_attempt(10),
            retry=retry_if_exception_type(socket.timeout),
        ):
            with attempt:
                result = request.execute()
        if items_name in result:
            items = result[items_name]
            if isinstance(items, dict):
                for location, item in items.items():
                    if (
                        method_name == "aggregatedList"
                        and exclude_region_resources
                        and str(location).startswith("regions/")
                    ):
                        continue
                    if subitems_name in item:
                        yield from item[subitems_name]
            else:
                yield from items
        if hasattr(gcp_resource, next_method_name):
            method = getattr(gcp_resource, next_method_name)
            request = method(request, result)
        else:
            request = None


def get_result_data(result: Dict, value: Union[str, Callable]) -> Any:
    """Returns data from a GCP API call result dict.

    Args:
        result: Dict containing the result or a GCP API execute() call.
        value: Either directly the name of a key found in result or
            a callable like a lambda that finds the relevant data withing
            result.
    """
    data = None
    if callable(value):
        try:
            data = value(result)
        except Exception:
            log.exception(f"Exception while trying to fetch data calling {value}")
    elif value in result:
        data = result[value]
    return data


def common_resource_kwargs(resource: BaseResource) -> Dict:
    common_kwargs = {}
    if resource.account().id != "undefined" and "project" in resource.resource_args:
        common_kwargs["project"] = resource.account().id
    if resource.zone().name != "undefined" and "zone" in resource.resource_args:
        common_kwargs["zone"] = resource.zone().name
    elif resource.region().name != "undefined" and "region" in resource.resource_args:
        common_kwargs["region"] = resource.region().name
    return common_kwargs


def delete_resource(resource: BaseResource) -> bool:
    delete_kwargs = {str(resource._delete_identifier): resource.name}
    common_kwargs = common_resource_kwargs(resource)
    delete_kwargs.update(common_kwargs)

    gr = gcp_resource(resource)
    request = gr.delete(**delete_kwargs)
    request.execute()
    return True


def gcp_service(resource: BaseResource, graph: Graph = None):
    service_kwargs = {}
    if resource.account().id != "undefined":
        service_kwargs["credentials"] = Credentials.get(resource.account(graph).id)
    return gcp_client(resource.client, resource.api_version, **service_kwargs)


def gcp_resource(resource: BaseResource, graph: Graph = None):
    service = gcp_service(resource, graph)
    gr = getattr(service, resource._client_method)
    return gr()
