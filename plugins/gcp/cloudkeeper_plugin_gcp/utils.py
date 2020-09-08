from pprint import pformat
from re import sub
from cloudkeeper_plugin_gcp import resources
from typing import Iterable, List
import cloudkeeper.logging
from googleapiclient import discovery
from googleapiclient.errors import HttpError
from googleapiclient.discovery_cache.base import Cache
from google.oauth2 import service_account
from datetime import datetime

# from google.oauth2.credentials import UserAccessTokenCredentials

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


class MemoryCache(Cache):
    _CACHE = {}

    def get(self, url):
        return MemoryCache._CACHE.get(url)

    def set(self, url, content):
        MemoryCache._CACHE[url] = content


class Credentials:
    _CREDENTIALS = {}

    def __init__(self):
        pass

    def load(sa_file):
        credentials = load_credentials(sa_file)


def load_credentials(sa_file: str):
    return service_account.Credentials.from_service_account_file(sa_file, scopes=SCOPES)


def gcp_client(service: str, version: str, credentials: str):
    client = discovery.build(
        service, version, credentials=credentials, cache=MemoryCache()
    )
    return client


def list_credential_projects(credentials) -> List:
    ret = []
    client = gcp_client("cloudresourcemanager", "v1", credentials=credentials)
    projects = client.projects()
    for project in paginate(projects, "list", "projects"):
        lifecycle_status = project.get("lifecycleState")
        ctime = project.get("createTime")
        if ctime is not None:
            ctime = iso2datetime(ctime)
        project_name = project.get("name")
        project_id = project.get("projectId")
        project_number = project.get("projectNumber")
        p = {
            "id": project_id,
            "name": project_name,
            "project_number": project_number,
            "lifecycle_status": lifecycle_status,
            "ctime": ctime,
        }
        ret.append(p)
    return ret


def iso2datetime(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def paginate(
    resource, method_name, items_name, subitems_name=None, **kwargs
) -> Iterable:
    next_method_name = method_name + "_next"
    method = getattr(resource, method_name)
    request = method(**kwargs)
    while request is not None:
        result = request.execute()
        if items_name in result:
            items = result[items_name]
            if isinstance(items, dict):
                for item in items.values():
                    if subitems_name in item:
                        yield from item[subitems_name]
            else:
                yield from items
        if hasattr(resource, next_method_name):
            method = getattr(resource, next_method_name)
            request = method(request, result)
        else:
            request = None


def compute_client(credentials):
    return gcp_client("compute", "v1", credentials=credentials)
