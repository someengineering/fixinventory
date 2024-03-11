from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, MutableMapping, Optional, Any, Tuple, Union, Dict
from urllib.parse import urlparse

from attr import define
from azure.core.exceptions import (
    ClientAuthenticationError,
    ResourceNotFoundError,
    map_error,
    HttpResponseError,
)
from azure.core.pipeline import PipelineResponse
from azure.core.rest import HttpRequest
from azure.core.utils import case_insensitive_dict
from azure.mgmt.core.exceptions import ARMErrorFormat
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.resources._serialization import Serializer
from azure.mgmt.resource.resources.models import GenericResource

from fix_plugin_azure.config import AzureCredentials
from fixlib.types import Json


@define
class AzureApiSpec:
    service: str
    version: str
    path: str
    path_parameters: List[str] = []
    query_parameters: List[str] = []
    access_path: Optional[str] = None
    expect_array: bool = False


class AzureClient(ABC):
    @abstractmethod
    def list(self, spec: AzureApiSpec, **kwargs: Any) -> List[Json]:
        pass

    @abstractmethod
    def for_location(self, location: str) -> AzureClient:
        pass

    @abstractmethod
    def delete(self, resource_id: str) -> bool:
        pass

    @abstractmethod
    def update_resource_tag(self, tag_name: str, tag_value: str, resource_id: str) -> bool:
        pass

    @abstractmethod
    def delete_resource_tag(self, tag_name: str, resource_id: str) -> bool:
        pass

    @staticmethod
    def __create_management_client(
        credential: AzureCredentials,
        subscription_id: str,
        resource_group: Optional[str] = None,
    ) -> AzureClient:
        return AzureResourceManagementClient(credential, subscription_id, resource_group)

    create = __create_management_client


class AzureResourceManagementClient(AzureClient):
    def __init__(
        self,
        credential: AzureCredentials,
        subscription_id: str,
        location: Optional[str] = None,
    ) -> None:
        self.credential = credential
        self.subscription_id = subscription_id
        self.location = location
        self.client = ResourceManagementClient(self.credential, self.subscription_id)

    def list(self, spec: AzureApiSpec, **kwargs: Any) -> List[Json]:
        try:
            return self._call(spec, **kwargs)
        except HttpResponseError as e:
            if e.error and e.error.code == "NoRegisteredProviderFound":
                return []  # API not available in this region
            else:
                raise e

    def delete(self, resource_id: str) -> bool:
        try:
            self.client.resources.begin_delete_by_id(resource_id=resource_id, api_version="2021-04-01")
        except HttpResponseError as e:
            if e.error and e.error.code == "ResourceNotFoundError":
                return False  # Resource not found to delete
            else:
                raise e

        return True

    def update_resource_tag(self, tag_name: str, tag_value: str, resource_id: str) -> bool:
        return self._update_or_delete_tag(
            tag_name=tag_name, tag_value=tag_value, resource_id=resource_id, is_update=True
        )

    def delete_resource_tag(self, tag_name: str, resource_id: str) -> bool:
        return self._update_or_delete_tag(tag_name=tag_name, tag_value="", resource_id=resource_id, is_update=False)

    def _update_or_delete_tag(self, tag_name: str, tag_value: str, resource_id: str, is_update: bool) -> bool:
        try:
            # Get the resource by its ID
            resource = self.client.resources.get_by_id(resource_id=resource_id, api_version="2021-04-01")

            # Check if need to update or delete tag
            if is_update:
                # Create the tag or update its value if it exists
                resource.tags[tag_name] = tag_value
            else:
                # Check if the tag exists in the resource's tags
                existing_tag_value = resource.tags.get(tag_name)

                # If the tag exists, delete it
                if existing_tag_value is not None:
                    resource.tags.pop(tag_name)
                else:
                    return True

            # Create or update the resource to reflect the removal of the tag
            updated_resource = GenericResource(location=resource.location, tags=resource.tags)
            self.client.resources.begin_create_or_update_by_id(resource_id, "2021-04-01", updated_resource)

        except HttpResponseError as e:
            if e.error and e.error.code == "ResourceNotFoundError":
                return False  # Resource not found
            elif e.error and e.error.code == "ResourceExistsError":
                return False  # Tag for update/delete does not exist
            else:
                raise e

        return True

    # noinspection PyProtectedMember
    def _call(self, spec: AzureApiSpec, **kwargs: Any) -> List[Json]:
        ser = Serializer()

        error_map = {
            401: ClientAuthenticationError,
            404: ResourceNotFoundError,
        }

        # Construct lookup map used to fill query and path parameters
        lookup_map = {"subscriptionId": self.subscription_id, "location": self.location, **kwargs}

        # Construct headers
        headers = case_insensitive_dict()
        headers["Accept"] = ser.header("accept", headers.pop("Accept", "application/json"), "str")  # type: ignore # noqa: E501

        # Construct path map
        path_map = case_insensitive_dict()
        for param in spec.path_parameters:
            if lookup_map.get(param, None) is not None:
                path_map[param] = lookup_map[param]
            else:
                raise KeyError(f"Path parameter {param} was not provided as argument")

        # Construct parameters
        params = case_insensitive_dict()
        params["api-version"] = ser.query("api-version", spec.version, "str")  # type: ignore
        for param in spec.query_parameters:
            if param not in params:
                if lookup_map.get(param, None) is not None:
                    params[param] = ser.query(param, lookup_map[param], "str")  # type: ignore # noqa: E501
                else:
                    raise KeyError(f"Query parameter {param} was not provided as argument")

        # Construct url
        path = spec.path.format_map(path_map)
        url = self.client._client.format_url(path)  # pylint: disable=protected-access

        # Send request
        response = self._make_request(url, params, headers)

        # Handle error responses
        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        # Parse json content
        js: Union[Json, List[Json]] = response.json()

        if isinstance(js, dict):
            if "nextLink" in js:
                js = self._handle_pagination(js, spec, error_map, headers)
            else:
                if spec.access_path:
                    js = js[spec.access_path]
        if spec.expect_array and isinstance(js, list):
            return js
        else:
            return [js]  # type: ignore

    def _handle_pagination(
        self, js: Json, spec: AzureApiSpec, error_map: Dict[int, Any], headers: MutableMapping[str, Any]
    ) -> List[Json]:
        nextlink_jsons: List[Json] = []
        if spec.access_path:
            nextlink_jsons.extend(js[spec.access_path])
        else:
            nextlink_jsons.append(js)
        while "nextLink" in js:
            nextlink = js["nextLink"]
            if nextlink is None:
                break
            # Split nextlink to parts
            path, queries = self._split_nextlink(nextlink)

            nextlink_params = self._parse_query_parameters(queries)
            url = self.client._client.format_url(path)

            response = self._make_request(url, nextlink_params, headers)
            if response.status_code != 200:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)
            js = response.json()
            if isinstance(js, dict):
                if spec.access_path:
                    nextlink_jsons.extend(js[spec.access_path])
                else:
                    nextlink_jsons.append(js)

        return nextlink_jsons

    def _split_nextlink(self, nextlink: str) -> Tuple[str, str]:
        # Parse url to extract queries and path
        parsed_url = urlparse(nextlink)
        path_without_query = parsed_url.path
        path_queries = parsed_url.query
        return (path_without_query, path_queries)

    def _parse_query_parameters(self, queries: str) -> Dict[str, str]:
        # Construct parameters for requesting the next link
        params = {}
        for query in queries.split("&"):
            key, value = query.split("=")
            params[key] = value
        return params

    def _make_request(self, url: str, params: MutableMapping[str, Any], headers: MutableMapping[str, Any]) -> Any:
        # Construct and send request
        request = HttpRequest(method="GET", url=url, params=params, headers=headers)
        pipeline_response: PipelineResponse = self.client._client._pipeline.run(request, stream=False)  # type: ignore
        response = pipeline_response.http_response

        return response

    def for_location(self, location: str) -> AzureClient:
        return AzureClient.create(self.credential, self.subscription_id, location)
