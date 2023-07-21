from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional, Any, Union

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

from resoto_plugin_azure.config import AzureCredentials
from resotolib.types import Json


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

    @staticmethod
    def __create_management_client(
        credential: AzureCredentials, subscription_id: str, resource_group: Optional[str] = None
    ) -> AzureClient:
        return AzureResourceManagementClient(credential, subscription_id, resource_group)

    create = __create_management_client


class AzureResourceManagementClient(AzureClient):
    def __init__(self, credential: AzureCredentials, subscription_id: str, location: Optional[str] = None) -> None:
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

    def delete(self, resource_id: str) -> None:
        self.client.resources.delete_by_id(resource_id)

    # noinspection PyProtectedMember
    def _call(self, spec: AzureApiSpec, **kwargs: Any) -> List[Json]:
        _SERIALIZER = Serializer()

        error_map = {
            401: ClientAuthenticationError,
            404: ResourceNotFoundError,
        }

        # Construct headers
        headers = case_insensitive_dict(kwargs.pop("headers", {}) or {})
        headers["Accept"] = _SERIALIZER.header("accept", headers.pop("Accept", "application/json"), "str")  # type: ignore # noqa: E501

        # Construct parameters
        params = case_insensitive_dict(kwargs.pop("params", {}) or {})
        params["api-version"] = _SERIALIZER.query("api_version", spec.version, "str")  # type: ignore

        # Construct url
        path = spec.path.format_map({"subscriptionId": self.subscription_id, "location": self.location, **params})
        url = self.client._client.format_url(path)  # pylint: disable=protected-access

        # Construct and send request
        request = HttpRequest(method="GET", url=url, params=params, headers=headers, **kwargs)
        pipeline_response: PipelineResponse = self.client._client._pipeline.run(  # type: ignore
            request, stream=False, **kwargs
        )
        response = pipeline_response.http_response

        # Handle error responses
        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)  # type: ignore
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)  # type: ignore

        # Parse json content
        # TODO: handle pagination
        js: Union[Json, List[Json]] = response.json()
        if spec.access_path and isinstance(js, dict):
            js = js[spec.access_path]
        if spec.expect_array and isinstance(js, list):
            return js
        else:
            return [js]  # type: ignore

    def for_location(self, location: str) -> AzureClient:
        return AzureClient.create(self.credential, self.subscription_id, location)
