from __future__ import annotations
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


class AzureClient:
    def __init__(
        self, credential: AzureCredentials, subscription_id: str, resource_group: Optional[str] = None
    ) -> None:
        self.credential = credential
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.client = ResourceManagementClient(self.credential, self.subscription_id)

    def list(self, spec: AzureApiSpec, **kwargs: Any) -> List[Json]:
        return self._call(spec, **kwargs)

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
        path = spec.path.format_map(
            {"subscriptionId": self.subscription_id, "resourceGroupName": self.resource_group, **params}
        )
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
        js: Union[Json, List[Json]] = response.json()
        if spec.access_path and isinstance(js, dict):
            js = js[spec.access_path]
        if spec.expect_array and isinstance(js, list):
            return js
        else:
            return [js]  # type: ignore

    def for_resource_group(self, resource_group: str) -> AzureClient:
        return AzureClient(self.credential, self.subscription_id, resource_group)
