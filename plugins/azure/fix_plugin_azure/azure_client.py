from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import List, MutableMapping, Optional, Any, Union, Dict

from attr import define
from retrying import retry
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

log = logging.getLogger("fix.plugins.azure")


class MetricRequestError(HttpResponseError):
    """Error raised when there's an issue retrieving metric data from the Azure API."""


def is_retryable_exception(e: Exception) -> bool:
    # If we receive a metric request error, then repeat the request
    if isinstance(e, MetricRequestError):
        log.debug(f"Azure Metric request error occured, retrying: {e}")
        return True
    if isinstance(e, HttpResponseError):
        error_code = getattr(e.error, "code", None)
        status_code = getattr(e.response, "status_code", None)

        if error_code == "TooManyRequests" or status_code == 429:
            log.debug(f"Azure API request limit exceeded or throttling, retrying with exponential backoff: {e}")
            return True

    return False


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
        result = self._list_with_retry(spec, **kwargs)
        if result is None:
            return []
        return result  # type: ignore

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

    @retry(  # type: ignore
        stop_max_attempt_number=10,  # 10 attempts: 1000 max 60000: max wait time is 5 minutes
        wait_exponential_multiplier=1000,
        wait_exponential_max=60000,
        retry_on_exception=is_retryable_exception,
    )
    def _list_with_retry(self, spec: AzureApiSpec, **kwargs: Any) -> Optional[List[Json]]:
        try:
            return self._call(spec, **kwargs)
        except ClientAuthenticationError as e:
            log.error(f"[Azure] Call to Azure API is not authorized!: {e}")
            return None
        except HttpResponseError as e:
            if error := e.error:
                if error.code == "NoRegisteredProviderFound":
                    return None  # API not available in this region
                elif error.code == "BadRequest" and spec.service == "metric":
                    raise MetricRequestError from e
            log.warning(f"[Azure] Error encountered while requesting resource: {e}")
            raise e
        except Exception as e:
            log.warning(f"[Azure] called service={spec.service}: hit unexpected error: {e}", exc_info=e)
            return None

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
                js = self._handle_pagination(js, spec, error_map)
            else:
                if spec.access_path:
                    js = js[spec.access_path]
        if spec.expect_array and isinstance(js, list):
            return js
        else:
            return [js]  # type: ignore

    def _handle_pagination(self, js: Json, spec: AzureApiSpec, error_map: Dict[int, Any]) -> List[Json]:
        nextlink_jsons: List[Json] = []
        if spec.access_path:
            nextlink_jsons.extend(js[spec.access_path])
        else:
            nextlink_jsons.append(js)
        while nextlink_url := js.get("nextLink"):
            response = self._make_request(nextlink_url, {}, {})
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

    def _make_request(self, url: str, params: MutableMapping[str, Any], headers: MutableMapping[str, Any]) -> Any:
        # Construct and send request
        request = HttpRequest(method="GET", url=url, params=params, headers=headers)
        pipeline_response: PipelineResponse = self.client._client._pipeline.run(request, stream=False)  # type: ignore
        response = pipeline_response.http_response

        return response

    def for_location(self, location: str) -> AzureClient:
        return AzureClient.create(self.credential, self.subscription_id, location)
