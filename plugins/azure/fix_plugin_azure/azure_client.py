from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from datetime import timedelta
from functools import lru_cache
from typing import List, Optional, Any, Union, Dict, cast
from urllib.parse import urlparse

import requests
from attr import define, field
from azure.core.exceptions import (
    ClientAuthenticationError,
    ResourceNotFoundError,
    map_error,
    HttpResponseError,
)
from azure.core.rest import HttpRequest, HttpResponse
from azure.core.rest._requests_basic import RestRequestsTransportResponse
from azure.core.utils import case_insensitive_dict
from azure.mgmt.core.exceptions import ARMErrorFormat
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.resources._serialization import Serializer
from azure.mgmt.resource.resources.models import GenericResource
from retrying import retry

from fix_plugin_azure.config import AzureConfig, AzureCredentials
from fixlib.core.actions import CoreFeedback, ErrorAccumulator
from fixlib.types import Json, JsonElement

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
        status_code = getattr(e, "status_code", None)

        if error_code == "TooManyRequests" or status_code == 429:
            log.debug(f"Azure API request limit exceeded or throttling, retrying with exponential backoff: {e}")
            return True

    return False


NextPageProps = ["nextLink", "NextPageLink", "@odata.nextLink"]
ErrorMap = {
    401: ClientAuthenticationError,
    404: ResourceNotFoundError,
}


@define
class AzureResourceSpec:
    service: str
    path: str
    version: str
    path_parameters: List[str] = []
    query_parameters: List[str] = []
    access_path: Optional[str] = None
    expect_array: bool = False
    expected_error_codes: Dict[str, Optional[str]] = field(factory=dict)
    """
    A dictionary that maps specific error codes (str) to corresponding hints (Optional[str]) to provide additional context or troubleshooting information when an error occurs.
    """

    def request(self, client: "MicrosoftResourceManagementClient", **kwargs: Any) -> HttpRequest:
        ser = Serializer()
        # Construct lookup map used to fill query and path parameters
        lookup_map = {"subscriptionId": client.subscription_id, "location": client.location, **kwargs}

        # Construct the path map
        path_map = case_insensitive_dict()
        for param in self.path_parameters:
            if lookup_map.get(param, None) is not None:
                path_map[param] = lookup_map[param]
            else:
                raise KeyError(
                    f"{self.service}:{self.path}: Path parameter {param} was not provided as argument. {lookup_map}"
                )

        # Construct parameters
        params = case_insensitive_dict()
        params["api-version"] = ser.query("api-version", self.version, "str")  # type: ignore
        for param in self.query_parameters:
            if param not in params:
                if lookup_map.get(param, None) is not None:
                    params[param] = ser.query(param, lookup_map[param], "str")  # type: ignore # noqa: E501
                else:
                    raise KeyError(f"Query parameter {param} was not provided as argument")

        # Construct url
        path = self.path.format_map(path_map)
        url = client.resource_management_client._client.format_url(path)  # pylint: disable=protected-access
        return HttpRequest(method="GET", url=url, params=params)

    def response(self, client: "MicrosoftResourceManagementClient", request: HttpRequest) -> HttpResponse:
        pipeline_response = client.resource_management_client._client._pipeline.run(request, stream=False)
        return cast(HttpResponse, pipeline_response.http_response)

    @property
    def action(self) -> str:
        return self.path


@define
class RestApiSpec:
    service: str
    url: str
    scope: str = ""  # if not provided, will be inferred from the URL: <scheme>://<netloc>/.default
    headers: Optional[Dict[str, str]] = None
    parameters: Optional[Dict[str, str]] = None
    access_path: Optional[str] = None
    expect_array: bool = False
    expected_error_codes: Dict[str, Optional[str]] = field(factory=dict)
    """
    A dictionary that maps specific error codes (str) to corresponding hints (Optional[str]) to provide additional context or troubleshooting information when an error occurs.
    """

    def __attrs_post_init__(self) -> None:
        if self.scope == "":
            ps = urlparse(self.url)
            self.scope = f"{ps.scheme}://{ps.netloc}/.default"

    def request(self, _: "MicrosoftResourceManagementClient", **__: Any) -> HttpRequest:
        return HttpRequest(method="GET", url=self.url, params=self.parameters, headers=self.headers)

    def response(self, client: "MicrosoftResourceManagementClient", request: HttpRequest) -> HttpResponse:
        tkn = client.token_cache.token(self.scope)
        # parameters already encoded into the URL
        request.headers.update({"Authorization": f"Bearer {tkn}"})
        response = requests.get(request.url, headers=request.headers, timeout=120)
        result = RestRequestsTransportResponse(internal_response=response, request=request)  # type: ignore
        result.read()  # explicit read required
        return result

    @property
    def action(self) -> str:
        return self.url


MicrosoftRestSpec = Union[AzureResourceSpec, RestApiSpec]


class CredentialsTokenCache:
    def __init__(self, credentials: AzureCredentials, ttl: timedelta = timedelta(minutes=30)) -> None:
        self.credentials = credentials
        self.ttl_seconds = ttl.total_seconds()

    @lru_cache(maxsize=128)
    def __token(self, scope: str, _: int) -> str:
        return self.credentials.get_token(scope).token

    def token(self, scope: str) -> str:
        return self.__token(scope, int(time.time() / self.ttl_seconds))


class MicrosoftClient(ABC):
    @abstractmethod
    def list(self, spec: MicrosoftRestSpec, **kwargs: Any) -> List[Json]:
        pass

    @abstractmethod
    def for_location(self, location: str) -> MicrosoftClient:
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
        config: AzureConfig,
        credential: AzureCredentials,
        subscription_id: str,
        location: Optional[str] = None,
        core_feedback: Optional[CoreFeedback] = None,
        error_accumulator: Optional[ErrorAccumulator] = None,
        token_cache: Optional[CredentialsTokenCache] = None,
    ) -> MicrosoftClient:
        return MicrosoftResourceManagementClient(
            config, credential, subscription_id, location, core_feedback, error_accumulator, token_cache
        )

    create = __create_management_client


class MicrosoftResourceManagementClient(MicrosoftClient):
    def __init__(
        self,
        config: AzureConfig,
        credential: AzureCredentials,
        subscription_id: str,
        location: Optional[str] = None,
        core_feedback: Optional[CoreFeedback] = None,
        accumulator: Optional[ErrorAccumulator] = None,
        token_cache: Optional[CredentialsTokenCache] = None,
    ) -> None:
        self.config = config
        self.credential = credential
        self.subscription_id = subscription_id
        self.location = location
        self.core_feedback = core_feedback
        self.token_cache = token_cache or CredentialsTokenCache(credential)
        self.accumulator = accumulator or ErrorAccumulator()
        self.resource_management_client = ResourceManagementClient(self.credential, self.subscription_id)

    def list(self, spec: MicrosoftRestSpec, **kwargs: Any) -> List[Json]:
        result = self._list_with_retry(spec, **kwargs)
        if result is None:
            return []
        return result  # type: ignore

    def delete(self, resource_id: str) -> bool:
        try:
            self.resource_management_client.resources.begin_delete_by_id(
                resource_id=resource_id, api_version="2021-04-01"
            )
        except HttpResponseError as e:
            if error := e.error:
                error_code = error.code or "Unknown"
                if error_code == "ResourceNotFoundError":
                    return False  # Resource not found to delete
                else:
                    msg = f"An Azure API error occurred during the deletion of a resource: {e}"
                    self.accumulator.add_error(False, error_code, "Resource deletion", "service_resource", msg)
                    if self.config.discard_account_on_resource_error:
                        raise
                    return False

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
            resource = self.resource_management_client.resources.get_by_id(
                resource_id=resource_id, api_version="2021-04-01"
            )

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
            self.resource_management_client.resources.begin_create_or_update_by_id(
                resource_id, "2021-04-01", updated_resource
            )

        except HttpResponseError as e:
            if error := e.error:
                error_code = error.code or "Unknown"
                if error_code == "ResourceNotFoundError":
                    return False  # Resource not found
                elif error_code == "ResourceExistsError":
                    return False  # Tag for update/delete does not exist
                else:
                    msg = f"An Azure API error occurred during the updating or deletion tag of a resource: {e}"
                    self.accumulator.add_error(
                        False, error_code, "Resource updating or deletion", "service_resource", msg
                    )
                    if self.config.discard_account_on_resource_error:
                        raise
                    return False

        return True

    @retry(  # type: ignore
        stop_max_attempt_number=10,  # 10 attempts: 1000 max 60000: max wait time is 5 minutes
        wait_exponential_multiplier=1000,
        wait_exponential_max=60000,
        retry_on_exception=is_retryable_exception,
    )
    def _list_with_retry(self, spec: MicrosoftRestSpec, **kwargs: Any) -> Optional[List[Json]]:
        try:
            result = self._call(spec, **kwargs)
            if result is None:
                return None
            elif isinstance(result, list):
                return result
            else:
                return [result]  # type: ignore
        except ClientAuthenticationError as e:
            log.warning(f"[Azure] Invoke Azure CLI is failed!: {e}. Api spec: {spec}")
            if (error := e.error) and (error_code := error.code):
                msg = "Invoke Azure CLI is failed!"
                self.accumulator.add_error(False, error_code, spec.service, spec.action, msg, self.location)
            return None
        except HttpResponseError as e:
            if error := e.error:
                code = error.code or "Unknown"
                if error.code == "NoRegisteredProviderFound":
                    return None  # API not available in this region
                elif error.code in spec.expected_error_codes:
                    if hint := spec.expected_error_codes.get(code):
                        self.accumulator.add_error(False, code, spec.service, spec.action, str(hint))
                    return None
                elif error.code == "BadRequest" and spec.service == "metric":
                    raise MetricRequestError from e
                self.accumulator.add_error(False, code, spec.service, spec.action, str(e), self.location)
            log.warning(f"[Azure] Client Error: status={e.status_code}, error={e.error}, message={e}, spec={spec}")
            return None
        except Exception as e:
            log.warning(f"[Azure] called service={spec.service}: hit unexpected error: {e}, spec={spec}", exc_info=e)
            if self.config.discard_account_on_resource_error:
                raise
            return None

    # noinspection PyProtectedMember
    def _call(self, spec: MicrosoftRestSpec, **kwargs: Any) -> JsonElement:
        # Walk all pages if necessary
        next_page_request: Optional[HttpRequest] = spec.request(self, **kwargs)
        result: Union[None, Json, List[Json]] = None
        while next_page_request:
            response = spec.response(self, next_page_request)
            # Handle error responses
            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=ErrorMap)
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)

            # Parse json content
            js: Union[Json, List[Json]] = response.json()

            # is there a next page?
            np_url = next((npp for np in NextPageProps if isinstance(js, dict) and (npp := js.get(np))), None)
            next_page_request = HttpRequest(next_page_request.method, np_url) if np_url else None

            # access the right path
            js = js[spec.access_path] if spec.access_path and isinstance(js, dict) else js

            # ensure it is an array if required
            if spec.expect_array and not isinstance(js, list):
                js = [js]

            # assign or append. this will throw in case the result is paginated but no list
            if result is None:
                result = js
            elif isinstance(result, list) and isinstance(js, list):
                result.extend(js)
            else:
                raise ValueError("Paginated result but ApiSpec does not expect array!")

        return result

    def for_location(self, location: str) -> MicrosoftClient:
        return MicrosoftClient.create(
            self.config,
            self.credential,
            self.subscription_id,
            location,
            self.core_feedback,
            self.accumulator,
            self.token_cache,
        )
