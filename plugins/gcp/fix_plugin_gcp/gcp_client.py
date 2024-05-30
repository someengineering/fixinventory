from __future__ import annotations

from typing import Optional, List, Dict, Any, Set, Tuple

from attr import define, evolve
from google.auth.credentials import Credentials
from googleapiclient import discovery

from fix_plugin_gcp.utils import MemoryCache
from fixlib.core.actions import CoreFeedback
from fixlib.json import value_in_path
from fixlib.types import Json

InternalZoneProp = "_zone"
RegionProp = "region"

# Store the discovery function as separate variable.
# This is used in tests to change the builder function.
_discovery_function = discovery.build


@define(eq=False, slots=False)
class GcpApiSpec:
    service: str
    version: str
    accessors: List[str]
    action: str
    request_parameter: Dict[str, str]
    request_parameter_in: Set[str]
    response_path: str
    response_regional_sub_path: Optional[str] = None
    set_label_identifier: str = "resource"
    get_identifier: Optional[str] = None
    delete_identifier: Optional[str] = None
    required_iam_permissions: Optional[List[str]] = None
    mutate_iam_permissions: Optional[List[str]] = None
    expected_errors: Optional[Set[str]] = None

    def for_delete(self) -> GcpApiSpec:
        params = self.request_parameter.copy()
        params[self._delete_identifier] = "{resource}"
        if self.is_zone_specific:
            params["zone"] = "{zone}"
        return evolve(
            self,
            action="delete",
            request_parameter=params,
            required_iam_permissions=self.mutate_iam_permissions,
        )

    def for_get(self) -> GcpApiSpec:
        params = self.request_parameter.copy()
        params[self._get_identifier] = "{resource}"
        if self.is_zone_specific:
            params["zone"] = "{zone}"
        # a) can not be derived and b) will be defined in mutate_iam_permissions if required
        return evolve(self, action="get", request_parameter=params, required_iam_permissions=[])

    def for_set_labels(self) -> GcpApiSpec:
        params = self.request_parameter.copy()
        params[self.set_label_identifier] = "{resource}"
        if self.is_zone_specific:
            params["zone"] = "{zone}"
        return evolve(
            self,
            action="setLabels",
            request_parameter=params,
            required_iam_permissions=self.mutate_iam_permissions,
        )

    @property
    def _get_identifier(self) -> str:
        return (
            self.get_identifier or self.accessors[-1][:-1]
        )  # Poor persons `singularize(), i.e. ["vpnTunnels"] -> "vpnTunnel"`

    @property
    def _delete_identifier(self) -> str:
        return self.delete_identifier or self._get_identifier

    @property
    def next_action(self) -> str:
        return self.action + "_next"

    @property
    def is_zone_specific(self) -> bool:
        return self.response_regional_sub_path is not None

    @property
    def is_project_level(self) -> bool:
        # api spec is on project level, if no other param than project is required
        return not (self.request_parameter_in - {"project"})

    @property
    def fqn(self) -> str:
        return f"{self.service}.{self.version}.{'.'.join(self.accessors)}.{self.action}"

    @property
    def iam_permissions(self) -> List[str]:
        # See https://cloud.google.com/iam/docs/permissions-reference for permission names
        # if permission name is defined, use it
        if self.required_iam_permissions is not None:
            return self.required_iam_permissions
        # derive the permission name from the api spec
        action = "list" if self.action == "aggregatedList" else self.action
        return [self.service + "." + ".".join(self.accessors) + "." + action]


class GcpClient:
    def __init__(
        self,
        credentials: Credentials,
        *,
        project_id: Optional[str] = None,
        region: Optional[str] = None,
        core_feedback: Optional[CoreFeedback] = None,
    ) -> None:
        self.credentials = credentials
        self.project_id = project_id
        self.region = region
        self.core_feedback = core_feedback

    def delete(self, api_spec: GcpApiSpec, **kwargs: Any) -> Json:
        return self.call_single(api_spec, None, **kwargs)

    def get(self, api_spec: GcpApiSpec, **kwargs: Any) -> Json:
        return self.call_single(api_spec, None, **kwargs)

    def set_labels(self, api_spec: GcpApiSpec, body: Dict[str, Any], **kwargs: Any) -> Json:
        return self.call_single(api_spec, body, **kwargs)

    def call_single(self, api_spec: GcpApiSpec, body: Optional[Any] = None, **kwargs: Any) -> Json:
        client = _discovery_function(
            api_spec.service, api_spec.version, credentials=self.credentials, cache=MemoryCache()
        )
        executor = client
        for accessor in api_spec.accessors:
            executor = getattr(executor, accessor)()
        params_map = {**{"project": self.project_id, "region": self.region}, **kwargs}
        params = {k: v.format_map(params_map) for k, v in api_spec.request_parameter.items()}
        if body:
            params.update({"body": body})
        request = getattr(executor, api_spec.action)(**params)
        result: Json = request.execute()
        return result

    def list(self, api_spec: GcpApiSpec, **kwargs: Any) -> List[Json]:
        # todo add caching
        client = _discovery_function(
            api_spec.service, api_spec.version, credentials=self.credentials, cache=MemoryCache()
        )
        executor = client
        for accessor in api_spec.accessors:
            executor = getattr(executor, accessor)()
        params_map = {**{"project": self.project_id, "region": self.region}, **kwargs}
        params = {k: v.format_map(params_map) for k, v in api_spec.request_parameter.items()}
        result: List[Json] = []

        def next_responses(request: Any) -> None:
            response = request.execute()
            page = value_in_path(response, api_spec.response_path)
            if (sub_path := api_spec.response_regional_sub_path) is not None and isinstance(page, dict):
                for zonal_marker, zonal_response in page.items():
                    zone_prop, zonal_name = self.__extract_zonal_prop(zonal_marker)
                    for item in value_in_path(zonal_response, sub_path) or []:
                        # store the zone as part of the item
                        item[zone_prop] = zonal_name
                        result.append(item)
            elif isinstance(page, list):
                result.extend(page)
            elif page is None:
                pass
            else:
                raise ValueError(f"Unexpected response type: {type(page)}")

            if hasattr(executor, api_spec.next_action) and (
                nxt_req := getattr(executor, api_spec.next_action)(previous_request=request, previous_response=response)
            ):
                return next_responses(nxt_req)

        next_responses(getattr(executor, api_spec.action)(**params))
        return result

    @staticmethod
    def __extract_zonal_prop(name: str) -> Tuple[str, str]:
        if name == "global":
            return RegionProp, name
        if "/" not in name:
            raise ValueError(f"Unexpected zonal name: {name}")
        zonal_kind, zonal_name = name.split("/", maxsplit=1)
        if zonal_kind == "regions":
            return RegionProp, zonal_name
        elif zonal_kind == "zones":
            return InternalZoneProp, zonal_name
        else:
            raise ValueError(f"Unexpected zonal kind: {zonal_kind}")
