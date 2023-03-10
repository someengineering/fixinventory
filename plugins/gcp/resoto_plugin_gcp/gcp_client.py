from typing import Optional, List, Dict, Any, Set

from attr import define
from google.auth.credentials import Credentials
from googleapiclient import discovery

from resoto_plugin_gcp.utils import MemoryCache
from resotolib.core.actions import CoreFeedback
from resotolib.json import value_in_path
from resotolib.types import Json

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

    def get(self, api_spec: GcpApiSpec, **kwargs: Any) -> Json:
        client = _discovery_function(
            api_spec.service, api_spec.version, credentials=self.credentials, cache=MemoryCache()
        )
        executor = client
        for accessor in api_spec.accessors:
            executor = getattr(executor, accessor)()
        params_map = {**{"project": self.project_id, "region": self.region}, **kwargs}
        params = {k: v.format_map(params_map) for k, v in api_spec.request_parameter.items()}
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
                for zone_marker, zone_response in page.items():
                    zone = zone_marker.split("/")[-1]
                    for item in value_in_path(zone_response, sub_path) or []:
                        # store the zone as part of the item
                        item[InternalZoneProp] = zone
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
