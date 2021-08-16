import cloudkeeper.logging
from cloudkeeper.graph import Graph
from pprint import pformat
from kubernetes import client
from typing import ClassVar, Iterable, Dict, Union, Callable, Any, List, Optional
from dataclasses import dataclass, field

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


@dataclass(eq=False)
class KubernetesResource:
    resource_type: ClassVar[str] = "kubernetes_resource"
    api: ClassVar[object] = NotImplemented
    list_method: ClassVar[str] = NotImplemented
    attr_map: ClassVar[Dict] = {}
    search_map: ClassVar[Dict] = {
        "_owner": [
            "id",
            (
                lambda r: [o.uid for o in r.metadata.owner_references]
                if r.metadata.owner_references is not None
                else []
            ),
        ]
    }
    predecessor_names: ClassVar[List[str]] = ["_owner"]
    successor_names: ClassVar[List[str]] = []

    self_link: Optional[str] = None
    _api_response: Optional[str] = field(repr=False, default=None)

    def delete(self, graph: Graph) -> bool:
        return NotImplemented

    def update_tag(self, key, value) -> bool:
        return NotImplemented

    def delete_tag(self, key) -> bool:
        return NotImplemented

    @classmethod
    def list(cls, api_client: client.ApiClient) -> Iterable:
        f = getattr(cls.api(api_client), cls.list_method, None)
        if callable(f):
            return f(watch=False).items
        else:
            return ()

    @classmethod
    def collect(cls, api_client: client.ApiClient, graph: Graph):
        for response in cls.list(api_client):
            kwargs, search_results = default_attributes(
                response, cls.attr_map, cls.search_map, graph
            )
            parent = graph.root
            namespace = response.metadata.namespace
            resource = cls(**kwargs)
            if namespace:
                ns = graph.search_first_all(
                    {"resource_type": "kubernetes_namespace", "name": namespace}
                )
                if ns:
                    parent = ns
            log.debug(f"Collected {resource.rtdname} in {parent.rtdname}")
            graph.add_resource(parent, resource)

            parent_map = {True: cls.predecessor_names, False: cls.successor_names}

            for is_parent, sr_names in parent_map.items():
                for sr_name in sr_names:
                    if sr_name in search_results:
                        srs = search_results[sr_name]
                        for sr in srs:
                            if is_parent:
                                src = sr
                                dst = resource
                            else:
                                src = resource
                                dst = sr
                            graph.add_edge(src, dst)
                    else:
                        if sr_name in cls.search_map:
                            graph_search = cls.search_map[sr_name]
                            attr = graph_search[0]
                            value_name = graph_search[1]
                            value = get_response_data(response, value_name)
                            if value:
                                if isinstance(value, list):
                                    values = value
                                    for value in values:
                                        resource.add_deferred_connection(
                                            attr, value, is_parent
                                        )
                                elif isinstance(value, str):
                                    resource.add_deferred_connection(
                                        attr, value, is_parent
                                    )
                                else:
                                    log.error(
                                        (
                                            "Unable to add deferred connection for"
                                            f" value {value} of type {type(value)}"
                                        )
                                    )
                        else:
                            log.error(f"Key {sr_name} is missing in search_map")
            post_process = getattr(cls, "post_process", None)
            if callable(post_process):
                post_process(resource, graph)


def default_attributes(
    response, attr_map: Dict, search_map: Dict, graph: Graph
) -> Dict:
    kwargs = {
        "id": response.metadata.uid,
        "name": response.metadata.name,
        "ctime": response.metadata.creation_timestamp,
        "self_link": response.metadata.self_link,
        "tags": response.metadata.labels if response.metadata.labels else {},
        "_api_response": pformat(response),
    }
    search_results = {}
    for map_to, map_from in attr_map.items():
        data = get_response_data(response, map_from)
        if data is None:
            log.debug(f"Unable to set {map_to}, attribute {map_from} not in result")
            continue
        kwargs[map_to] = data

    for map_to, search_data in search_map.items():
        search_attr = search_data[0]
        search_value_name = search_data[1]
        search_value = get_response_data(response, search_value_name)
        if search_value is None:
            continue
        if isinstance(search_value, list):
            search_values = search_value
        else:
            search_values = [search_value]
        for search_value in search_values:
            search_result = graph.search_first(search_attr, search_value)
            if search_result:
                if map_to not in search_results:
                    search_results[map_to] = []
                search_results[map_to].append(search_result)
        if (
            map_to not in kwargs
            and map_to in search_results
            and not str(map_to).startswith("_")
        ):
            search_result = search_results[map_to]
            if len(search_result) == 1:
                kwargs[map_to] = search_result[0]
            else:
                kwargs[map_to] = list(search_result)

    return kwargs, search_results


def get_response_data(response, value: Union[str, Callable]) -> Any:
    """Returns data from a Kubernetes API response.

    Args:
        result: Dict containing the result or a GCP API execute() call.
        value: Either directly the name of a key found in result or
            a callable like a lambda that finds the relevant data withing
            result.
    """
    data = None
    if callable(value):
        try:
            data = value(response)
        except Exception:
            log.exception(f"Exception while trying to fetch data calling {value}")
    elif value in response:
        data = response[value]
    return data
