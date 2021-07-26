from typing import List, Dict, Union
from cloudkeeper.baseresources import BaseResource
import cloudkeeper.logging
import threading
from cloudkeeper.baseplugin import BasePlugin
from cloudkeeper.graph import Graph
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import (
    Event,
    EventType,
    add_event_listener,
    remove_event_listener,
)
from datetime import date, datetime, timezone, timedelta
import requests
import json

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class KeepercorePlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "keepercore"
        self.exit = threading.Event()
        add_event_listener(EventType.SHUTDOWN, self.shutdown)
        add_event_listener(
            EventType.COLLECT_FINISH, self.keepercore_event_handler, blocking=False
        )

    def __del__(self):
        remove_event_listener(EventType.COLLECT_FINISH, self.keepercore_event_handler)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        self.exit.wait()

    @staticmethod
    def keepercore_event_handler(event: Event):
        if not ArgumentParser.args.keepercore_uri:
            return

        graph: Graph = event.data
        log.info("Keepercore Event Handler called")
        model = get_model_from_graph(graph)
        base_uri = ArgumentParser.args.keepercore_uri.strip("/")
        keepercore_graph = ArgumentParser.args.keepercore_graph
        model_uri = f"{base_uri}/model"
        graph_uri = f"{base_uri}/graph/{keepercore_graph}"
        report_uri = f"{graph_uri}/reported/sub_graph/root"
        log.debug(f"Creating graph {keepercore_graph} via {graph_uri}")
        r = requests.post(graph_uri, data="", headers={"accept": "application/json"})
        if r.status_code != 200:
            log.error(r.content)
        log.debug(f"Updating model via {model_uri}")
        r = requests.patch(model_uri, data=json.dumps(model))
        if r.status_code != 200:
            log.error(r.content)
        graph_iterator = GraphIterator(graph)
        log.debug(f"Sending subgraph via {report_uri}")
        r = requests.put(report_uri, data=graph_iterator, headers={"Content-Type": "application/x-ndjson"})
        log.debug(r.content.decode())
        log.debug(f"Sent {graph_iterator.nodes_sent} nodes and {graph_iterator.edges_sent} edges to keepercore")

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--keepercore-uri",
            help="Keepercore URI",
            default=None,
            dest="keepercore_uri",
        )
        arg_parser.add_argument(
            "--keepercore-graph",
            help="Keepercore graph name",
            default="ck",
            dest="keepercore_graph",
        )

    def shutdown(self, event: Event):
        log.debug(
            f"Received event {event.event_type} - shutting down keepercore plugin"
        )
        self.exit.set()


def get_model_from_graph(graph: Graph) -> List:
    models = {}
    with graph.lock.read_access:
        for node in graph.nodes:
            node_models = get_models_from_node(node)
            for node_model in node_models:
                if not node_model.get("fqn") in models:
                    models[node_model.get("fqn")] = node_model
                else:
                    existing_properties = models[node_model.get("fqn")].get(
                        "properties", []
                    )
                    for new_property in node_model.get("properties", []):
                        if new_property not in existing_properties:
                            existing_properties.append(new_property)
    model = [m for m in models.values()]
    return model


def get_models_from_node(node: BaseResource) -> List:
    models = []
    model = {}
    resource_type = node.resource_type
    if resource_type == "graph_root":
        resource_type = "cloudkeeper_graph_root"
    if type(resource_type) is str:
        model["fqn"] = resource_type
    else:
        model["fqn"] = node.__class__
    model["properties"], attribute_models = get_node_attributes(node, get_model=True)
    models.append(model)
    models.extend(attribute_models)
    return models


resource_attributes_blacklist = [
    "metrics_description",
    "event_log",
    "uuid",
    "dname",
    "rtdname",
    "pricing_info",
]


def get_node_attributes(
    resource: BaseResource, get_model: bool = False
) -> Union[List, Dict]:
    attributes_list = []
    attributes_models = []
    attributes = dict(resource.__dict__)

    for attr_name in dir(resource):
        if attr_name.startswith("_"):
            continue
        attr_type = getattr(type(resource), attr_name, None)
        if isinstance(attr_type, property):
            try:
                attributes[attr_name] = getattr(resource, attr_name, None)
            except Exception:
                pass
    attributes["tags"] = dict(attributes.pop("_tags"))
    resource_type = resource.resource_type
    if resource_type == "graph_root":
        resource_type = "cloudkeeper_graph_root"
    attributes["kind"] = resource_type

    remove_keys = []
    add_keys = {}

    for key, value in attributes.items():
        if str(key).startswith("_") or str(key) in resource_attributes_blacklist:
            remove_keys.append(key)
        elif not isinstance(
            value,
            (
                str,
                int,
                float,
                complex,
                list,
                tuple,
                range,
                dict,
                set,
                frozenset,
                bool,
                bytes,
                bytearray,
                memoryview,
                date,
                datetime,
                timezone,
                timedelta,
            ),
        ):
            remove_keys.append(key)

    for key in remove_keys:
        attributes.pop(key)
    attributes.update(add_keys)

    for key, value in attributes.items():
        python_type = type(value)
        keepercore_type = python_type_to_keepercore(value)
        if keepercore_type is None:
            keepercore_type = str(python_type.__name__)
            attributes_models.append({"fqn": keepercore_type, "runtime_kind": "string"})
        required = False
        if key in ("kind", "id", "tags"):
            required = True
        entry = {
            "name": key,
            "kind": keepercore_type,
            "description": "",
            "required": required,
        }
        attributes_list.append(entry)

        if isinstance(value, (date, datetime, timedelta, timezone)):
            attributes[key] = str(value)

    if get_model:
        return attributes_list, attributes_models
    else:
        return attributes


def python_type_to_keepercore(value) -> str:
    value_type = type(value)
    value_value_type = None
    if value_type in (list, set, frozenset) and len(value) > 0:
        value_value_type = type(value[0])
    map = {
        str: "string",
        int: "float",
        float: "float",
        complex: "float",
        bool: "boolean",
        date: "date",
        datetime: "datetime",
        dict: "dictionary",
        list: "string[]",
        tuple: "string[]",
        set: "string[]",
        frozenset: "string[]",
    }
    if value_value_type is not None:
        map.update(
            {
                list: f"{map.get(value_value_type)}[]",
                tuple: f"{map.get(value_value_type)}[]",
                set: f"{map.get(value_value_type)}[]",
                frozenset: f"{map.get(value_value_type)}[]",
            }
        )
    return map.get(value_type)


class GraphIterator:
    def __init__(self, graph: Graph):
        self.graph = graph
        self.nodes_sent = 0
        self.edges_sent = 0

    def __iter__(self):
        with self.graph.lock.read_access:
            for node in self.graph.nodes:
                node_attributes = get_node_attributes(node)
                node_id = node.sha256
                node_json = {"id": node_id, "data": node_attributes}
                attributes_json = json.dumps(node_json) + "\n"
                self.nodes_sent += 1
                yield (attributes_json.encode())
            for node in self.graph.nodes:
                for successor in node.successors(self.graph):
                    successor_id = successor.sha256
                    link = {"from": node_id, "to": successor_id}
                    link_json = json.dumps(link) + "\n"
                    self.edges_sent += 1
                    yield (link_json.encode())
