from typing import Iterable, List, Dict, Union
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
from functools import partial
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
        ArgumentParser.args.keepercore_uri = ArgumentParser.args.keepercore_uri.strip(
            "/"
        )

        graph: Graph = event.data
        log.info("Keepercore Event Handler called")
        model = get_model_from_graph(graph)
        from pprint import pformat

        log.debug(pformat(model))
        model_uri = f"{ArgumentParser.args.keepercore_uri}/model"
        graph_uri = f"{ArgumentParser.args.keepercore_uri}/graph/ck/reported/batch/sub_graph/root"
        r = requests.patch(model_uri, data=json.dumps(model))
        log.debug(r.content)
        h = {"Content-Type": "application/x-ndjson"}
        f = GraphIterator(graph)
        r = requests.post(graph_uri, data=f, headers=h)
        log.debug(r.content)

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--keepercore-uri",
            help="Keepercore URI",
            default=None,
            dest="keepercore_uri",
        )

    def shutdown(self, event: Event):
        log.debug(
            f"Received event {event.event_type} - shutting down keepercore plugin"
        )
        self.exit.set()


def get_model_from_graph(graph: Graph) -> List:
    model = []

    with graph.lock.read_access:
        for node in graph.nodes:
            node_models = get_models_from_node(node)
            for node_model in node_models:
                if not any(node_model.get("fqn") == d.get("fqn") for d in model):
                    model.append(node_model)
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
        int: "int64",
        float: "float",
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

    def __iter__(self):
        with self.graph.lock.read_access:
            for node in self.graph.nodes:
                node_attributes = get_node_attributes(node)
                node_id = node.sha256
                node_json = {"id": node_id, "data": node_attributes}
                attributes_json = json.dumps(node_json) + "\n"
                yield (attributes_json.encode())
                for predecessor in node.predecessors(self.graph):
                    predecessor_id = predecessor.sha256
                    link = {"from": predecessor_id, "to": node_id}
                    link_json = json.dumps(link) + "\n"
                    yield (link_json.encode())
