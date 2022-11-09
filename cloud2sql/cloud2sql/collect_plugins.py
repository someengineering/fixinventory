import multiprocessing
from logging import getLogger
from queue import Queue
from typing import Dict, Optional

import pkg_resources
import yaml
from resotoclient import Kind, Model
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.config import Config
from resotolib.core.actions import CoreFeedback
from resotolib.core.model_export import node_to_dict
from resotolib.json import from_json
from resotolib.types import Json
from sqlalchemy import Engine

from cloud2sql.sql import SqlModel, SqlUpdater

log = getLogger("cloud2sql")


def collectors(feedback: CoreFeedback) -> Dict[str, BaseCollectorPlugin]:
    result = {}
    config: Config = Config  # type ignore
    for entry_point in pkg_resources.iter_entry_points("resoto.plugins"):
        plugin_class = entry_point.load()
        if issubclass(plugin_class, BaseCollectorPlugin):
            log.info(f"Found collector {plugin_class.cloud} ({plugin_class.__name__})")
            plugin_class.add_config(config)
            plugin = plugin_class()
            if hasattr(plugin, "core_feedback"):
                setattr(plugin, "core_feedback", feedback)
            result[plugin_class.cloud] = plugin
    return result


def configure(path_to_config: Optional[str]) -> None:
    if path_to_config:
        with open(path_to_config) as f:
            Config.running_config.data = Config.read_config(yaml.safe_load(f))
    else:
        Config.init_default_config()


def collect(collector: BaseCollectorPlugin, engine: Engine) -> None:
    # collect cloud data
    collector.collect()
    # read the kinds created from this collector
    kinds = [from_json(m, Kind) for m in collector.graph.export_model(walk_subclasses=False)]
    model = SqlModel(Model({k.fqn: k for k in kinds}))
    with engine.connect() as conn:
        # create the ddl metadata from the kinds
        metadata = model.create_schema()
        # create the tables
        metadata.create_all(conn)
        # ingest the data
        updater = SqlUpdater(model)
        for node in collector.graph.nodes:
            node._graph = collector.graph
            exported = node_to_dict(node)
            exported["type"] = "node"
            stmt = updater.insert_node(exported)
            if stmt is not None:
                conn.execute(stmt)
        for edge in collector.graph.edges:
            from_node = edge[0]
            to_node = edge[1]
            stmt = updater.insert_node({"from": from_node, "to": to_node, "type": "edge"})
            if stmt is not None:
                conn.execute(stmt)
        conn.commit()


def collect_from_plugins(engine: Engine) -> None:
    # the multiprocessing manager is used to share data between processes
    mp_manager = multiprocessing.Manager()
    core_messages: Queue[Json] = mp_manager.Queue()
    feedback = CoreFeedback("cloud2sql", "collect", "collect", core_messages)
    all_collectors = collectors(feedback)
    configure("/Users/matthias/config.yaml")  # get path via args
    for collector in all_collectors.values():
        collect(collector, engine)
