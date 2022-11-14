import concurrent
import multiprocessing
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor, Future
from contextlib import suppress
from logging import getLogger
from queue import Queue
from threading import Event
from time import sleep
from typing import Dict, Optional, List

import pkg_resources
import yaml
from resotoclient import Kind, Model
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.baseresources import BaseResource
from resotolib.config import Config
from resotolib.core.actions import CoreFeedback
from resotolib.core.model_export import node_to_dict
from resotolib.json import from_json
from resotolib.proc import emergency_shutdown
from resotolib.types import Json
from rich import print as rich_print
from rich.live import Live
from sqlalchemy import Engine

from cloud2sql.show_progress import CollectInfo
from cloud2sql.sql import SqlModel, SqlUpdater

log = getLogger("cloud2sql")


def collectors(raw_config: Json, feedback: CoreFeedback) -> Dict[str, BaseCollectorPlugin]:
    result = {}
    config: Config = Config  # type ignore
    for entry_point in pkg_resources.iter_entry_points("resoto.plugins"):
        plugin_class = entry_point.load()
        if issubclass(plugin_class, BaseCollectorPlugin) and plugin_class.cloud in raw_config:
            log.info(f"Found collector {plugin_class.cloud} ({plugin_class.__name__})")
            plugin_class.add_config(config)
            plugin = plugin_class()
            if hasattr(plugin, "core_feedback"):
                setattr(plugin, "core_feedback", feedback.with_context(plugin.cloud))
            result[plugin_class.cloud] = plugin

    Config.init_default_config()
    Config.running_config.data = {**Config.running_config.data, **Config.read_config(raw_config)}
    return result


def configure(path_to_config: Optional[str]) -> Json:
    # Config.init_default_config()
    if path_to_config:
        with open(path_to_config) as f:
            # Config.running_config.data = {**Config.running_config.data, **Config.read_config(yaml.safe_load(f))}
            return yaml.safe_load(f)


def collect(collector: BaseCollectorPlugin, engine: Engine, feedback: CoreFeedback, args: Namespace) -> None:
    # collect cloud data
    feedback.progress_done(collector.cloud, 0, 1)
    collector.collect()
    # read the kinds created from this collector
    kinds = [from_json(m, Kind) for m in collector.graph.export_model(walk_subclasses=False)]
    model = SqlModel(Model({k.fqn: k for k in kinds}))
    node_edge_count = len(collector.graph.nodes) + len(collector.graph.edges)
    ne_current = 0
    progress_update = 5000
    feedback.progress_done("sync_db", 0, node_edge_count, context=[collector.cloud])
    with engine.connect() as conn:
        # create the ddl metadata from the kinds
        model.create_schema(conn, args)
        # ingest the data
        updater = SqlUpdater(model)
        node: BaseResource
        for node in collector.graph.nodes:
            node._graph = collector.graph
            exported = node_to_dict(node)
            exported["type"] = "node"
            exported["ancestors"] = {
                "cloud": {"reported": {"id": node.cloud().name}},
                "account": {"reported": {"id": node.account().name}},
                "region": {"reported": {"id": node.region().name}},
                "zone": {"reported": {"id": node.zone().name}},
            }
            stmt = updater.insert_node(exported)
            if stmt is not None:
                conn.execute(stmt)
            ne_current += 1
            if ne_current % progress_update == 0:
                feedback.progress_done("sync_db", ne_current, node_edge_count, context=[collector.cloud])
        for edge in collector.graph.edges:
            from_node = edge[0]
            to_node = edge[1]
            stmt = updater.insert_node({"from": from_node, "to": to_node, "type": "edge"})
            if stmt is not None:
                conn.execute(stmt)
            ne_current += 1
            if ne_current % progress_update == 0:
                feedback.progress_done("sync_db", ne_current, node_edge_count, context=[collector.cloud])
        conn.commit()
    feedback.progress_done(collector.cloud, 1, 1)


def show_messages(core_messages: Queue[Json], end: Event) -> None:
    info = CollectInfo()
    while not end.is_set():
        with Live(info.render(), auto_refresh=False, transient=True) as live:
            with suppress(Exception):
                info.handle_message(core_messages.get(timeout=1))
                live.update(info.render())
    for message in info.rendered_messages():
        rich_print(message)


def collect_from_plugins(engine: Engine, args: Namespace) -> None:
    # the multiprocessing manager is used to share data between processes
    mp_manager = multiprocessing.Manager()
    core_messages: Queue[Json] = mp_manager.Queue()
    feedback = CoreFeedback("cloud2sql", "collect", "collect", core_messages)
    raw_config = configure(args.config)
    all_collectors = collectors(raw_config, feedback)
    end = Event()
    with ThreadPoolExecutor(max_workers=4) as executor:
        try:
            if args.show == "progress":
                executor.submit(show_messages, core_messages, end)
            futures: List[Future] = []
            for collector in all_collectors.values():
                futures.append(executor.submit(collect, collector, engine, feedback, args))
            for future in concurrent.futures.as_completed(futures):
                future.result()
        except Exception as e:
            # set end and wait for live to finish, otherwise the cursor is not reset
            end.set()
            sleep(1)
            print(f"Encountered Error. Giving up. {e}")
            emergency_shutdown()
        finally:
            end.set()
