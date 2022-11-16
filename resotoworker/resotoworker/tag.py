from typing import Any, Dict, List, Type

from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.baseresources import BaseResource
from resotolib.config import Config
from resotolib.core.model_export import node_from_dict, node_to_dict
from resotolib.logger import log
from resotolib.types import Json


def core_tag_tasks_processor(plugin: Type[BaseCollectorPlugin], config: Config, task_data: Dict[str, Any]) -> Json:
    delete_tags: List[str] = task_data.get("delete", [])
    update_tags: Dict[str, str] = task_data.get("update", {})
    node_data: Dict[str, Any] = task_data.get("node", {})

    def delete(node: BaseResource, key: str) -> None:
        log.debug(f"Calling parent resource to delete tag {key} in cloud")
        if plugin.delete_tag(config, node, key):
            log_msg = f"Successfully deleted tag {key} in cloud"
            node.add_change("tags")
            node.log(log_msg)
            log.info(f"{log_msg} for {node.kind}:{node.id}")
            del node.tags[key]
        else:
            log_msg = f"Error deleting tag {key} in cloud"
            node.log(log_msg)
            raise AttributeError(f"{log_msg} for {node.kind}:{node.id}")

    def update(node: BaseResource, key: str, value: str) -> None:
        log.debug(f"Calling parent resource to set tag {key} to {value} in cloud")
        if plugin.update_tag(config, node, key, value):
            log_msg = f"Successfully set tag {key} to {value} in cloud"
            node.add_change("tags")
            node.log(log_msg)
            log.info(f"{log_msg} for {node.kind}:{node.id}")
            node.tags[key] = value
        else:
            log_msg = f"Error setting tag {key} to {value} in cloud"
            node.log(log_msg)
            raise AttributeError(f"{log_msg} for {node.kind}:{node.id}")

    nd = node_from_dict(node_data, include_select_ancestors=True)
    for delete_tag in delete_tags:
        delete(nd, delete_tag)

    for k, v in update_tags.items():
        update(nd, k, v)

    return node_to_dict(nd)
