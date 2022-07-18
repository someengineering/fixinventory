from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.baseresources import BaseResource
from resotolib.config import Config
from resotolib.logger import log
from resotolib.core.model_export import node_from_dict, node_to_dict
from resotolib.types import Json
from typing import Any, Dict, List, Type


def core_tag_tasks_processor(
    plugins: Dict[str, Type[BaseCollectorPlugin]], config: Config, message: Dict[str, Any]
) -> Json:
    task_id = message.get("task_id")
    # task_name = message.get("task_name")
    # task_attrs = message.get("attrs", {})
    task_data: Dict[str, Any] = message.get("data", {})
    delete_tags: List[str] = task_data.get("delete", [])
    update_tags: Dict[str, str] = task_data.get("update", {})
    node_data: Dict[str, Any] = task_data.get("node", {})
    result = "done"
    extra_data: Dict[str, Any] = {}

    def delete(plugin: Type[BaseCollectorPlugin], node: BaseResource, key: str) -> None:
        log.debug(f"Calling parent resource to delete tag {key} in cloud")
        try:
            if plugin.delete_tag(config, node, key):
                log_msg = f"Successfully deleted tag {key} in cloud"
                node.add_change("tags")
                node.log(log_msg)
                log.info((f"{log_msg} for {node.kind}" f" {node.id}"))
                del node.tags[key]
            else:
                log_msg = f"Error deleting tag {key} in cloud"
                node.log(log_msg)
                log.error((f"{log_msg} for {node.kind}" f" {node.id}"))
        except Exception as e:
            log_msg = f"Unhandled exception while trying to delete tag {key} in cloud:" f" {type(e)} {e}"
            node.log(log_msg, exception=e)
            if node._raise_tags_exceptions:
                raise
            else:
                log.exception(log_msg)

    def update(plugin: Type[BaseCollectorPlugin], node: BaseResource, key: str, value: str) -> None:
        log.debug(f"Calling parent resource to set tag {key} to {value} in cloud")
        try:
            if plugin.update_tag(config, node, key, value):
                log_msg = f"Successfully set tag {key} to {value} in cloud"
                node.add_change("tags")
                node.log(log_msg)
                log.info((f"{log_msg} for {node.kind}" f" {node.id}"))
                node.tags[key] = value
            else:
                log_msg = f"Error setting tag {key} to {value} in cloud"
                node.log(log_msg)
                log.error((f"{log_msg} for {node.kind}" f" {node.id}"))
        except Exception as e:
            log_msg = f"Unhandled exception while trying to set tag {key} to {value}" f" in cloud: {type(e)} {e}"
            node.log(log_msg, exception=e)
            if node._raise_tags_exceptions:
                raise
            else:
                log.exception(log_msg)

    try:
        node = node_from_dict(node_data, include_select_ancestors=True)
        plugin = plugins.get(node.cloud().id)
        if plugin is None:
            raise ValueError(f"No plugin found for cloud {node.cloud().id}")
        for delete_tag in delete_tags:
            delete(plugin, node, delete_tag)

        for k, v in update_tags.items():
            update(plugin, node, k, v)

        node_dict = node_to_dict(node)
        extra_data.update({"data": node_dict})
    except Exception as e:
        log.exception("Error while updating tags")
        result = "error"
        extra_data["error"] = str(e)

    reply_message = {
        "task_id": task_id,
        "result": result,
    }
    reply_message.update(extra_data)
    return reply_message
