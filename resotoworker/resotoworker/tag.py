from typing import Any, Dict, List, Type

from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.baseresources import BaseResource
from resotolib.config import Config
from resotolib.core.model_export import node_from_dict, node_to_dict
from resotolib.core.tasks import CoreTaskResult
from resotolib.logger import log


def core_tag_tasks_processor(
    plugin: Type[BaseCollectorPlugin], config: Config, message: Dict[str, Any]
) -> CoreTaskResult:
    task_id = message.get("task_id")
    task_data: Dict[str, Any] = message.get("data", {})
    delete_tags: List[str] = task_data.get("delete", [])
    update_tags: Dict[str, str] = task_data.get("update", {})
    node_data: Dict[str, Any] = task_data.get("node", {})

    def delete(node: BaseResource, key: str) -> CoreTaskResult:
        log.debug(f"Calling parent resource to delete tag {key} in cloud")
        try:
            if plugin.delete_tag(config, node, key):
                log_msg = f"Successfully deleted tag {key} in cloud"
                node.add_change("tags")
                node.log(log_msg)
                log.info((f"{log_msg} for {node.kind}" f" {node.id}"))
                del node.tags[key]
                return CoreTaskResult(task_id=task_id, data=node_to_dict(node))
            else:
                log_msg = f"Error deleting tag {key} in cloud"
                node.log(log_msg)
                log.error((f"{log_msg} for {node.kind}" f" {node.id}"))
                return CoreTaskResult(task_id=task_id, error=log_msg)
        except Exception as e:
            log_msg = f"Unhandled exception while trying to delete tag {key} in cloud:" f" {type(e)} {e}"
            node.log(log_msg, exception=e)
            if node._raise_tags_exceptions:
                raise
            else:
                log.exception(log_msg)
                return CoreTaskResult(task_id=task_id, error=log_msg)

    def update(node: BaseResource, key: str, value: str) -> CoreTaskResult:
        log.debug(f"Calling parent resource to set tag {key} to {value} in cloud")
        try:
            if plugin.update_tag(config, node, key, value):
                log_msg = f"Successfully set tag {key} to {value} in cloud"
                node.add_change("tags")
                node.log(log_msg)
                log.info((f"{log_msg} for {node.kind}" f" {node.id}"))
                node.tags[key] = value
                return CoreTaskResult(task_id=task_id, data=node_to_dict(node))
            else:
                log_msg = f"Error setting tag {key} to {value} in cloud"
                node.log(log_msg)
                log.error((f"{log_msg} for {node.kind}" f" {node.id}"))
                return CoreTaskResult(task_id=task_id, error=log_msg)
        except Exception as e:
            log_msg = f"Unhandled exception while trying to set tag {key} to {value}" f" in cloud: {type(e)} {e}"
            node.log(log_msg, exception=e)
            if node._raise_tags_exceptions:
                raise
            else:
                log.exception(log_msg)
                return CoreTaskResult(task_id=task_id, error=log_msg)

    try:
        nd = node_from_dict(node_data, include_select_ancestors=True)
        for delete_tag in delete_tags:
            return delete(nd, delete_tag)

        for k, v in update_tags.items():
            return update(nd, k, v)

    except Exception as e:
        log.exception("Error while updating tags")
        return CoreTaskResult(task_id, error=str(e))
