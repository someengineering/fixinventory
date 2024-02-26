from typing import NewType

TaskDescriptorId = NewType("TaskDescriptorId", str)
SubscriberId = NewType("SubscriberId", str)
TaskId = NewType("TaskId", str)
WorkerId = NewType("WorkerId", str)
ConfigId = NewType("ConfigId", str)
NodeId = NewType("NodeId", str)
InfraAppName = NewType("InfraAppName", str)
GraphName = NewType("GraphName", str)
Email = NewType("Email", str)
Password = NewType("Password", str)


def valid_root_graph_name(graph_name: GraphName) -> bool:
    return ("_" not in graph_name) and (not graph_name.startswith("snapshot-"))
