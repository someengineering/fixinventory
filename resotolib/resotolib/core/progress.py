from __future__ import annotations

from abc import abstractmethod, ABC
from typing import List, Optional, Any, Dict, Callable

from attr import define, field, evolve
from treelib import Tree, Node

from resotolib.types import Json, JsonElement

_TreeRoot = "root"


@define
class ProgressInfo:
    current: int
    total: int

    @property
    def percentage(self) -> int:
        return int(self.current * 100 / self.total)

    @property
    def done(self) -> bool:
        return self.current == self.total


@define
class Progress(ABC):
    name: str
    path: List[str] = field(kw_only=True, factory=list)

    @abstractmethod
    def overall_progress(self) -> ProgressInfo:
        pass

    @abstractmethod
    def update_progress(self, progress: Progress) -> Progress:
        pass

    @abstractmethod
    def mark_done(self) -> Progress:
        pass

    @property
    def percentage(self) -> int:
        return self.overall_progress().percentage

    @staticmethod
    def from_progresses(name: str, progresses: List[Progress]) -> ProgressTree:
        updated = ProgressTree(name)
        for p in progresses:
            updated.add_progress(p)
        return updated

    def to_json(self, key: Optional[Callable[[Progress], Any]] = None) -> Json:
        p = {"path": self.path} if self.path else {}
        if isinstance(self, ProgressDone):
            return {
                "kind": "progress",
                "name": self.name,
                **p,
                "current": self.current,
                "total": self.total,
            }
        elif isinstance(self, ProgressTree):
            node_iter = (part.data for part in self.sub_tree.all_nodes_itr() if part.data is not None)
            nodes: List[Progress] = sorted(node_iter, key=key) if key else list(node_iter)  # type: ignore
            return {"kind": "tree", "name": self.name, **p, "parts": [part.to_json() for part in nodes]}
        else:
            raise AttributeError("No handler to marshal progress")

    def info_json(self) -> JsonElement:
        if isinstance(self, ProgressDone):
            if self.total == self.current:
                return "done"
            elif self.current == 0:
                return "in progress"
            else:
                return f"{self.percentage}%"
        elif isinstance(self, ProgressTree):
            cloned = Tree(self.sub_tree.subtree(self.sub_tree.root), deep=True)

            def level_info(nd: Node) -> Json:
                if dt := nd.data:
                    return dt.info_json()
                else:
                    return {child.tag: level_info(child) for child in cloned.children(nd.identifier)}

            return {self.name: level_info(cloned.get_node(cloned.root))}
        else:
            raise AttributeError("No handler to marshal progress")

    @staticmethod
    def from_json(json: Json) -> Progress:
        name = json["name"]
        path = json.get("path", [])
        if json["kind"] == "progress":
            return ProgressDone(name, json["current"], json["total"], path=path)
        elif json["kind"] == "tree":
            tree = ProgressTree(name, path=path)
            for part in json["parts"]:
                tree.add_progress(Progress.from_json(part))
            return tree
        else:
            raise AttributeError("No handler to unmarshal progress")


@define
class ProgressDone(Progress):
    current: int
    total: int

    def __attrs_post_init__(self):
        if self.total <= 0:
            raise ValueError("total must be greater than 0")
        if self.current > self.total:
            raise ValueError(f"current ({self.current}) > total ({self.total})")

    def __str__(self) -> str:
        return f"{self.current}/{self.total}"

    def overall_progress(self) -> ProgressInfo:
        return ProgressInfo(self.current, self.total)

    def update_progress(self, progress: Progress) -> Progress:
        return Progress.from_progresses(_TreeRoot, [self, progress])

    def mark_done(self) -> Progress:
        return evolve(self, current=self.total)


@define(eq=False)
class ProgressTree(Progress):
    sub_tree: Tree = field(factory=Tree)

    def __attrs_post_init__(self) -> None:
        if not self.sub_tree.root:
            self.sub_tree.create_node(_TreeRoot, _TreeRoot)

    def __eq__(self, other: Any) -> bool:
        def data_nodes(tree: Tree) -> Dict[str, Progress]:
            return {nid: node.data for nid, node in tree.nodes.items() if node.data is not None}

        if isinstance(other, ProgressTree):
            return data_nodes(self.sub_tree) == data_nodes(other.sub_tree)
        else:
            return False

    def sub_progress(self, nid: str) -> Optional[Progress]:
        nid = nid if nid.startswith(_TreeRoot) else _TreeRoot + "." + nid
        node = self.sub_tree.get_node(nid)
        if node is None:
            return None
        elif node.data is not None:
            return node.data
        else:
            return evolve(self, sub_tree=Tree(self.sub_tree.subtree(nid), deep=True))

    def has_path(self, nid: str) -> bool:
        nid = nid if nid.startswith(_TreeRoot) else _TreeRoot + "." + nid
        return nid in self.sub_tree

    def by_path(self, nid: str) -> Optional[Progress]:
        nid = nid if nid.startswith(_TreeRoot) else _TreeRoot + "." + nid
        node = self.sub_tree.get_node(nid)
        return node.data if node and node.data else None

    def overall_progress(self) -> ProgressInfo:
        def sub_progress_info(nid: str) -> ProgressInfo:
            node = self.sub_tree.get_node(nid)
            # either the node is a data node or a tree node with children
            if node.data is not None:
                return node.data.overall_progress()
            else:
                parts = [sub_progress_info(child.identifier) for child in self.sub_tree.children(nid)]
                total_max = max(parts, key=lambda x: x.total).total if parts else 1
                current = 0
                total = 0
                for info in parts:
                    current += int(info.current * total_max / max(1, info.total))
                    total += total_max
                return ProgressInfo(current, total)

        return sub_progress_info(self.sub_tree.root)

    def mark_done(self) -> Progress:
        cloned = evolve(self, sub_tree=Tree(self.sub_tree.subtree(self.sub_tree.root), deep=True))
        for node in cloned.sub_tree.all_nodes():
            if node.data is not None:
                node.data = node.data.mark_done()
        return cloned

    def update_progress(self, progress: Progress) -> Progress:
        cloned = evolve(self, sub_tree=Tree(self.sub_tree.subtree(self.sub_tree.root), deep=True))
        cloned.add_progress(progress)
        return cloned

    def add_progress(self, progress: Progress) -> None:
        last = self.sub_tree.root
        last_path = last
        path = last
        for part in progress.path:
            path += "." + part
            if path not in self.sub_tree:  # if the path does not exist, create it
                self.sub_tree.create_node(part, path, parent=last_path)
            elif self.sub_tree[path].data is not None:  # if the path contains a value: remove it
                self.sub_tree[path].data = None
            last_path = path
        nid = path + "." + progress.name
        if nid in self.sub_tree and nid != self.sub_tree.root:
            self.sub_tree.remove_node(nid)
        self.sub_tree.create_node(progress.name, nid, parent=last_path, data=progress)

    def copy(self) -> ProgressTree:
        return evolve(self, sub_tree=Tree(self.sub_tree.subtree(self.sub_tree.root), deep=True))
