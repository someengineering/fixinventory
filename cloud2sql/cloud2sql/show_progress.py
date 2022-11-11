import shutil
from typing import Optional, Dict, Any, List

from resotolib.core.progress import ProgressTree, Progress
from resotolib.types import Json
from rich.console import Group
from rich.markdown import Markdown
from rich.text import Text
from rich.tree import Tree as RichTree


class CollectInfo:
    def __init__(self) -> None:
        self.progress = ProgressTree("Progress")
        self.messages: List[Json] = []
        self.info_count: int = 0
        self.error_count: int = 0

    def handle_message(self, message: Json) -> Json:
        if message["kind"] == "action_progress":
            self.progress.add_progress(Progress.from_json(message["data"]["progress"]))
        else:
            if message["data"]["level"] == "info":
                self.info_count += 1
            else:
                self.error_count += 1
            self.messages.append(message)
        return message

    def render(self, max_height: Optional[int] = None) -> Any:
        max_height = max_height or shutil.get_terminal_size(fallback=(80, 25))[1]
        res = progress_to_table(self.progress, max_height)
        if self.messages:
            res = Group(Markdown(f"- {self.error_count} errors\n- {self.info_count} warnings"), res)
        return res

    def rendered_messages(self) -> List[Any]:
        def markup(m: Json) -> Text:
            level = "[red]ERROR[/red]" if m["data"]["level"] == "error" else "[yellow]WARNING[/yellow]"
            return Text.from_markup(f"{level}: {m['data']['message']}")

        return [markup(m) for m in self.messages]


def progress_to_table(progress: ProgressTree, max_height: int) -> RichTree:
    remaining = max_height

    def render_progress(pg: Progress) -> Any:
        pi = pg.overall_progress()
        emoji = ":white_check_mark:" if pi.done else ":arrows_counterclockwise:"
        text = ("done" if pi.done else "in_progress") if pi.total == 1 else f"{pi.percentage}%"
        return Text.from_markup(f"{emoji} {pg.name} [dim]{text}[/dim]")

    def walk_node(nid: str, node: Dict[str, Any], rt: Optional[RichTree] = None) -> RichTree:
        nonlocal remaining
        if remaining < 1:
            return rt or RichTree(progress.name)
        dn = node[nid]
        data = dn["data"]
        node_content = render_progress(data) if data is not None else Text(nid)
        sub = RichTree(progress.name) if rt is None else rt.add(node_content)
        remaining -= 1

        for child in dn.get("children", []):
            for nid, _ in child.items():
                walk_node(nid, child, sub)
        return sub

    return walk_node(progress.sub_tree.root, progress.sub_tree.to_dict(with_data=True))
