from typing import Generator, List, Dict, Iterator, Sequence, Mapping, Union, Any, Optional
import json
from enum import Enum
import os
import requests
import zipfile
import argparse
from resotocore.util import (
    value_in_path,
    value_in_path_get,
    count_iterator,
)
from resotocore.model.resolve_in_graph import NodePath
from collections import defaultdict
import re
from dataclasses import dataclass

JsonElement = Union[str, int, float, bool, None, Mapping[str, Any], Sequence[Any]]

class ResourceKind(Enum):
    INSTANCE = 1
    VOLUME = 2
    IMAGE = 3
    FIREWALL = 4
    K8S_CLUSER = 5
    NETWORK = 6
    LOAD_BALANCER = 7


@dataclass
class ResourceDescription:
    uid: str
    name: str
    id: str
    kind: ResourceKind
    kind_name: str


do_kinds = {
    "droplet": ResourceKind.INSTANCE,
    "volume": ResourceKind.VOLUME,
    "image": ResourceKind.IMAGE,
    "firewall": ResourceKind.FIREWALL,
    "kubernetes_cluster": ResourceKind.K8S_CLUSER,
    "network": ResourceKind.NETWORK,
    "load_balancer": ResourceKind.LOAD_BALANCER,
}


def parse_kind(kind: str) -> Optional[ResourceKind]:
    cloud, rest = kind.split('_')[0], "_".join(kind.split('_')[1:])
    if cloud == 'digitalocean':
        return do_kinds.get(rest)
    else:
        return None

def generate_icon_map():
    icon_dir = "./Assets/Architecture-Service-Icons_01312022"
    compute = "Arch_Compute"
    storage = "Arch_Storage"
    security = "Arch_Security-Identity-Compliance"
    containers = "Arch_Containers"
    networking = "Arch_Networking-Content-Delivery"
    size = "16"
    prefix_amazon = "Arch_Amazon"
    prefix_aws = "Arch_AWS"
    prefix = "Arch"
    icon_map = {
        ResourceKind.INSTANCE: f"{icon_dir}/{compute}/{size}/{prefix_amazon}-EC2_{size}.svg",
        ResourceKind.VOLUME: f"{icon_dir}/{storage}/{size}/{prefix_amazon}-Elastic-Block-Store_{size}.svg",
        ResourceKind.IMAGE: f"{icon_dir}/{compute}/{size}/{prefix_amazon}-EC2_{size}.svg",
        ResourceKind.FIREWALL: f"{icon_dir}/{security}/{size}/{prefix_aws}-Network-Firewall_{size}.svg",
        ResourceKind.K8S_CLUSER: f"{icon_dir}/{containers}/{size}/{prefix_amazon}-Elastic-Kubernetes-Service_{size}.svg",
        ResourceKind.NETWORK: f"{icon_dir}/{networking}/{size}/{prefix_amazon}-Virtual-Private-Cloud_{size}.svg",
        ResourceKind.LOAD_BALANCER: f"{icon_dir}/{networking}/{size}/{prefix}_Elastic-Load-Balancing_{size}.svg",
    }
    return icon_map


def render_img_tag(src: Optional[str]) -> str:
    return f'<img src="{src}" />' if src else ""


def render_resource(resource: ResourceDescription, icon_map: Mapping[ResourceDescription, str], color: int) -> str:
    return f""""{resource.uid}" [shape=plain, label=<<TABLE STYLE="ROUNDED" COLOR="{color}" BORDER="1" CELLBORDER="1" CELLPADDING="5">
    <TR>
        <TD SIDES="B">
        <TABLE CELLPADDING="1" BORDER="0" CELLSPACING="0">
        <TR>
            <TD ALIGN="right">{render_img_tag(icon_map.get(resource.kind))}</TD>
            <TD ALIGN="left">{resource.kind_name}</TD>
        </TR>
        </TABLE>
        </TD>
    </TR>
    <TR>
        <TD SIDES="B">{resource.id}</TD>
    </TR>
    <TR>
        <TD BORDER="0">{resource.name}</TD>
    </TR>
</TABLE>>];"""


def render_dot_header(node: str, edge: str) -> str:
    return f"""digraph {{
rankdir=LR
overlap=false
splines=true
{node}
{edge}"""


def render_dot(gen: Iterator[JsonElement]) -> Generator[str, None, None]:
    # We use the paired12 color scheme: https://graphviz.org/doc/info/colors.html with color names as 1-12
    cit = count_iterator()
    icon_map = generate_icon_map()
    colors: Dict[str, int] = defaultdict(lambda: (next(cit) % 12) + 1)
    node = "node [shape=plain colorscheme=paired12]"
    edge = "edge [arrowsize=0.5]"
    yield render_dot_header(node, edge) 
    in_account: Dict[str, List[str]] = defaultdict(list)
    for item in gen:
        if isinstance(item, dict):
            type_name = item.get("type")
            if type_name == "node":
                uid = value_in_path(item, NodePath.node_id)
                if uid:
                    name = value_in_path_get(item, NodePath.reported_name, "n/a")
                    kind = value_in_path_get(item, NodePath.reported_kind, "n/a")
                    account = value_in_path_get(item, NodePath.ancestor_account_name, "graph_root")
                    id = value_in_path_get(item, NodePath.reported_id, "graph_root")
                    paired12 = colors[kind]
                    in_account[account].append(uid)
                    resource = ResourceDescription(uid, name, id, parse_kind(kind), kind)
                    yield render_resource(resource, icon_map, paired12)
            elif type_name == "edge":
                from_node = value_in_path(item, NodePath.from_node)
                to_node = value_in_path(item, NodePath.to_node)
                edge_type = value_in_path(item, NodePath.edge_type)
                if from_node and to_node:
                    yield f' "{from_node}" -> "{to_node}" '
        else:
            raise AttributeError(f"Expect json object but got: {type(item)}: {item}")
    # All elements in the same account are rendered as dedicated subgraph
    for account, uids in in_account.items():
        yield f' subgraph "{account}" {{'
        for uid in uids:
            yield f'    "{uid}"'
        yield " }"

    yield "}"

def ensure_assets():

    if not os.path.exists("Assets"):
        print("AWS icon assets missing. Downloading assets...")
        r = requests.get("https://d1.awsstatic.com/webteam/architecture-icons/q1-2022/Asset-Package_01312022.735e45eb7f0891333b7fcce325b0af915fd44766.zip")
        with open("./Asset-Package.zip", "wb") as f:
            f.write(r.content)
        with zipfile.ZipFile("Asset-Package.zip", "r") as zip_ref:
            zip_ref.extractall("Assets")
        os.remove("Asset-Package.zip")
        print("Downloading done.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("json_dump", help="Resoto json dump")
    parser.add_argument("out", help="DOT output file")
    args = parser.parse_args()    
    ensure_assets()
    with open(args.json_dump, "r") as f:
        with open(args.out, "w") as out:
            json_obj = json.load(f)
            for line in render_dot(json_obj):
                out.write(f"{line}\n")

if __name__ == "__main__":
    main()
