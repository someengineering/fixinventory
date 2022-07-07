try:
    from typing import (
        Generator,
        List,
        Dict,
        Iterator,
        Sequence,
        Mapping,
        Union,
        Any,
        Optional,
    )
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
    from resotocore.util import uuid_str, utc
    from collections import defaultdict
    from attrs import define
    from posthog import Client
    import subprocess
    from pathlib import Path
    import shlex
except ImportError:
    print(f"Can't import one or more modules. Is resoto dev environment activated?")
    print(f"Hint: see https://resoto.com/docs/contributing/components for more info.")
    exit(1)

JsonElement = Union[str, int, float, bool, None, Mapping[str, Any], Sequence[Any]]

run_id = uuid_str()
resoto_assets_path = f"{str(Path.home())}/.resoto/cache/aws_icon_assets/"


class ResourceKind(Enum):
    INSTANCE = 1
    VOLUME = 2
    IMAGE = 3
    FIREWALL = 4
    K8S_CLUSER = 5
    NETWORK = 6
    LOAD_BALANCER = 7
    CLOUD = 8


kind_colors = {
    ResourceKind.INSTANCE: "8",
    ResourceKind.VOLUME: "4",
    ResourceKind.IMAGE: "7",
    ResourceKind.FIREWALL: "6",
    ResourceKind.K8S_CLUSER: "5",
    ResourceKind.NETWORK: "10",
    ResourceKind.LOAD_BALANCER: "9",
    ResourceKind.CLOUD: "1",
}


@define
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
    cloud, rest = kind.split("_")[0], "_".join(kind.split("_")[1:])
    if cloud == "digitalocean":
        return do_kinds.get(rest)
    else:
        return None


def generate_icon_map():
    icon_dir = f"{resoto_assets_path}/Architecture-Service-Icons_01312022"
    compute = "Arch_Compute"
    storage = "Arch_Storage"
    security = "Arch_Security-Identity-Compliance"
    containers = "Arch_Containers"
    networking = "Arch_Networking-Content-Delivery"
    size = "32"
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


def render_resource(
    resource: ResourceDescription,
    icon_map: Mapping[ResourceDescription, str],
    color: int,
) -> str:
    return f""""{resource.uid}" [shape=plain, label=<<TABLE STYLE="ROUNDED" COLOR="{color}" BORDER="3" CELLBORDER="1" CELLPADDING="5">
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
                    id = value_in_path_get(item, NodePath.reported_id, "n/a")
                    parsed_kind = parse_kind(kind)
                    paired12 = kind_colors.get(parsed_kind, colors[kind])
                    in_account[account].append(uid)
                    resource = ResourceDescription(uid, name, id, parsed_kind, kind)
                    yield render_resource(resource, icon_map, paired12)
            elif type_name == "edge":
                from_node = value_in_path(item, NodePath.from_node)
                to_node = value_in_path(item, NodePath.to_node)
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
    if not os.path.exists(resoto_assets_path):
        print("AWS icon assets missing. Downloading assets...")
        os.makedirs(resoto_assets_path, exist_ok=True)
        r = requests.get(
            "https://d1.awsstatic.com/webteam/architecture-icons/q1-2022/Asset-Package_01312022.735e45eb7f0891333b7fcce325b0af915fd44766.zip"
        )
        with open("./Asset-Package.zip", "wb") as f:
            f.write(r.content)
        with zipfile.ZipFile("Asset-Package.zip", "r") as zip_ref:
            zip_ref.extractall(resoto_assets_path)
        os.remove("Asset-Package.zip")
        print("Downloading done.")


def send_analytics(run_id: str, event: str):
    if "RESOTOCORE_ANALYTICS_OPT_OUT" not in os.environ:
        client = Client(
            api_key="n/a",
            host="https://analytics.some.engineering",
            flush_interval=0.5,
            max_retries=3,
            gzip=True,
        )
        api_key = requests.get("https://cdn.some.engineering/posthog/public_api_key").text.strip()
        client.api_key = api_key
        for consumer in client.consumers:
            consumer.api_key = api_key
        system_id = f"dot-rendering-script"
        now = utc()
        client.identify(system_id, {"run_id": run_id, "created_at": now})
        client.capture(
            distinct_id=system_id,
            event=event,
            properties={"run_id": run_id},  # type: ignore
            timestamp=now,
        )


def resh(query, args) -> str:
    uri = ["--resotocore-uri", shlex.quote(args.uri)] if args.uri else []
    psk = ["--psk", shlex.quote(args.psk)] if args.psk else []
    command = ["resh"] + uri + psk + ["--stdin"]
    p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = p.communicate(input=query.encode())[0].decode()
    return output


def preflight_check(args):
    resh_result = subprocess.run(["resh", "-h"], stdout=subprocess.PIPE)
    if resh_result.returncode != 0:
        print("Can't find resh. Is resoto virtualenv activated?")
        print("Hint: see https://resoto.com/docs/contributing/components for more info.")
        exit(1)
    resh_ping = resh("echo ping", args)
    if not resh_ping.startswith("ping"):
        print(f"resh can't reach resotocore at {args.uri}: {resh_ping}")
        exit(1)
    grahviz_result = subprocess.run([args.engine, "-V"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if grahviz_result.returncode != 0:
        print(f"Can't find {args.engine} grahviz renderer. Is graphviz instlled?")
        print("See https://graphviz.org/download/ for the installation instructions.")
        exit(1)


def call_resh(args):
    query = args.query
    query += " | format --json | write resoto_graph_export.json"
    if os.path.isfile("resoto_graph_export.json"):
        os.remove("resoto_graph_export.json")
    output = resh(query, args)
    if not output.startswith("Received a file"):
        print(f"resh error: {output}")
        exit(1)


def generate_dot():
    with open("resoto_graph_export.json", "r") as f:
        with open("resoto_graph_export.dot", "w") as out:
            json_obj = json.load(f)
            for line in render_dot(json_obj):
                out.write(f"{line}\n")
    if os.path.isfile("resoto_graph_export.json"):
        os.remove("resoto_graph_export.json")


def run_graphviz(args) -> str:
    engine = args.engine
    output_format = f"-T{args.format}"
    output_file = args.output
    command = [engine, output_format, "resoto_graph_export.dot", "-o", output_file]
    render_result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if render_result.returncode != 0:
        print(f"{engine} error: {render_result.stdout.decode()}")
        exit(1)
    os.remove("resoto_graph_export.dot")
    return output_file


def report_success(output_file):
    print("Successfully rendered graph to " + output_file)


def main():
    parser = argparse.ArgumentParser(
        description="Render a result of a resoto query to image file.",
        epilog="""Example: python3 render_dot.py 'search --with-edges is(instance) <-[0:]->'
This command will collect instances in your graph and render them to an svg file.
""",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("query", help="query for visualization")
    parser.add_argument("--engine", help="graphviz layout engine to use", default="sfdp")
    parser.add_argument("--format", help="output format", default="svg")
    parser.add_argument("--output", help="output file", default="graph.svg")
    parser.add_argument("--psk", help="Pre shared key to be passed to resh", dest="psk")
    parser.add_argument("--resotocore-uri", help="resotocore URI", dest="uri")
    args = parser.parse_args()
    preflight_check(args)
    ensure_assets()
    call_resh(args)
    generate_dot()
    output_name = run_graphviz(args)
    report_success(output_name)
    send_analytics(run_id, "dot-rendering-script-executed")


if __name__ == "__main__":
    main()
