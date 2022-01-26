import json
from argparse import ArgumentParser
from random import randint

from typing import Optional

parser = ArgumentParser()
parser.add_argument("-c", "--collector", type=str, default="dummy_collector_1")
parser.add_argument("-d", "--depth", type=int, default=10)
parser.add_argument("-w", "--width", type=int, default=10)
parser.add_argument("--wild", action="store_true")
ns = parser.parse_args()
collector, depth, width, wild = ns.collector, ns.depth, ns.width, ns.wild

by_idx = {
    0: {"kind": "aws_ec2_keypair", "id": "aws", "name": "aws"},
    1: {
        "account_alias": "",
        "id": "111111111111",
        "kind": "aws_account",
        "name": "111111111111",
        "role": "abc_role",
    },
    2: {"id": "ap-southeast-2", "kind": "aws_region", "name": "ap-southeast-2"},
    3: {
        "arn": "arn:aws:iam::111111111111:policy/salt-foo-k8s",
        "id": "ANPAJLC62VS6AAAAAAAWC",
        "kind": "aws_iam_policy",
        "mtime": "2018-04-18T19:21:25Z",
        "name": "salt-foo-k8s",
    },
    4: {"id": "vpc_quota", "kind": "aws_vpc_quota", "name": "vpc_quota", "quota": 5, "tags": {}, "usage": 0},
    5: {"id": "vpc-4a51231d", "is_default": True, "kind": "aws_vpc", "name": "vpc-4a51231d"},
    6: {"id": "subnet-c7a970ae", "kind": "aws_ec2_subnet", "name": "subnet-c7a970ae"},
    7: {"id": "acl-d242b5ba", "is_default": True, "kind": "aws_ec2_network_acl", "name": "acl-d242b5ba"},
    8: {"id": "rtb-861fc8e1", "kind": "aws_ec2_route_table", "name": "rtb-861fc8e1"},
    9: {"id": "sg-3b2a094e", "kind": "aws_ec2_security_group", "name": "public-slave-security-group"},
}


def node(level, identity, replace: bool = False, kind: Optional[str] = None):
    idjs = {"name": f"name: {identity} at level: {level}", "tags": {}}
    num = randint(0, 100) if wild else level
    reported = by_idx[num % len(by_idx)] | idjs
    if kind:
        reported["kind"] = kind
    metadata = {"level": level}
    metadata = metadata | {"replace": True} if replace else metadata
    desired = {"name": f"some cool name", "age": 29}
    js = {"id": identity, "reported": reported, "metadata": metadata, "desired": desired}
    # replace flag is now on metadata level
    # js = js | {"replace": True} if replace else js
    print(json.dumps(js))


def edge(from_node, to_node, edge_type):
    print(json.dumps({"from": from_node, "to": to_node, "edge_type": edge_type}))


root = f"root"
collector_root = f"{collector}_root"
node(0, root, kind="graph_root")
node(0, collector_root, replace=True, kind="cloud")
edge(root, collector_root, "dependency")

for o in range(0, depth):
    oid = f"{collector}_{o}"
    node(o, oid)
    edge(collector_root, oid, "dependency")
    edge(collector_root, oid, "delete")
    for i in range(0, width):
        iid = f"{collector}_{o}_{i}"
        node(o, iid)
        edge(oid, iid, "dependency")
        edge(oid, iid, "delete")
