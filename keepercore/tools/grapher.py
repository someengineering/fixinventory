import json
from argparse import ArgumentParser
from random import randint

parser = ArgumentParser()
parser.add_argument("-c", "--collector", type=str, default="dummy_collector_1")
parser.add_argument("-d", "--depth", type=int, default=10)
parser.add_argument("-w", "--width", type=int, default=10)
parser.add_argument("--wild", action="store_true")
ns = parser.parse_args()
collector, depth, width, wild = ns.collector, ns.depth, ns.width, ns.wild

by_idx = {
    0: {"kind": "cloud", "atime": "2021-02-15T16:15:21Z", "ctime": "2021-02-15T16:15:21Z"},
    1: {
        "kind": "aws_account",
        "account_alias": "foo",
        "role": "bla",
        "age": "0:00:05.618571",
        "atime": "2021-02-15T16:15:22Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2021-02-15T16:15:22Z",
        "last_access": "2021-02-15T16:15:22Z",
        "last_update": "2021-02-15T16:15:22Z",
        "mtime": "2021-02-15T16:15:22Z",
    },
    2: {
        "kind": "aws_region",
        "age": "5447 days, 16:15:30.732418",
        "atime": "2021-02-15T16:15:30Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2006-03-19T00:00:00Z",
        "last_access": "0:00:00.000275",
        "last_update": "0:00:00.000287",
        "mtime": "2021-02-15T16:15:30Z",
    },
    3: {
        "kind": "aws_iam_policy",
        "arn": "arn:aws:iam::fpp:policy/DeployServerPolicy",
        "age": "937 days, 23:14:25.081178",
        "atime": "2021-02-15T16:15:32Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2018-07-23T17:01:07Z",
        "last_access": "0:00:00.000266",
        "last_update": "937 days, 23:14:25.081219",
        "mtime": "2018-07-23T17:01:07Z",
    },
    4: {
        "kind": "aws_vpc_quota",
        "quota": 5,
        "usage": 0,
        "age": "0:00:02.319276",
        "atime": "2021-02-15T16:35:15Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2021-02-15T16:35:15Z",
        "last_access": "0:00:02.319296",
        "last_update": "0:00:02.319308",
        "mtime": "2021-02-15T16:35:15Z",
        "usage_percentage": 0,
    },
    5: {
        "kind": "aws_vpc",
        "is_default": True,
        "age": "236 days, 18:36:10.949511",
        "atime": "2021-02-15T16:35:19Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2020-06-23T21:59:08Z",
        "last_access": "0:00:00.000269",
        "last_update": "0:00:00.000276",
        "mtime": "2021-02-15T16:35:19Z",
    },
    6: {
        "kind": "aws_ec2_subnet",
        "age": "0:00:00.000222",
        "atime": "2021-02-15T16:35:22Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2021-02-15T16:35:22Z",
        "last_access": "0:00:00.000231",
        "last_update": "0:00:00.000239",
        "mtime": "2021-02-15T16:35:22Z",
    },
    7: {
        "kind": "aws_ec2_network_acl",
        "is_default": True,
        "age": "256 days, 17:24:30.181890",
        "atime": "2021-02-15T16:36:10Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2020-06-03T23:11:40Z",
        "last_access": "0:00:00.001373",
        "last_update": "0:00:00.001393",
        "mtime": "2021-02-15T16:36:10Z",
    },
    8: {
        "kind": "aws_ec2_route_table",
        "age": "0:00:00.000583",
        "atime": "2021-02-15T16:35:28Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2021-02-15T16:35:28Z",
        "last_access": "0:00:00.000597",
        "last_update": "0:00:00.000606",
        "mtime": "2021-02-15T16:35:28Z",
    },
    9: {
        "kind": "aws_ec2_security_group",
        "age": "0:00:00.189233",
        "atime": "2021-02-15T16:35:31Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2021-02-15T16:35:31Z",
        "last_access": "0:00:00.189252",
        "last_update": "0:00:00.189259",
        "mtime": "2021-02-15T16:35:31Z",
    },
    10: {
        "kind": "aws_ec2_internet_gateway_quota",
        "quota": 5,
        "usage": 0,
        "age": "0:00:00.000097",
        "atime": "2021-02-15T16:35:31Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2021-02-15T16:35:31Z",
        "last_access": "0:00:00.000106",
        "last_update": "0:00:00.000115",
        "mtime": "2021-02-15T16:35:31Z",
        "usage_percentage": 0,
    },
    11: {
        "kind": "aws_iam_instance_profile",
        "arn": "arn:aws:iam::foonla:instance-profile/aws-elasticbeanstalk-ec2-role",
        "age": "1134 days, 4:00:30.818540",
        "atime": "2021-02-15T16:15:33Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2018-01-08T12:15:03Z",
        "last_access": "0:00:00.000211",
        "last_update": "0:00:00.000220",
        "mtime": "2021-02-15T16:15:33Z",
    },
    12: {
        "kind": "aws_s3_bucket_quota",
        "quota": -1,
        "usage": 0,
        "age": "0:00:00.795871",
        "atime": "2021-02-15T16:16:02Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2021-02-15T16:16:02Z",
        "last_access": "0:00:00.795896",
        "last_update": "0:00:00.795906",
        "mtime": "2021-02-15T16:16:02Z",
        "usage_percentage": 0,
    },
    13: {
        "kind": "aws_ec2_instance_type",
        "quota": -1,
        "usage": 0,
        "instance_type": "m4.2xlarge",
        "instance_cores": 8,
        "instance_memory": 32,
        "ondemand_cost": 0.4,
        "reservations": 0,
        "age": "0:00:14.998049",
        "atime": "2021-02-15T16:17:48Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2021-02-15T16:17:48Z",
        "last_access": "0:00:14.998065",
        "last_update": "0:00:14.998074",
        "mtime": "2021-02-15T16:17:48Z",
        "usage_percentage": 0,
    },
    14: {
        "kind": "aws_ec2_instance",
        "instance_cores": 8,
        "instance_memory": 32,
        "instance_type": "t3.2xlarge",
        "age": "482 days, 0:15:18.738742",
        "atime": "2021-02-15T16:35:36Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2019-10-22T16:20:25Z",
        "instance_status": "running",
        "last_access": "0:00:06.771807",
        "last_update": "0:00:06.771818",
        "mtime": "2021-02-15T16:35:36Z",
    },
    15: {
        "kind": "aws_ec2_network_interface",
        "network_interface_status": "available",
        "network_interface_type": "interface",
        "mac": "0e:f8:c1:dd:db:92",
        "description": "",
        "age": "0:00:00.000201",
        "atime": "2021-02-15T16:36:22Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2021-02-15T16:36:22Z",
        "last_access": "0:00:00.000215",
        "last_update": "0:00:00.000223",
        "mtime": "2021-02-15T16:36:22Z",
    },
    16: {
        "kind": "aws_ec2_volume",
        "volume_size": 80,
        "volume_type": "gp2",
        "snapshot_before_delete": False,
        "age": "153 days, 21:38:44.066039",
        "atime": "2021-02-15T16:18:46Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2020-09-14T18:40:02Z",
        "last_access": "0:00:00.000358",
        "last_update": "0:00:00.000373",
        "mtime": "2021-02-15T16:18:46Z",
        "volume_status": "in-use",
    },
    17: {
        "kind": "aws_ec2_volume_type",
        "quota": -1,
        "usage": 0,
        "volume_type": "gp2",
        "ondemand_cost": 0.1,
        "age": "0:00:06.655182",
        "atime": "2021-02-15T16:19:01Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2021-02-15T16:19:01Z",
        "last_access": "0:00:06.655200",
        "last_update": "0:00:06.655212",
        "mtime": "2021-02-15T16:19:01Z",
        "usage_percentage": 0,
    },
    18: {
        "kind": "aws_autoscaling_group",
        "min_size": -1,
        "max_size": -1,
        "arn": "arn:aws:autoscaling:us-east-1:GOO:autoScalingGroup:bla:autoScalingGroupName/eks-aeba2879-fooo",
        "age": "165 days, 17:47:57.744458",
        "atime": "2021-02-15T16:20:41Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2020-09-02T22:32:43Z",
        "last_access": "0:00:00.000142",
        "last_update": "0:00:00.000156",
        "mtime": "2021-02-15T16:20:41Z",
    },
    19: {
        "kind": "aws_eks_cluster",
        "arn": "arn:aws:eks:us-east-1:BLU:cluster/eks-demo-001-eks-cluster",
        "cluster_status": "ACTIVE",
        "cluster_endpoint": "https://boo.gr7.us-east-1.eks.amazonaws.com",
        "age": "165 days, 18:02:33.276840",
        "atime": "2021-02-15T16:21:45Z",
        "clean": False,
        "cleaned": False,
        "ctime": "2020-09-02T22:19:12Z",
        "last_access": "0:00:00.000288",
        "last_update": "0:00:00.000303",
        "mtime": "2021-02-15T16:21:45Z",
    },
}


def node(level, identity, merge: bool = False):
    idjs = {"name": f"name: {identity} at level: {level}", "label": f"{identity}:{level}"}
    num = randint(0, 100) if wild else level
    reported = by_idx[num % len(by_idx)] | idjs
    metadata = {"level": level}
    desired = {"name": f"some cool name", "age": 29}
    js = {"id": identity, "reported": reported, "desired": desired, "metadata": metadata}
    js = js | {"merge": True} if merge else js
    print(json.dumps(js))


def edge(from_node, to_node, edge_type):
    print(json.dumps({"from": from_node, "to": to_node, "edge_type": edge_type}))


root = f"root"
collector_root = f"{collector}_root"
node(0, root)
node(0, collector_root, merge=True)
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
