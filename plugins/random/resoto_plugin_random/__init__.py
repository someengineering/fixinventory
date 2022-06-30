import random
import hashlib
import time
from resotolib.baseresources import BaseResource
from resotolib.logger import log
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.graph import Graph
from resotolib.args import ArgumentParser
from resotolib.config import Config
from .config import RandomConfig
from .resources import (
    first_names,
    purposes,
    instance_statuses,
    instance_types,
    volume_statuses,
    RandomAccount,
    RandomRegion,
    RandomNetwork,
    RandomLoadBalancer,
    RandomInstance,
    RandomVolume,
)
from typing import List, Callable, Dict, Optional

employees = []


class RandomCollectorPlugin(BaseCollectorPlugin):
    cloud = "random"

    def collect(self) -> None:
        """This method is being called by resoto whenever the collector runs

        It is responsible for querying the cloud APIs for remote resources and adding
        them to the plugin graph.
        The graph root (self.graph.root) must always be followed by one or more
        accounts. An account must always be followed by a region.
        A region can contain arbitrary resources.
        """
        log.debug("plugin: collecting random resources")
        random.seed(Config.random.seed)
        add_random_resources(self.graph)
        random.seed()

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        pass

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(RandomConfig)


def get_id(input: str, digest_size: int = 10) -> str:
    return hashlib.blake2b(str(input).encode(), digest_size=digest_size).digest().hex()


def add_random_resources(graph: Graph) -> None:
    global employees
    employees = random.choices(first_names, k=random.randint(5, 30))
    add_accounts(graph)


def add_accounts(graph: Graph) -> None:
    num_accounts = random.randint(1, 10)
    log.debug(f"Adding {num_accounts} accounts")
    for account_num in range(num_accounts):
        account_id = str(int(get_id(f"account_{account_num}", 6), 16))
        account = RandomAccount(account_id, {}, name=f"Random Account {account_num}")
        graph.add_resource(graph.root, account)
        add_regions(graph, [account], account=account)


region_templates = {
    "ap-northeast-": "Asia Pacific North East",
    "ap-southeast-": "Asia Pacific South East",
    "ap-south-": "Asia Pacific South",
    "ca-central-": "Canada Central",
    "eu-central-": "EU Central",
    "eu-north-": "EU North",
    "eu-west-": "EU West",
    "sa-east-": "South America East",
    "us-east-": "US East",
    "us-west-": "US West",
}


def add_regions(graph: Graph, parents: List[BaseResource], account: BaseResource = None) -> None:
    num_total_regions = random.randint(10, 100)
    all_regions = {}
    r_num = 1
    i = 0
    while i < num_total_regions:
        for rt_short, rt_long in region_templates.items():
            r_short = f"{rt_short}{r_num}"
            r_long = f"{rt_long} {r_num}"
            all_regions[r_short] = r_long
            i += 1
            if i >= num_total_regions:
                break
        r_num += 1

    num_regions = random.randint(1, 4)
    regions = random.sample(sorted(all_regions), num_regions)
    log.debug(f"Adding {num_regions} regions {regions} in {account.rtdname}")
    for r in regions:
        region = RandomRegion(r, {}, name=all_regions[r], _account=account)
        graph.add_node(region)
        for parent in parents:
            graph.add_edge(parent, region)
        id_path = f"{account.id}/{region.id}"
        add_networks(graph, [region], account=account, region=region, id_path=id_path)


def add_networks(
    graph: Graph,
    parents: List[BaseResource],
    id_path: str,
    num: Optional[int] = None,
    account: BaseResource = None,
    region: BaseResource = None,
    kwargs: Optional[Dict] = None,
) -> None:
    add_resources(
        graph=graph,
        parents=parents,
        children=[add_instance_groups],
        cls=RandomNetwork,
        short_prefix="rndnet-",
        long_prefix="Network",
        min=1,
        max=4,
        num=num,
        id_path=id_path,
        account=account,
        region=region,
    )


def add_instance_groups(
    graph: Graph,
    parents: List[BaseResource],
    id_path: str,
    num: Optional[int] = None,
    account: BaseResource = None,
    region: BaseResource = None,
    kwargs: Optional[Dict] = None,
) -> None:
    num_groups = random.randint(5, 50)
    log.debug(f"Adding {num_groups} instance groups in {region.rtdname}")
    instance_status = random.choices(instance_statuses, weights=[1, 85, 1, 11, 1, 1], k=1)[0]
    instance_type = random.choices(list(instance_types), weights=[10, 10, 20, 50, 20, 10, 5, 5], k=1)[0]
    tags = {}
    long_prefix = f"Instance"
    purpose = random.choice(purposes)
    tags["costCenter"] = purpose[0]
    has_owner = random.randrange(100) < 90
    if has_owner:
        owner = random.choice(employees)
        tags["owner"] = owner
        long_prefix = purpose[1]
    kwargs = {
        "tags": tags,
        "instance_status": instance_status,
        "instance_type": instance_type,
        "instance_cores": instance_types[instance_type][0],
        "instance_memory": instance_types[instance_type][1],
    }
    add_instances(
        graph=graph,
        parents=parents,
        id_path=id_path,
        num=num,
        long_prefix=long_prefix,
        account=account,
        region=region,
        kwargs=kwargs,
    )


def add_instances(
    graph: Graph,
    parents: List[BaseResource],
    id_path: str,
    long_prefix: str,
    num: Optional[int] = None,
    account: BaseResource = None,
    region: BaseResource = None,
    kwargs: Optional[Dict] = None,
) -> None:
    if long_prefix.startswith("Webserver"):
        lb = add_loadbalancer(
            graph=graph, id_path=id_path, parents=parents, account=account, region=region, kwargs=kwargs
        )
        parents.append(lb)

    volume_status = random.choices(volume_statuses, weights=[2, 15, 80, 1, 1, 1], k=1)[0]
    volume_tags = kwargs.get("tags", {})
    child_kwargs = {"tags": volume_tags, "volume_status": volume_status}

    add_resources(
        graph=graph,
        parents=parents,
        children=[add_volumes],
        cls=RandomInstance,
        short_prefix="rndi-",
        long_prefix=long_prefix,
        min=0,
        max=50,
        num=num,
        num_children=random.randint(1, 5),
        jitter=int(time.time() % 3),
        id_path=id_path,
        account=account,
        region=region,
        kwargs=kwargs,
        child_kwargs=child_kwargs,
    )


def add_volumes(
    graph: Graph,
    parents: List[BaseResource],
    id_path: str,
    num: Optional[int] = None,
    account: BaseResource = None,
    region: BaseResource = None,
    kwargs: Optional[Dict] = None,
) -> None:
    add_resources(
        graph=graph,
        parents=parents,
        children=[],
        cls=RandomVolume,
        short_prefix="rndvol-",
        long_prefix="Volume",
        min=1,
        max=5,
        num=num,
        id_path=id_path,
        account=account,
        region=region,
        kwargs=kwargs,
    )


def add_resources(
    graph: Graph,
    parents: List[BaseResource],
    children: List[Callable],
    cls: BaseResource,
    short_prefix: str,
    long_prefix: str,
    min: int,
    max: int,
    id_path: str,
    jitter: int = 0,
    num: Optional[int] = None,
    num_children: Optional[int] = None,
    account: BaseResource = None,
    region: BaseResource = None,
    kwargs: Optional[Dict] = None,
    child_kwargs: Optional[Dict] = None,
) -> None:
    if kwargs is None:
        kwargs = {"tags": {}}
    if num:
        num_resources = num
    else:
        num_resources = random.randint(min, max) + jitter
    log.debug(
        f"Adding {num_resources} {long_prefix} resources in {account.rtdname} {region.rtdname} with parents: {parents}, children: {children}"
    )
    for resource_num in range(num_resources):
        resource_id_path = f"{id_path}/{short_prefix}{resource_num}"
        log.debug(f"Adding {long_prefix} {resource_num} resource ({id_path})")
        resource_id = short_prefix + get_id(resource_id_path)
        name = f"{long_prefix} {resource_num}"
        resource = cls(resource_id, name=name, _account=account, _region=region, **kwargs)
        graph.add_node(resource)
        for parent in parents:
            graph.add_edge(parent, resource)
        child_parents = [resource]
        if region != resource:
            child_parents.append(region)
        for child in children:
            child(
                graph=graph,
                parents=child_parents,
                id_path=resource_id_path,
                account=account,
                region=region,
                num=num_children,
                kwargs=child_kwargs,
            )


def add_loadbalancer(
    graph: Graph,
    id_path: str,
    parents: List[BaseResource],
    account: BaseResource = None,
    region: BaseResource = None,
    kwargs: Optional[Dict] = None,
) -> BaseResource:
    resource_id_path = f"{id_path}/lb"
    log.debug(f"Adding load balancer resource ({id_path}) ({kwargs})")
    if kwargs is None:
        tags = {}
    else:
        tags = kwargs.get("tags", {})
    resource_id = "rndlb-" + get_id(resource_id_path)
    lb = RandomLoadBalancer(resource_id, tags=tags, name="LoadBalancer", _account=account, _region=region)
    graph.add_node(lb)
    for parent in parents:
        graph.add_edge(parent, lb)
    return lb
