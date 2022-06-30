import random
import hashlib
from resotolib.logger import log
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.graph import Graph
from resotolib.args import ArgumentParser
from resotolib.config import Config
from .config import RandomConfig
from .resources import (
    RandomAccount,
    RandomRegion,
    RandomNetwork,
    RandomInstance,
    RandomVolume,
)


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


regions = {
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ca-central-1": "Canada (Central)",
    "eu-central-1": "EU (Frankfurt)",
    "eu-west-1": "EU (Ireland)",
    "eu-west-2": "EU (London)",
    "eu-west-3": "EU (Paris)",
    "eu-north-1": "EU (Stockholm)",
    "sa-east-1": "South America (São Paulo)",
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
}


def get_id(input: str, digest_size: int = 10) -> str:
    return hashlib.blake2b(str(input).encode(), digest_size=digest_size).digest().hex()


def add_random_resources(graph: Graph) -> None:
    region_list = list(regions)
    num_accounts = random.randint(1, 10)
    log.debug(f"Adding {num_accounts} accounts")
    for account_num in range(num_accounts):
        account_id = str(int(get_id(f"account_{account_num}", 6), 16))
        account = RandomAccount(account_id, {}, name=f"Random Account {account_num}")
        graph.add_resource(graph.root, account)
        num_regions = random.randint(0, len(regions))
        log.debug(f"Adding {num_regions} regions in {account.rtdname}")
        for region_num in range(num_regions):
            region = RandomRegion(region_list[region_num], {}, name=regions[region_list[region_num]], _account=account)
            graph.add_resource(account, region)
            num_networks = random.randint(1, 20)
            log.debug(f"Adding {num_networks} networks in {account.rtdname} {region.rtdname}")
            for network_num in range(num_networks):
                network_id = "net-" + get_id(f"network_{account_num}_{region_num}_{network_num}")
                network = RandomNetwork(network_id, {}, _account=account, _region=region)
                graph.add_resource(region, network)
                num_instances = random.randint(1, 500)
                log.debug(f"Adding {num_instances} instances in {account.rtdname} {region.rtdname} {network.rtdname}")
                for instance_num in range(num_instances):
                    instance_id = "i-" + get_id(f"instance_{account_num}_{region_num}_{network_num}_{instance_num}")
                    instance = RandomInstance(instance_id, {}, _account=account, _region=region)
                    graph.add_resource(region, instance)
                    graph.add_edge(network, instance)
                    num_volumes = random.randint(1, 5)
                    log.debug(
                        f"Adding {num_volumes} volumes to {account.rtdname} {region.rtdname} {network.rtdname} {instance.rtdname}"
                    )
                    for volume_num in range(num_volumes):
                        volume_id = "vol-" + get_id(
                            f"volume_{account_num}_{region_num}_{network_num}_{instance_num}_{volume_num}"
                        )
                        volume = RandomVolume(volume_id, {}, _account=account, _region=region)
                        graph.add_resource(region, volume)
                        graph.add_edge(instance, volume)
