from resoto_plugin_digitalocean.collector import DigitalOceanTeamCollector
from resoto_plugin_digitalocean.resources import DigitalOceanTeam
from fixtures import (
    droplets,
    regions,
    volumes,
    vpcs,
    databases,
    k8s,
    snapshots,
    load_balancers,
    floating_ips,
    projects,
    project_resources
)
from resotolib.graph import sanitize
from resotolib.baseresources import Cloud
from resotolib.graph import Graph, GraphRoot
import datetime
from resoto_plugin_digitalocean.client import StreamingWrapper
import os
import re


class ClientMock(object):

    def __init__(self, responses):
        self.responses = responses

    def __getattr__(self, name):
        def wrapper(*args, **kwargs):
            return self.responses.get(name, [])

        return wrapper


def prepare_graph(do_client) -> Graph:
    cloud = Cloud('do')
    team = DigitalOceanTeam(id="do:team:test_team")
    plugin_instance = DigitalOceanTeamCollector(team, do_client)
    plugin_instance.collect()
    cloud_graph = Graph(root=cloud)
    graph = Graph(root=GraphRoot("root", {}))
    cloud_graph.merge(plugin_instance.graph)
    graph.merge(cloud_graph)
    sanitize(graph)
    return graph


def check_edges(graph: Graph, from_id: str, to_id: str) -> None:
    for (node_from, node_to, edge) in graph.edges:
        if node_from.id == from_id and node_to.id == to_id:
            return
    assert False, f"Edge {from_id} -> {to_id} not found"


def _test_api_call():

    access_token = os.environ['RESOTO_DIGITALOCEAN_API_TOKENS'].split(" ")[0]

    client = StreamingWrapper(access_token)

    resources = client.list_project_resources("75088298-73bd-4c8f-ba4b-91fc220d0ac7")
    print()
    print(re.sub("'", '"', str(resources)))
    assert False


def test_collect_teams():

    do_client = ClientMock({})
    graph = prepare_graph(do_client)

    check_edges(graph, "do", "do:team:test_team")
    team_node = graph.search_first("id", "do:team:test_team")
    assert team_node.name == "do:team:test_team"
    assert team_node.id == "do:team:test_team"


def test_collect_regions():

    do_client = ClientMock({
        "list_regions": regions,
        "list_droplets": droplets
    })

    graph = prepare_graph(do_client)

    check_edges(graph, "do", "do:team:test_team")
    check_edges(graph, "do:team:test_team", "do:region:fra1")
    check_edges(graph, "do:region:fra1", "do:droplet:289110074")

    # region nyc1 should not be in the graph since it has no resources in it
    assert graph.search_first("id", "do:region:nyc1") is None

    region = graph.search_first("id", "do:region:fra1")
    assert region.name == "Frankfurt 1"
    assert region.kind == "digitalocean_region"
    assert region.slug == "fra1"
    assert region.features == ['backups', 'ipv6', 'metadata', 'install_agent', 'storage', 'image_transfer']
    assert region.available is True


def test_collect_vpcs():
    do_client = ClientMock({
        "list_regions": regions,
        "list_vpcs": vpcs,
    })
    graph = prepare_graph(do_client)

    check_edges(graph, "do:region:fra1", "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959")
    vpc = graph.search_first("id", "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959")
    assert vpc.id == "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959"
    assert vpc.name == "default-fra1"
    assert vpc.description == ""
    assert vpc.ip_range == "127.0.0.1/20"
    assert vpc.default is True


def test_collect_droplets():
    do_client = ClientMock({
        "list_regions": regions,
        "list_droplets": droplets,
        "list_vpcs": vpcs,
    })
    graph = prepare_graph(do_client)

    check_edges(graph, "do:region:fra1", "do:droplet:289110074")
    check_edges(graph, "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959", "do:droplet:289110074")
    droplet = graph.search_first("id", "do:droplet:289110074")
    assert droplet.id == "do:droplet:289110074"
    assert droplet.name == "ubuntu-s-1vcpu-1gb-fra1-01"
    assert droplet.instance_memory == 1024
    assert droplet.instance_cores == 1
    assert droplet.instance_status == "running"
    assert droplet.region().id == "do:region:fra1"
    assert droplet.image == "ubuntu-20-04-x64"
    assert droplet.locked is False
    assert droplet.ctime == datetime.datetime(2022, 3, 3, 16, 26, 55, tzinfo=datetime.timezone.utc)
    assert droplet.tags == {}


def test_collect_volumes():
    do_client = ClientMock({
        "list_regions": regions,
        "list_droplets": droplets,
        "list_volumes": volumes,
    })
    graph = prepare_graph(do_client)

    check_edges(graph, "do:droplet:289110074", "do:volume:631f81d2-9fc1-11ec-800c-0a58ac14d197")
    volume = graph.search_first("id", "do:volume:631f81d2-9fc1-11ec-800c-0a58ac14d197")
    assert volume.id == "do:volume:631f81d2-9fc1-11ec-800c-0a58ac14d197"
    assert volume.name == "volume-fra1-01"
    assert volume.description == "Test volume"
    assert volume.filesystem_type == "ext4"
    assert volume.filesystem_label == ""
    assert volume.volume_size == 1
    assert volume.volume_status == "in-use"


def test_collect_database():
    do_client = ClientMock({
        "list_regions": regions,
        "list_databases": databases,
        "list_vpcs": vpcs,
    })
    graph = prepare_graph(do_client)

    check_edges(graph, "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959", "do:dbaas:2848a998-e151-4d5a-9813-0904a44c2397")
    database = graph.search_first("id", "do:dbaas:2848a998-e151-4d5a-9813-0904a44c2397")
    assert database.id == "do:dbaas:2848a998-e151-4d5a-9813-0904a44c2397"
    assert database.name == "db-postgresql-fra1-82725"
    assert database.db_type == "pg"
    assert database.db_status == "online"
    assert database.db_version == "14"
    assert database.db_endpoint == "host.b.db.ondigitalocean.com"
    assert database.region().id == "do:region:fra1"
    assert database.instance_type == "db-s-1vcpu-1gb"


def test_collect_k8s_clusters():
    do_client = ClientMock({
        "list_regions": regions,
        "list_vpcs": vpcs,
        "list_droplets": droplets,
        "list_kubernetes_clusters": k8s,
    })
    graph = prepare_graph(do_client)

    check_edges(
        graph,
        "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959",
        "do:kubernetes:e1c48631-b382-4001-2168-c47c54795a26"
    )
    check_edges(graph, "do:kubernetes:e1c48631-b382-4001-2168-c47c54795a26", "do:droplet:290075243")

    cluster = graph.search_first("id", "do:kubernetes:e1c48631-b382-4001-2168-c47c54795a26")
    assert cluster.id == "do:kubernetes:e1c48631-b382-4001-2168-c47c54795a26"
    assert cluster.name == "k8s-1-22-7-do-0-fra1-test"
    assert cluster.version == "1.22.7-do.0"
    assert cluster.region().id == "do:region:fra1"
    assert cluster.cluster_subnet == "10.244.0.0/16"
    assert cluster.service_subnet == "10.245.0.0/16"
    assert cluster.ipv4 == "127.0.0.1"
    assert cluster.endpoint == "https://e1c48631-b382-4001-2168-c47c54795a26.k8s.ondigitalocean.com"
    assert cluster.auto_upgrade is False
    assert cluster.status == "running"
    assert cluster.surge_upgrade is True
    assert cluster.registry_enabled is False
    assert cluster.ha is False


def test_collect_snapshots():
    do_client = ClientMock({
        "list_regions": regions,
        "list_droplets": droplets,
        "list_snapshots": snapshots,
    })
    graph = prepare_graph(do_client)

    check_edges(graph, "do:droplet:289110074", "do:snapshot:103198134")
    snapshot = graph.search_first("id", "do:snapshot:103198134")
    assert snapshot.id == "do:snapshot:103198134"
    assert snapshot.volume_size == 25
    assert snapshot.size_gigabytes == 2
    assert snapshot.resource_id == "289110074"
    assert snapshot.resource_type == "droplet"


def test_collect_loadbalancers():
    do_client = ClientMock({
        "list_regions": regions,
        "list_load_balancers": load_balancers,
        "list_droplets": droplets,
        "list_vpcs": vpcs,
    })
    graph = prepare_graph(do_client)

    check_edges(
        graph,
        "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959",
        "do:loadbalancer:9625f517-75f0-4af8-a336-62374e68dc0d"
    )
    check_edges(graph, "do:loadbalancer:9625f517-75f0-4af8-a336-62374e68dc0d", "do:droplet:289110074")
    lb = graph.search_first("id", "do:loadbalancer:9625f517-75f0-4af8-a336-62374e68dc0d")
    assert lb.id == "do:loadbalancer:9625f517-75f0-4af8-a336-62374e68dc0d"
    assert lb.name == "fra1-load-balancer-01"
    assert lb.ip == "127.0.0.1"
    assert lb.size == "lb-small"
    assert lb.size_unit == 1
    assert lb.status == "new"
    assert lb.redirect_http_to_https is False
    assert lb.enable_proxy_protocol is False
    assert lb.enable_backend_keepalive is False
    assert lb.disable_lets_encrypt_dns_records is False


def test_collect_floating_ips():
    do_client = ClientMock({
        "list_regions": regions,
        "list_floating_ips": floating_ips,
        "list_droplets": droplets,
    })
    graph = prepare_graph(do_client)
    check_edges(graph, "do:droplet:289110074", "do:floatingip:127.0.0.1")
    floating_ip = graph.search_first("id", "do:floatingip:127.0.0.1")
    assert floating_ip.id == "do:floatingip:127.0.0.1"
    assert floating_ip.ip_address == "127.0.0.1"
    assert floating_ip.ip_address_family == "ipv4"
    assert floating_ip.locked is False


def test_collect_projects():
    do_client = ClientMock({
        "list_regions": regions,
        "list_projects": projects,
        "list_project_resources": project_resources,
        "list_droplets": droplets,
        "list_load_balancers": load_balancers,
        "list_floating_ips": floating_ips,
        "list_kubernetes_clusters": k8s,
        "list_databases": databases,
        "list_volumes": volumes,
    })
    graph = prepare_graph(do_client)
    check_edges(
        graph,
        "do:project:75088298-73bd-4c8f-ba4b-91fc220d0ac7",
        "do:droplet:289110074"
    )
    check_edges(
        graph,
        "do:project:75088298-73bd-4c8f-ba4b-91fc220d0ac7",
        "do:loadbalancer:9625f517-75f0-4af8-a336-62374e68dc0d"
    )
    check_edges(
        graph,
        "do:project:75088298-73bd-4c8f-ba4b-91fc220d0ac7",
        "do:floatingip:127.0.0.1"
    )
    check_edges(
        graph,
        "do:project:75088298-73bd-4c8f-ba4b-91fc220d0ac7",
        "do:kubernetes:e1c48631-b382-4001-2168-c47c54795a26"
    )
    check_edges(
        graph,
        "do:project:75088298-73bd-4c8f-ba4b-91fc220d0ac7",
        "do:dbaas:2848a998-e151-4d5a-9813-0904a44c2397"
    )
    check_edges(
        graph,
        "do:project:75088298-73bd-4c8f-ba4b-91fc220d0ac7",
        "do:volume:631f81d2-9fc1-11ec-800c-0a58ac14d197"
    )

