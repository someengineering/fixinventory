from importlib import resources
from re import template
from resoto_plugin_digitalocean.collector import DigitalOceanTeamCollector
from resoto_plugin_digitalocean.resources import DigitalOceanTeam
from fixtures import droplets, regions, volumes
from resotolib.graph import sanitize
from resotolib.baseresources import Cloud
from resotolib.graph import Graph, GraphRoot
import datetime
from resoto_plugin_digitalocean.client import StreamingWrapper
import os, re

class ClientMock(object):

    def __init__(self, responses):
        self.responses = responses

    def __getattr__(self, name):
        def wrapper(*args, **kwargs):
            print("'%s' was called" % name)
            return self.responses.get(name, [])

        return wrapper


def prepare_graph(team_graph: Graph) -> Graph:
    cloud = Cloud('do')
    cloud_graph = Graph(root=cloud)
    graph = Graph(root=GraphRoot("root", {}))
    cloud_graph.merge(team_graph)
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

    resources = client.list_volumes()
    print(re.sub("'", '"', str(resources)))
    assert False


def test_collect_teams():
    team = DigitalOceanTeam(id="do:team:test_team")

    do_client = ClientMock({})
    
    plugin_instance = DigitalOceanTeamCollector(team, do_client)
    plugin_instance.collect()

    graph = prepare_graph(plugin_instance.graph)

    check_edges(graph, "do", "do:team:test_team")
    team_node = graph.search_first("id", "do:team:test_team")
    assert team_node.name == "do:team:test_team"
    assert team_node.id == "do:team:test_team"


def test_collect_regions():

    team = DigitalOceanTeam(id="do:team:test_team")

    do_client = ClientMock({
        "list_regions": regions,
        "list_droplets": droplets
    })

    plugin_instance = DigitalOceanTeamCollector(team, do_client)
    plugin_instance.collect()

    graph = prepare_graph(plugin_instance.graph)

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


def test_collect_droplets():

    team = DigitalOceanTeam(id="do:team:test_team")
    do_client = ClientMock({
        "list_regions": regions,
        "list_droplets": droplets
    })
    plugin_instance = DigitalOceanTeamCollector(team, do_client)
    plugin_instance.collect()
    graph = prepare_graph(plugin_instance.graph)

    check_edges(graph, "do:region:fra1", "do:droplet:289110074")
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
    assert droplet.tags == {'test_droplet_tag': ''}
    
def test_collect_volumes():

    team = DigitalOceanTeam(id="do:team:test_team")
    do_client = ClientMock({
        "list_regions": regions,
        "list_droplets": droplets,
        "list_volumes": volumes,
    })
    plugin_instance = DigitalOceanTeamCollector(team, do_client)
    plugin_instance.collect()
    graph = prepare_graph(plugin_instance.graph)

    for edge in graph.edges:
        print
        print(edge[2])

    check_edges(graph, "do:droplet:289110074", "do:volume:631f81d2-9fc1-11ec-800c-0a58ac14d197")
    volume = graph.search_first("id", "do:volume:631f81d2-9fc1-11ec-800c-0a58ac14d197")
    assert volume.id == "do:volume:631f81d2-9fc1-11ec-800c-0a58ac14d197"
    assert volume.name == "volume-fra1-01"
    assert volume.description == "Test volume"
    assert volume.filesystem_type == "ext4"
    assert volume.filesystem_label == ""
    assert volume.volume_size == 1
    assert volume.volume_status == "in-use"
