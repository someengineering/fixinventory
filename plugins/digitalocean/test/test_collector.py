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
    project_resources,
    spaces,
    apps,
    cdn_endpoints,
    certificates
)
from resotolib.graph import sanitize
from resotolib.baseresources import Cloud
from resotolib.graph import Graph, GraphRoot
import datetime


class ClientMock(object):
    def __init__(self, responses):
        self.responses = responses

    def __getattr__(self, name):
        def wrapper(*args, **kwargs):
            return self.responses.get(name, [])

        return wrapper


def prepare_graph(do_client) -> Graph:
    cloud = Cloud("do")
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


def test_collect_teams():

    do_client = ClientMock({})
    graph = prepare_graph(do_client)

    check_edges(graph, "do", "do:team:test_team")
    team_node = graph.search_first("id", "do:team:test_team")
    assert team_node.name == "do:team:test_team"
    assert team_node.id == "do:team:test_team"


def test_collect_regions():

    do_client = ClientMock({"list_regions": regions, "list_droplets": droplets})

    graph = prepare_graph(do_client)

    check_edges(graph, "do", "do:team:test_team")
    check_edges(graph, "do:team:test_team", "do:region:fra1")
    check_edges(graph, "do:region:fra1", "do:droplet:289110074")

    # region nyc1 should not be in the graph since it has no resources in it
    assert graph.search_first("id", "do:region:nyc1") is None

    region = graph.search_first("id", "do:region:fra1")
    assert region.name == "Frankfurt 1"
    assert region.kind == "digitalocean_region"
    assert region.do_region_slug == "fra1"
    assert region.do_region_features == [
        "backups",
        "ipv6",
        "metadata",
        "install_agent",
        "storage",
        "image_transfer",
    ]
    assert region.is_available is True


def test_collect_vpcs():
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_vpcs": vpcs,
        }
    )
    graph = prepare_graph(do_client)

    check_edges(graph, "do:region:fra1", "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959")
    vpc = graph.search_first("id", "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959")
    assert vpc.id == "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959"
    assert vpc.name == "default-fra1"
    assert vpc.do_vpc_description == ""
    assert vpc.do_vpc_ip_range == "127.0.0.1/20"
    assert vpc.is_default is True


def test_collect_droplets():
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_droplets": droplets,
            "list_vpcs": vpcs,
        }
    )
    graph = prepare_graph(do_client)

    check_edges(graph, "do:region:fra1", "do:droplet:289110074")
    check_edges(
        graph, "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959", "do:droplet:289110074"
    )
    check_edges(graph, "do:image:101111514", "do:droplet:289110074")
    image = graph.search_first("id", "do:image:101111514")
    assert image.id == "do:image:101111514"
    assert image.name == "20.04 (LTS) x64"
    assert image.do_image_distribution == "Ubuntu"
    assert image.do_image_slug == "ubuntu-20-04-x64"
    assert image.do_image_public is True
    assert image.do_image_type == "base"
    assert image.do_image_size_gigabytes == 1
    assert image.do_image_min_disk_size == 15
    assert image.do_image_status == "available"

    droplet = graph.search_first("id", "do:droplet:289110074")
    assert droplet.id == "do:droplet:289110074"
    assert droplet.name == "ubuntu-s-1vcpu-1gb-fra1-01"
    assert droplet.instance_memory == 1024
    assert droplet.instance_cores == 1
    assert droplet.instance_status == "running"
    assert droplet.region().id == "do:region:fra1"
    assert droplet.do_droplet_image == "ubuntu-20-04-x64"
    assert droplet.is_locked is False
    assert droplet.ctime == datetime.datetime(
        2022, 3, 3, 16, 26, 55, tzinfo=datetime.timezone.utc
    )
    assert droplet.tags == {}


def test_collect_volumes():
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_droplets": droplets,
            "list_volumes": volumes,
        }
    )
    graph = prepare_graph(do_client)

    check_edges(
        graph, "do:droplet:289110074", "do:volume:631f81d2-9fc1-11ec-800c-0a58ac14d197"
    )
    volume = graph.search_first("id", "do:volume:631f81d2-9fc1-11ec-800c-0a58ac14d197")
    assert volume.id == "do:volume:631f81d2-9fc1-11ec-800c-0a58ac14d197"
    assert volume.name == "volume-fra1-01"
    assert volume.do_volume_description == "Test volume"
    assert volume.do_volume_filesystem_type == "ext4"
    assert volume.do_volume_filesystem_label == "label"
    assert volume.volume_size == 1
    assert volume.volume_status == "in-use"


def test_collect_database():
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_databases": databases,
            "list_vpcs": vpcs,
        }
    )
    graph = prepare_graph(do_client)

    check_edges(
        graph,
        "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959",
        "do:dbaas:2848a998-e151-4d5a-9813-0904a44c2397",
    )
    database = graph.search_first("id", "do:dbaas:2848a998-e151-4d5a-9813-0904a44c2397")
    assert database.id == "do:dbaas:2848a998-e151-4d5a-9813-0904a44c2397"
    assert database.name == "do:dbaas:db-postgresql-fra1-82725"
    assert database.db_type == "pg"
    assert database.db_status == "online"
    assert database.db_version == "14"
    assert database.db_endpoint == "host.b.db.ondigitalocean.com"
    assert database.region().id == "do:region:fra1"
    assert database.instance_type == "db-s-1vcpu-1gb"


def test_collect_k8s_clusters():
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_vpcs": vpcs,
            "list_droplets": droplets,
            "list_kubernetes_clusters": k8s,
        }
    )
    graph = prepare_graph(do_client)

    check_edges(
        graph,
        "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959",
        "do:kubernetes:e1c48631-b382-4001-2168-c47c54795a26",
    )
    check_edges(
        graph,
        "do:kubernetes:e1c48631-b382-4001-2168-c47c54795a26",
        "do:droplet:290075243",
    )

    cluster = graph.search_first(
        "id", "do:kubernetes:e1c48631-b382-4001-2168-c47c54795a26"
    )
    assert cluster.id == "do:kubernetes:e1c48631-b382-4001-2168-c47c54795a26"
    assert cluster.name == "k8s-1-22-7-do-0-fra1-test"
    assert cluster.do_k8s_version == "1.22.7-do.0"
    assert cluster.region().id == "do:region:fra1"
    assert cluster.do_k8s_cluster_subnet == "10.244.0.0/16"
    assert cluster.do_k8s_service_subnet == "10.245.0.0/16"
    assert cluster.do_k8s_ipv4 == "127.0.0.1"
    assert (
        cluster.do_k8s_endpoint
        == "https://e1c48631-b382-4001-2168-c47c54795a26.k8s.ondigitalocean.com"
    )
    assert cluster.do_k8s_auto_upgrade is False
    assert cluster.do_k8s_status == "running"
    assert cluster.do_k8s_surge_upgrade is True
    assert cluster.do_k8s_registry_enabled is False
    assert cluster.do_k8s_ha is False


def test_collect_snapshots():
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_droplets": droplets,
            "list_snapshots": snapshots,
        }
    )
    graph = prepare_graph(do_client)

    check_edges(graph, "do:droplet:289110074", "do:snapshot:103198134")
    snapshot = graph.search_first("id", "do:snapshot:103198134")
    assert snapshot.id == "do:snapshot:103198134"
    assert snapshot.volume_size == 25
    assert snapshot.do_snapshot_size_gigabytes == 2
    assert snapshot.do_snapshot_resource_id == "289110074"
    assert snapshot.do_snapshot_resource_type == "droplet"


def test_collect_loadbalancers():
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_load_balancers": load_balancers,
            "list_droplets": droplets,
            "list_vpcs": vpcs,
        }
    )
    graph = prepare_graph(do_client)

    check_edges(
        graph,
        "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959",
        "do:loadbalancer:9625f517-75f0-4af8-a336-62374e68dc0d",
    )
    check_edges(
        graph,
        "do:loadbalancer:9625f517-75f0-4af8-a336-62374e68dc0d",
        "do:droplet:289110074",
    )
    lb = graph.search_first(
        "id", "do:loadbalancer:9625f517-75f0-4af8-a336-62374e68dc0d"
    )
    assert lb.id == "do:loadbalancer:9625f517-75f0-4af8-a336-62374e68dc0d"
    assert lb.name == "fra1-load-balancer-01"
    assert lb.do_lb_ip == "127.0.0.1"
    assert lb.do_lb_size == "lb-small"
    assert lb.do_lb_size_unit == 1
    assert lb.do_lb_status == "new"
    assert lb.do_lb_redirect_http_to_https is False
    assert lb.do_lb_enable_proxy_protocol is False
    assert lb.do_lb_enable_backend_keepalive is False
    assert lb.do_lb_disable_lets_encrypt_dns_records is False


def test_collect_floating_ips():
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_floating_ips": floating_ips,
            "list_droplets": droplets,
        }
    )
    graph = prepare_graph(do_client)
    check_edges(graph, "do:droplet:289110074", "do:floatingip:127.0.0.1")
    floating_ip = graph.search_first("id", "do:floatingip:127.0.0.1")
    assert floating_ip.id == "do:floatingip:127.0.0.1"
    assert floating_ip.ip_address == "127.0.0.1"
    assert floating_ip.ip_address_family == "ipv4"
    assert floating_ip.is_locked is False


def test_collect_projects():
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_projects": projects,
            "list_project_resources": project_resources,
            "list_droplets": droplets,
            "list_load_balancers": load_balancers,
            "list_floating_ips": floating_ips,
            "list_kubernetes_clusters": k8s,
            "list_databases": databases,
            "list_volumes": volumes,
            "list_spaces": spaces,
        }
    )
    graph = prepare_graph(do_client)
    check_edges(
        graph, "do:project:75088298-73bd-4c8f-ba4b-91fc220d0ac7", "do:droplet:289110074"
    )
    check_edges(
        graph,
        "do:project:75088298-73bd-4c8f-ba4b-91fc220d0ac7",
        "do:loadbalancer:9625f517-75f0-4af8-a336-62374e68dc0d",
    )
    check_edges(
        graph,
        "do:project:75088298-73bd-4c8f-ba4b-91fc220d0ac7",
        "do:floatingip:127.0.0.1",
    )
    check_edges(
        graph,
        "do:project:75088298-73bd-4c8f-ba4b-91fc220d0ac7",
        "do:kubernetes:e1c48631-b382-4001-2168-c47c54795a26",
    )
    check_edges(
        graph,
        "do:project:75088298-73bd-4c8f-ba4b-91fc220d0ac7",
        "do:dbaas:2848a998-e151-4d5a-9813-0904a44c2397",
    )
    check_edges(
        graph,
        "do:project:75088298-73bd-4c8f-ba4b-91fc220d0ac7",
        "do:volume:631f81d2-9fc1-11ec-800c-0a58ac14d197",
    )
    check_edges(
        graph,
        "do:project:75088298-73bd-4c8f-ba4b-91fc220d0ac7",
        "do:space:api-test-space.resoto",
    )


def test_collect_space():
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_spaces": spaces,
        }
    )
    graph = prepare_graph(do_client)
    check_edges(graph, "do:region:fra1", "do:space:api-test-space.resoto")
    space = graph.search_first("id", "do:space:api-test-space.resoto")
    assert space.id == "do:space:api-test-space.resoto"
    assert space.name == "api-test-space.resoto"
    assert space.ctime == datetime.datetime(2022, 2, 23, 13, 42, 21, 455000, datetime.timezone.utc)


def test_collect_apps():
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_apps": apps,
            "list_databases": databases,
        }
    )
    graph = prepare_graph(do_client)
    check_edges(graph, "do:region:fra1", "do:app:5dc41512-7523-4eeb-9932-426aa570234b")
    check_edges(graph, "do:dbaas:2848a998-e151-4d5a-9813-0904a44c2397", "do:app:5dc41512-7523-4eeb-9932-426aa570234b")
    app = graph.search_first("id", "do:app:5dc41512-7523-4eeb-9932-426aa570234b")
    assert app.id == "do:app:5dc41512-7523-4eeb-9932-426aa570234b"
    assert app.do_app_default_ingress == "https://resoto_test_app.ondigitalocean.app"
    assert app.do_app_live_url == "https://resoto_test_app.ondigitalocean.app"
    assert app.do_app_live_url_base == "https://resoto_test_app.ondigitalocean.app"
    assert app.do_app_live_domain == "resoto_test_apps.ondigitalocean.app"


def test_cdn_endpoints():
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_cdn_endpoints": cdn_endpoints,
        }
    )
    graph = prepare_graph(do_client)
    check_edges(graph, "do:team:test_team", "do:cdn_endpoint:4edbbc3a-79a5-4950-b2d2-ae8f8f8e8e8c")
    endpoint = graph.search_first("id", "do:cdn_endpoint:4edbbc3a-79a5-4950-b2d2-ae8f8f8e8e8c")
    assert endpoint.id == "do:cdn_endpoint:4edbbc3a-79a5-4950-b2d2-ae8f8f8e8e8c"
    assert endpoint.do_cdn_origin == "resoto_test.ams3.digitaloceanspaces.com"
    assert endpoint.do_cdn_endpoint == "resoto_test.ams3.cdn.digitaloceanspaces.com"
    assert endpoint.do_cdn_created_at == "2021-11-16T16:00:44Z"
    assert endpoint.do_cdn_certificate_id == "429199eb-e6c6-4ab3-bad6-f8f8f8f8f8f8"
    assert endpoint.do_cdn_custom_domain == "test.domain.resoto"
    assert endpoint.do_cdn_ttl == 3600


def test_collect_certificates():
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_certificates": certificates
        }
    )
    graph = prepare_graph(do_client)
    check_edges(graph, "do:team:test_team", "do:certificate:429199eb-7137-4e2b-a15e-f74700173e3c")
    cert = graph.search_first("id", "do:certificate:429199eb-7137-4e2b-a15e-f74700173e3c")
    assert cert.id == "do:certificate:429199eb-7137-4e2b-a15e-f74700173e3c"
    assert cert.name == "cdn.resoto.test"
    assert cert.do_cert_sha1_fingerprint == "5909e5e05bbce0c63c2e2523542f74700173e3c2"
    assert cert.do_cert_dns_names == ["*.resoto.test", "resoto.test"]
    assert cert.do_cert_state == "verified"
    assert cert.do_cert_type == "custom"
