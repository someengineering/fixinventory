from resoto_plugin_digitalocean.collector import DigitalOceanTeamCollector
from resoto_plugin_digitalocean.resources import DigitalOceanTeam, DigitalOceanVolume, DigitalOceanDropletSize
from resoto_plugin_digitalocean.client import StreamingWrapper
from resotolib.core.actions import CoreFeedback
from .fixtures import (
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
    certificates,
    registry,
    registry_repositories,
    registry_repository_tags,
    ssh_keys,
    tags,
    domains,
    domain_records,
    firewalls,
    alerts,
)
from resotolib.graph import sanitize
from resotolib.baseresources import Cloud, EdgeType, GraphRoot, InstanceStatus, VolumeStatus
from resotolib.graph import Graph
import datetime
from typing import Dict, Any, List, cast


class ClientMock(StreamingWrapper, object):
    def __init__(self, responses: Dict[str, Any]) -> None:
        self.responses = responses

    def with_feedback(self, core_feedback: CoreFeedback) -> StreamingWrapper:
        return ClientMock(self.responses)

    def __getattribute__(self, name):  # type: ignore
        responses = super().__getattribute__("responses")

        def wrapper(*args, **kwargs) -> Any:  # type: ignore
            return responses.get(name, [])

        return wrapper


def prepare_graph(do_client: StreamingWrapper) -> Graph:
    cloud = Cloud(id="do")
    team = DigitalOceanTeam(id="test_team", urn="do:team:test_team")
    plugin_instance = DigitalOceanTeamCollector(team, do_client)
    plugin_instance.collect()
    cloud_graph = Graph(root=cloud)
    graph = Graph(root=GraphRoot(id="root", tags={}))
    cloud_graph.merge(plugin_instance.graph)
    graph.merge(cloud_graph)
    sanitize(graph)
    return graph


def check_edges(graph: Graph, from_id: str, to_id: str, delete: bool = False) -> None:
    for (node_from, node_to, edge) in graph.edges:
        if (
            hasattr(node_from, "urn")
            and hasattr(node_to, "urn")
            and node_from.urn == from_id
            and node_to.urn == to_id
            and edge.edge_type == (EdgeType.delete if delete else EdgeType.default)
        ):
            return
    assert False, f"Edge {from_id} -> {to_id} not found"


def test_collect_teams() -> None:

    do_client = ClientMock({})
    graph = prepare_graph(do_client)

    team_node = graph.search_first("urn", "do:team:test_team")
    assert team_node.name == "test_team"
    assert team_node.urn == "do:team:test_team"
    assert team_node.id == "test_team"


def test_collect_regions() -> None:

    do_client = ClientMock({"list_regions": regions, "list_droplets": droplets})

    graph = prepare_graph(do_client)

    check_edges(graph, "do:team:test_team", "do:region:fra1")
    check_edges(graph, "do:region:fra1", "do:droplet:289110074")

    # region nyc1 should not be in the graph since it has no resources in it
    assert graph.search_first("urn", "do:region:nyc1") is None

    region = graph.search_first("urn", "do:region:fra1")
    assert region.name == "Frankfurt 1"
    assert region.id == "fra1"
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
    droplet_sizes: List[str] = regions[1]["sizes"]
    assert set(region.do_region_droplet_sizes) == set(droplet_sizes)
    assert region.is_available is True


def test_collect_vpcs() -> None:
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_vpcs": vpcs,
        }
    )
    graph = prepare_graph(do_client)

    check_edges(graph, "do:region:fra1", "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959")
    vpc = graph.search_first("urn", "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959")
    assert vpc.urn == "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959"
    assert vpc.name == "default-fra1"
    assert vpc.description == ""
    assert vpc.ip_range == "127.0.0.1/20"
    assert vpc.is_default is True


def test_collect_droplets() -> None:
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_droplets": droplets,
            "list_vpcs": vpcs,
            "list_tags": tags,
        }
    )
    graph = prepare_graph(do_client)

    check_edges(graph, "do:region:fra1", "do:droplet:289110074")
    check_edges(graph, "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959", "do:droplet:289110074")
    check_edges(
        graph,
        "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959",
        "do:droplet:289110074",
        delete=True,
    )
    check_edges(graph, "do:image:101111514", "do:droplet:289110074")
    check_edges(graph, "do:size:s-1vcpu-1gb", "do:droplet:289110074")
    check_edges(graph, "do:tag:image_tag", "do:image:101111514")
    check_edges(graph, "do:tag:droplet_tag", "do:droplet:289110074")
    image = graph.search_first("urn", "do:image:101111514")
    assert image.urn == "do:image:101111514"
    assert image.name == "20.04 (LTS) x64"
    assert image.distribution == "Ubuntu"
    assert image.image_slug == "ubuntu-20-04-x64"
    assert image.is_public is True
    assert image.image_type == "base"
    assert image.size_gigabytes == 1
    assert image.min_disk_size == 15
    assert image.image_status == "available"
    assert image.tags == {"image_tag": None}

    size = cast(DigitalOceanDropletSize, graph.search_first("urn", "do:size:s-1vcpu-1gb"))
    assert size.urn == "do:size:s-1vcpu-1gb"
    assert size.instance_type == "s-1vcpu-1gb"
    assert size.instance_cores == 1
    assert size.instance_memory == 1
    assert size.ondemand_cost == 0.00744

    droplet = graph.search_first("urn", "do:droplet:289110074")
    assert droplet.urn == "do:droplet:289110074"
    assert droplet.name == "ubuntu-s-1vcpu-1gb-fra1-01"
    assert droplet.instance_memory == 1
    assert droplet.instance_cores == 1
    assert droplet.instance_status == InstanceStatus.RUNNING
    assert droplet.region().urn == "do:region:fra1"
    assert droplet.droplet_image == "ubuntu-20-04-x64"
    assert droplet.droplet_backup_ids == ["42"]
    assert droplet.is_locked is False
    assert droplet.ctime == datetime.datetime(2022, 3, 3, 16, 26, 55, tzinfo=datetime.timezone.utc)
    assert droplet.tags == {"droplet_tag": None}


def test_collect_volumes() -> None:
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_droplets": droplets,
            "list_volumes": volumes,
            "list_tags": tags,
        }
    )
    graph = prepare_graph(do_client)

    check_edges(graph, "do:droplet:289110074", "do:volume:631f81d2-9fc1-11ec-800c-0a58ac14d197")
    check_edges(graph, "do:tag:volume_tag", "do:volume:631f81d2-9fc1-11ec-800c-0a58ac14d197")
    volume = cast(DigitalOceanVolume, graph.search_first("urn", "do:volume:631f81d2-9fc1-11ec-800c-0a58ac14d197"))
    assert volume.urn == "do:volume:631f81d2-9fc1-11ec-800c-0a58ac14d197"
    assert volume.name == "volume-fra1-01"
    assert volume.description == "Test volume"
    assert volume.filesystem_type == "ext4"
    assert volume.filesystem_label == "label"
    assert volume.volume_size == 1
    assert volume.volume_status == VolumeStatus.IN_USE
    assert volume.ondemand_cost == 0.000149


def test_collect_database() -> None:
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_databases": databases,
            "list_vpcs": vpcs,
            "list_tags": tags,
        }
    )
    graph = prepare_graph(do_client)

    check_edges(
        graph,
        "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959",
        "do:dbaas:2848a998-e151-4d5a-9813-0904a44c2397",
    )
    check_edges(
        graph,
        "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959",
        "do:dbaas:2848a998-e151-4d5a-9813-0904a44c2397",
        delete=True,
    )
    check_edges(graph, "do:tag:database_tag", "do:dbaas:2848a998-e151-4d5a-9813-0904a44c2397")
    database = graph.search_first("urn", "do:dbaas:2848a998-e151-4d5a-9813-0904a44c2397")
    assert database.urn == "do:dbaas:2848a998-e151-4d5a-9813-0904a44c2397"
    assert database.name == "do:dbaas:db-postgresql-fra1-82725"
    assert database.db_type == "pg"
    assert database.db_status == "online"
    assert database.db_version == "14"
    assert database.db_endpoint == "host.b.db.ondigitalocean.com"
    assert database.region().urn == "do:region:fra1"
    assert database.instance_type == "db-s-1vcpu-1gb"


def test_collect_k8s_clusters() -> None:
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
        "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959",
        "do:kubernetes:e1c48631-b382-4001-2168-c47c54795a26",
        delete=True,
    )
    check_edges(
        graph,
        "do:kubernetes:e1c48631-b382-4001-2168-c47c54795a26",
        "do:droplet:290075243",
    )

    cluster = graph.search_first("urn", "do:kubernetes:e1c48631-b382-4001-2168-c47c54795a26")
    assert cluster.urn == "do:kubernetes:e1c48631-b382-4001-2168-c47c54795a26"
    assert cluster.name == "k8s-1-22-7-do-0-fra1-test"
    assert cluster.k8s_version == "1.22.7-do.0"
    assert cluster.region().urn == "do:region:fra1"
    assert cluster.k8s_cluster_subnet == "10.244.0.0/16"
    assert cluster.k8s_service_subnet == "10.245.0.0/16"
    assert cluster.ipv4_address == "127.0.0.1"
    assert cluster.endpoint == "https://e1c48631-b382-4001-2168-c47c54795a26.k8s.ondigitalocean.com"
    assert cluster.auto_upgrade_enabled is False
    assert cluster.cluster_status == "running"
    assert cluster.surge_upgrade_enabled is True
    assert cluster.registry_enabled is False
    assert cluster.ha_enabled is False


def test_collect_snapshots() -> None:
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_droplets": droplets,
            "list_snapshots": snapshots,
            "list_tags": tags,
        }
    )
    graph = prepare_graph(do_client)

    check_edges(graph, "do:droplet:289110074", "do:snapshot:103198134")
    check_edges(graph, "do:tag:snapshot_tag", "do:snapshot:103198134")
    snapshot = graph.search_first("urn", "do:snapshot:103198134")
    assert snapshot.urn == "do:snapshot:103198134"
    assert snapshot.volume_size == 25
    assert snapshot.snapshot_size_gigabytes == 2
    assert snapshot.resource_id == "289110074"
    assert snapshot.resource_type == "droplet"


def test_collect_loadbalancers() -> None:
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
        "do:vpc:0d3176ad-41e0-4021-b831-0c5c45c60959",
        "do:loadbalancer:9625f517-75f0-4af8-a336-62374e68dc0d",
        delete=True,
    )
    check_edges(
        graph,
        "do:loadbalancer:9625f517-75f0-4af8-a336-62374e68dc0d",
        "do:droplet:289110074",
    )
    lb = graph.search_first("urn", "do:loadbalancer:9625f517-75f0-4af8-a336-62374e68dc0d")
    assert lb.urn == "do:loadbalancer:9625f517-75f0-4af8-a336-62374e68dc0d"
    assert lb.name == "fra1-load-balancer-01"
    assert lb.public_ip_address == "127.0.0.1"
    assert lb.nr_nodes == 1
    assert lb.loadbalancer_status == "new"
    assert lb.redirect_http_to_https is False
    assert lb.enable_proxy_protocol is False
    assert lb.enable_backend_keepalive is False
    assert lb.disable_lets_encrypt_dns_records is False


def test_collect_floating_ips() -> None:
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_floating_ips": floating_ips,
            "list_droplets": droplets,
        }
    )
    graph = prepare_graph(do_client)
    check_edges(graph, "do:droplet:289110074", "do:floatingip:127.0.0.1")
    floating_ip = graph.search_first("urn", "do:floatingip:127.0.0.1")
    assert floating_ip.urn == "do:floatingip:127.0.0.1"
    assert floating_ip.ip_address == "127.0.0.1"
    assert floating_ip.ip_address_family == "ipv4"
    assert floating_ip.is_locked is False


def test_collect_projects() -> None:
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
    check_edges(graph, "do:project:75088298-73bd-4c8f-ba4b-91fc220d0ac7", "do:droplet:289110074")
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
    project = graph.search_first("urn", "do:project:75088298-73bd-4c8f-ba4b-91fc220d0ac7")
    assert project.owner_uuid == "d63ae7cb6500140c46fdb3585b0c1a874e195760"
    assert project.owner_id == "10225075"
    assert project.name == "Resoto DO plugin test project"
    assert project.description == "A project to validate assumptions about how API works"
    assert project.purpose == "Just trying out DigitalOcean"
    assert project.environment == "development"
    assert project.is_default is False
    assert project.ctime == datetime.datetime(2022, 2, 22, 11, 21, 30, 0, datetime.timezone.utc)


def test_collect_space() -> None:
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_spaces": spaces,
        }
    )
    graph = prepare_graph(do_client)
    check_edges(graph, "do:region:fra1", "do:space:api-test-space.resoto")
    space = graph.search_first("urn", "do:space:api-test-space.resoto")
    assert space.urn == "do:space:api-test-space.resoto"
    assert space.name == "api-test-space.resoto"
    assert space.ctime == datetime.datetime(2022, 2, 23, 13, 42, 21, 455000, datetime.timezone.utc)


def test_collect_apps() -> None:
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_apps": apps,
            "list_databases": databases,
        }
    )
    graph = prepare_graph(do_client)
    check_edges(graph, "do:region:fra1", "do:app:5dc41512-7523-4eeb-9932-426aa570234b")
    check_edges(
        graph,
        "do:dbaas:2848a998-e151-4d5a-9813-0904a44c2397",
        "do:app:5dc41512-7523-4eeb-9932-426aa570234b",
    )
    app = graph.search_first("urn", "do:app:5dc41512-7523-4eeb-9932-426aa570234b")
    assert app.urn == "do:app:5dc41512-7523-4eeb-9932-426aa570234b"
    assert app.default_ingress == "https://resoto_test_app.ondigitalocean.app"
    assert app.live_url == "https://resoto_test_app.ondigitalocean.app"
    assert app.live_url_base == "https://resoto_test_app.ondigitalocean.app"
    assert app.live_domain == "resoto_test_apps.ondigitalocean.app"


def test_cdn_endpoints() -> None:
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_cdn_endpoints": cdn_endpoints,
        }
    )
    graph = prepare_graph(do_client)
    check_edges(
        graph,
        "do:team:test_team",
        "do:cdn_endpoint:4edbbc3a-79a5-4950-b2d2-ae8f8f8e8e8c",
    )
    endpoint = graph.search_first("urn", "do:cdn_endpoint:4edbbc3a-79a5-4950-b2d2-ae8f8f8e8e8c")
    assert endpoint.urn == "do:cdn_endpoint:4edbbc3a-79a5-4950-b2d2-ae8f8f8e8e8c"
    assert endpoint.origin == "resoto_test.ams3.digitaloceanspaces.com"
    assert endpoint.endpoint == "resoto_test.ams3.cdn.digitaloceanspaces.com"
    assert endpoint.ctime == datetime.datetime(2021, 11, 16, 16, 00, 44, 0, datetime.timezone.utc)
    assert endpoint.certificate_id == "429199eb-e6c6-4ab3-bad6-f8f8f8f8f8f8"
    assert endpoint.custom_domain == "test.domain.resoto"
    assert endpoint.ttl == 3600


def test_collect_certificates() -> None:
    do_client = ClientMock({"list_regions": regions, "list_certificates": certificates})
    graph = prepare_graph(do_client)
    check_edges(
        graph,
        "do:team:test_team",
        "do:certificate:429199eb-7137-4e2b-a15e-f74700173e3c",
    )
    cert = graph.search_first("urn", "do:certificate:429199eb-7137-4e2b-a15e-f74700173e3c")
    assert cert.urn == "do:certificate:429199eb-7137-4e2b-a15e-f74700173e3c"
    assert cert.name == "cdn.resoto.test"
    assert cert.sha1_fingerprint == "5909e5e05bbce0c63c2e2523542f74700173e3c2"
    assert cert.dns_names == ["*.resoto.test", "resoto.test"]
    assert cert.certificate_state == "verified"
    assert cert.certificate_type == "custom"


def test_collect_container_registries() -> None:
    do_client = ClientMock(
        {
            "list_regions": regions,
            "get_registry_info": registry,
            "list_registry_repositories": registry_repositories,
            "list_registry_repository_tags": registry_repository_tags,
        }
    )
    graph = prepare_graph(do_client)
    check_edges(graph, "do:region:fra1", "do:cr:resoto-do-plugin-test")
    container_registry = graph.search_first("urn", "do:cr:resoto-do-plugin-test")
    assert container_registry.urn == "do:cr:resoto-do-plugin-test"
    assert container_registry.name == "resoto-do-plugin-test"
    assert container_registry.storage_usage_bytes == 6144
    assert container_registry.is_read_only is False

    check_edges(graph, "do:cr:resoto-do-plugin-test", "do:crr:resoto-do-plugin-test/hw")
    container_registry_repository = graph.search_first("urn", "do:crr:resoto-do-plugin-test/hw")
    assert container_registry_repository.urn == "do:crr:resoto-do-plugin-test/hw"
    assert container_registry_repository.name == "hw"
    assert container_registry_repository.tag_count == 1
    assert container_registry_repository.manifest_count == 1

    check_edges(
        graph,
        "do:crr:resoto-do-plugin-test/hw",
        "do:crrt:resoto-do-plugin-test/hw:latest",
    )
    check_edges(graph, "do:cr:resoto-do-plugin-test", "do:crrt:resoto-do-plugin-test/hw:latest")
    tag = graph.search_first("urn", "do:crrt:resoto-do-plugin-test/hw:latest")
    assert tag.urn == "do:crrt:resoto-do-plugin-test/hw:latest"
    assert tag.name == "latest"
    assert tag.manifest_digest == "sha256:2ce85c6b306674dcab6eae5fda252037d58f78b0e1bbd41aabf95de6cd7e4a9e"
    assert tag.compressed_size_bytes == 5164
    assert tag.size_bytes == 12660
    assert tag.mtime == datetime.datetime(2022, 3, 14, 13, 32, 40, 0, datetime.timezone.utc)


def test_collect_ssh_keys() -> None:
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_ssh_keys": ssh_keys,
        }
    )
    graph = prepare_graph(do_client)
    check_edges(graph, "do:team:test_team", "do:ssh_key:289794")
    ssh_key = graph.search_first("urn", "do:ssh_key:289794")
    assert ssh_key.urn == "do:ssh_key:289794"
    assert ssh_key.fingerprint == "3b:16:e4:bf:8b:00:8b:b8:59:8c:a9:d3:f0:19:fa:45"
    assert ssh_key.name == "Other Public Key"
    assert ssh_key.public_key == "ssh-rsa publickey keycomment"


def test_collect_tags() -> None:
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_tags": tags,
        }
    )
    graph = prepare_graph(do_client)
    tag = graph.search_first("urn", "do:tag:droplet_tag")
    assert tag.urn == "do:tag:droplet_tag"


def test_collect_domains() -> None:
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_domains": domains,
            "list_domain_records": domain_records,
        }
    )
    graph = prepare_graph(do_client)
    check_edges(graph, "do:team:test_team", "do:domain:do-plugin-test.resoto")
    domain = graph.search_first("urn", "do:domain:do-plugin-test.resoto")
    assert domain.ttl == 1800
    assert domain.zone_file == "$ORIGIN do-plugin-test.resoto."

    check_edges(graph, "do:domain:do-plugin-test.resoto", "do:domain_record:300035870")
    check_edges(graph, "do:domain:do-plugin-test.resoto", "do:domain_record:300035871")
    check_edges(graph, "do:domain:do-plugin-test.resoto", "do:domain_record:300035872")
    check_edges(graph, "do:domain:do-plugin-test.resoto", "do:domain_record:300035874")
    check_edges(graph, "do:domain:do-plugin-test.resoto", "do:domain_record:300036132")
    domain_record = graph.search_first("urn", "do:domain_record:300035870")
    assert domain_record.urn == "do:domain_record:300035870"
    assert domain_record.name == "@"
    assert domain_record.record_type == "SOA"
    assert domain_record.record_data == "1800"
    assert domain_record.record_priority is None
    assert domain_record.record_port is None
    assert domain_record.record_ttl == 1800
    assert domain_record.record_weight is None
    assert domain_record.record_flags is None
    assert domain_record.record_tag is None


def test_collect_firewalls() -> None:
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_firewalls": firewalls,
            "list_droplets": droplets,
            "list_tags": tags,
        }
    )
    graph = prepare_graph(do_client)
    check_edges(graph, "do:tag:firewall_tag", "do:firewall:fe2e76df-3e15-4895-800f-2d5b3b807711")
    check_edges(
        graph,
        "do:firewall:fe2e76df-3e15-4895-800f-2d5b3b807711",
        "do:droplet:289110074",
    )
    firewall = graph.search_first("urn", "do:firewall:fe2e76df-3e15-4895-800f-2d5b3b807711")
    assert firewall.firewall_status == "succeeded"
    assert firewall.ctime == datetime.datetime(2022, 3, 10, 13, 10, 50, 0, datetime.timezone.utc)


def test_alert_policies() -> None:
    do_client = ClientMock(
        {
            "list_regions": regions,
            "list_alert_policies": alerts,
        }
    )
    graph = prepare_graph(do_client)
    check_edges(
        graph,
        "do:team:test_team",
        "do:alert:d916cb34-6ee3-48c0-bca5-3f3cc08db5d3",
    )
    alert_policy = graph.search_first("urn", "do:alert:d916cb34-6ee3-48c0-bca5-3f3cc08db5d3")
    assert alert_policy.policy_type == "v1/insights/droplet/cpu"
    assert alert_policy.description == "CPU is running high"
    assert alert_policy.is_enabled is True
