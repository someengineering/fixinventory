import json
import os

from fix_plugin_gcp.resources.base import GraphBuilder
from fix_plugin_gcp.resources.filestore import GcpFilestoreBackup, GcpFilestoreInstance, GcpFilestoreInstanceSnapshot


def test_gcp_filestore_backup(random_builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/filestore_backup.json") as f:
        GcpFilestoreBackup.collect(raw=json.load(f)["backups"], builder=random_builder)

    backups = random_builder.nodes(clazz=GcpFilestoreBackup)
    assert len(backups) == 1


def test_gcp_filestore_instance(random_builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/filestore_instance.json") as f:
        GcpFilestoreInstance.collect(raw=json.load(f)["instances"], builder=random_builder)

    instances = random_builder.nodes(clazz=GcpFilestoreInstance)
    assert len(instances) == 1


def test_gcp_filestore_instance_snapshot(random_builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/filestore_instance_snapshot.json") as f:
        GcpFilestoreInstanceSnapshot.collect(raw=json.load(f)["snapshots"], builder=random_builder)

    snapshots = random_builder.nodes(clazz=GcpFilestoreInstanceSnapshot)
    assert len(snapshots) == 1
