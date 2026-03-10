import json
import os
from types import SimpleNamespace
from typing import Any

from googleapiclient.errors import HttpError

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


def test_gcp_filestore_instance_snapshot_service_disabled_is_expected(
    random_builder: GraphBuilder, monkeypatch: Any
) -> None:
    error = {
        "error": {
            "code": 403,
            "message": (
                "Cloud Filestore API has not been used in project test-project before or it is disabled. "
                "Enable it by visiting https://console.developers.google.com/apis/api/file.googleapis.com/overview"
            ),
            "status": "PERMISSION_DENIED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "SERVICE_DISABLED",
                    "domain": "googleapis.com",
                    "metadata": {
                        "consumer": "projects/test-project",
                        "service": "file.googleapis.com",
                    },
                }
            ],
        }
    }

    def raise_service_disabled(*_: Any, **__: Any) -> Any:
        raise HttpError(SimpleNamespace(status=403, reason="Forbidden"), json.dumps(error).encode("utf-8"))

    monkeypatch.setattr(random_builder.client, "list", raise_service_disabled)

    instance = GcpFilestoreInstance(id="projects/test-project/locations/us-east1/instances/test-instance")
    instance.post_process(random_builder, {})
    random_builder.executor.wait_for_submitted_work()

    assert random_builder.error_accumulator.regional_errors == {}
