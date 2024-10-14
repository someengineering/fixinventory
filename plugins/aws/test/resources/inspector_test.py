from fix_plugin_aws.resource.inspector import (
    AwsInspectorV2Finding,
    AwsInspectorV2CisScan,
    AwsInspectorV2CisScanConfiguration,
    AwsInspectorV2Coverage,
    AwsInspectorV2Filter,
)
from test.resources import round_trip_for


def test_inspector_v2_findings() -> None:
    round_trip_for(AwsInspectorV2Finding)


def test_inspector_v2_cis_scans() -> None:
    round_trip_for(AwsInspectorV2CisScan)


def test_inspector_v2_cis_scan_configurations() -> None:
    round_trip_for(AwsInspectorV2CisScanConfiguration)


def test_inspector_v2_coverages() -> None:
    round_trip_for(AwsInspectorV2Coverage)


def test_inspector_v2_filters() -> None:
    round_trip_for(AwsInspectorV2Filter)
