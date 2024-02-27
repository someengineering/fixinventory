from fix_plugin_aws.resource.config import AwsConfigRecorder
from test.resources import round_trip_for


def test_config_recorders() -> None:
    round_trip_for(AwsConfigRecorder)
