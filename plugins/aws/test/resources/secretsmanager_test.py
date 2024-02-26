from fix_plugin_aws.resource.secretsmanager import AwsSecretsManagerSecret
from test.resources import round_trip_for


def test_notebooks() -> None:
    first, builder = round_trip_for(AwsSecretsManagerSecret)
    assert len(builder.resources_of(AwsSecretsManagerSecret)) == 3
