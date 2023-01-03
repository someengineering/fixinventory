from test.resources import round_trip_for
from resoto_plugin_aws.resource.sagemaker import AwsSagemakerNotebook

def test_notebooks() -> None:
    first, builder = round_trip_for(AwsSagemakerNotebook)
    assert len(builder.resources_of(AwsSagemakerNotebook)) == 1
    # assert len(first.tags) == 1
