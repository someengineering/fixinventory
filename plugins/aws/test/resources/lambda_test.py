from resoto_plugin_aws.resource.lambda_ import AwsLambdaFunction
from test.resources import round_trip_for


def test_lambda() -> None:
    first, graph = round_trip_for(AwsLambdaFunction)
    assert len(graph.resources_of(AwsLambdaFunction)) == 2
