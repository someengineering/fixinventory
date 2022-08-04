from resoto_plugin_aws.resource.sqs import AwsSqsQueue
from test.resources import round_trip_for


def test_queues() -> None:
    first, builder = round_trip_for(AwsSqsQueue)
    assert len(builder.resources_of(AwsSqsQueue)) == 1
