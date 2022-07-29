from resoto_plugin_aws.resource.elasticbeanstalk import AwsBeanstalkApplication
from test.resources import round_trip_for


def test_applications() -> None:
    first, builder = round_trip_for(AwsBeanstalkApplication)
    assert len(builder.resources_of(AwsBeanstalkApplication)) == 3
