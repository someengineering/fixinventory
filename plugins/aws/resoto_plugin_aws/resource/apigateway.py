from typing import ClassVar, Dict, Optional, List, Type

from attrs import define, field
from resoto_plugin_aws.aws_client import AwsClient

from resoto_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from resoto_plugin_aws.resource.ec2 import AwsEc2VpcEndpoint
from resotolib.baseresources import ModelReference
from resotolib.json_bender import Bender, S, Bend, bend
from resoto_plugin_aws.utils import ToDict, arn_partition
from resotolib.types import Json


class ApiGatewayTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    service=spec.service,
                    action="tag-resource",
                    result_name=None,
                    resourceArn=self.arn,
                    tags={key: value},
                )
                return True
            return False
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    service=spec.service,
                    action="untag-resource",
                    result_name=None,
                    resourceArn=self.arn,
                    tagKeys=[key],
                )
                return True
            return False
        return False


@define(eq=False, slots=False)
class AwsApiGatewayEndpointConfiguration:
    kind: ClassVar[str] = "aws_api_gateway_endpoint_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "types": S("types", default=[]),
        "vpc_endpoint_ids": S("vpcEndpointIds", default=[])
    }
    types: List[str] = field(factory=list)
    vpc_endpoint_ids: List[str] = field(factory=list)

@define(eq=False, slots=False)
class AwsApiGatewayRestApi(ApiGatewayTaggable, AwsResource):
    kind: ClassVar[str] = "aws_api_gateway_rest_api"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("apigateway", "get-rest-apis", "items")
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["aws_vpc_endpoint"],
            "delete": ["aws_vpc_endpoint"]
        }
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "name": S("name"),
        "tags": S("tags", default=[]),
        "ctime": S("createdDate"),
        "description": S("description"),
        "api_version": S("version"),
        "api_warnings": S("warnings", default=[]),
        "api_binary_media_types": S("binaryMediaTypes", default=[]),
        "api_minimum_compression_size": S("minimumCompressionSize"),
        "api_key_source": S("apiKeySource"),
        "api_endpoint_configuration": S("endpointConfiguration") >> Bend(AwsApiGatewayEndpointConfiguration.mapping),
        "api_policy": S("policy"),
        "api_disable_execute_api_endpoint": S("disableExecuteApiEndpoint")
    }
    description: Optional[str] = field(default=None)
    api_version: Optional[str] = field(default=None)
    api_warnings: List[str] = field(factory=list)
    api_binary_media_types: List[str] = field(factory=list)
    api_minimum_compression_size: Optional[int] = field(default=None)
    api_key_source: Optional[str] = field(default=None)
    api_endpoint_configuration: Optional[AwsApiGatewayEndpointConfiguration] = field(default=None)
    api_policy: Optional[str] = field(default=None)
    api_disable_execute_api_endpoint: Optional[bool] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json:
            instance = cls.from_api(js)
            region = builder.region
            instance.arn = f"arn:{arn_partition(region)}:apigateway:{region.id}::/restapis/{instance.id}"
            builder.add_node(instance, js)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.api_endpoint_configuration:
            for endpoint in self.api_endpoint_configuration.vpc_endpoint_ids:
                builder.dependant_node(
                    self,
                    clazz=AwsEc2VpcEndpoint,
                    delete_same_as_default=True,
                    id=endpoint,
                )

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            service=self.api_spec.service,
            action="delete-rest-api",
            result_name=None,
            restApiId=self.id,
        )
        return True

resources: List[Type[AwsResource]] = [AwsApiGatewayRestApi]
