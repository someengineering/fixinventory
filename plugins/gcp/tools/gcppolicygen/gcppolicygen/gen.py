import os
from yaml import safe_dump
from resoto_plugin_gcp.collector import called_collect_apis, called_mutator_apis
from resoto_plugin_gcp.resource.base import GcpApiSpec


def get_policies(org_list: bool = True, collect: bool = True, mutate: bool = True, pricing_list: bool = False) -> list:
    def iam_statement(name: str, apis: list[AwsApiSpec]) -> tuple[set[str], str]:
        permissions = {api.iam_permission() for api in apis}
        statement = {
            "PolicyName": name,
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Resource": "*", "Action": sorted(permissions)}],
            },
        }
        return statement

    policies = []
    if org_list:
        policies.append(org_list_policy)
    if pricing_list:
        policies.append(pricing_list_policy)
    if collect:
        collect_policy = iam_statement("ResotoCollect", called_collect_apis())
        policies.append(collect_policy)
    if mutate:
        mutate_policy = iam_statement("ResotoMutate", called_mutator_apis())
        policies.append(mutate_policy)
    return policies
