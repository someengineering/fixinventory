import os
from yaml import safe_dump
from fix_plugin_aws.collector import called_collect_apis, called_mutator_apis
from fix_plugin_aws.resource.base import AwsApiSpec


org_list_policy = {
    "PolicyName": "FixOrgList",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "organizations:ListAccounts",
                    "organizations:DescribeAccount",
                    "ec2:DescribeRegions",
                    "iam:ListAccountAliases",
                ],
            }
        ],
    },
}


pricing_list_policy = {
    "PolicyName": "FixPricingList",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "pricing:DescribeServices",
                    "pricing:GetAttributeValues",
                    "pricing:GetProducts",
                ],
            }
        ],
    },
}


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
        collect_policy = iam_statement("FixCollect", called_collect_apis())
        policies.append(collect_policy)
    if mutate:
        mutate_policy = iam_statement("FixMutate", called_mutator_apis())
        policies.append(mutate_policy)
    return policies


def get_cf_template() -> str:
    local_path = os.path.abspath(os.path.dirname(__file__))
    template_path = os.path.join(local_path, "templates/fixinventory-role.template.in")
    with open(template_path, "r") as f:
        template = f.readlines()

    if not template[-1].endswith("\n"):
        template[-1] += "\n"

    indent_by = len(template[-1]) - len(template[-1].lstrip())

    policies = safe_dump(get_policies(collect=False, pricing_list=True), sort_keys=False)
    policies = "\n".join(" " * indent_by + line for line in policies.splitlines())

    return "".join(template) + policies + "\n"
