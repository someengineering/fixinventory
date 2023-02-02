from resoto_plugin_aws.collector import called_collect_apis, called_mutator_apis
from resoto_plugin_aws.resource.base import AwsApiSpec


org_list_policy = {
    "PolicyName": "ResotoOrgList",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "organizations:ListAccounts",
                    "ec2:DescribeRegions",
                    "iam:ListAccountAliases",
                ],
            }
        ],
    },
}


def get_policies() -> list:
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

    collect_policy = iam_statement("ResotoCollect", called_collect_apis())
    mutate_policy = iam_statement("ResotoMutate", called_mutator_apis())
    policies = [org_list_policy, collect_policy, mutate_policy]
    return policies
