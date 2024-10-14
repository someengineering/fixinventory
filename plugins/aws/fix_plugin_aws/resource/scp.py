from fix_plugin_aws.aws_client import AwsClient
from typing import List, Optional
from json import loads as json_loads
from fixlib.types import Json
from logging import getLogger

_expected_errors = ["AccessDeniedException", "AWSOrganizationsNotInUseException"]

logger = getLogger(__name__)


def get_scps(target_id: str, client: AwsClient) -> Optional[List[Json]]:
    policies: List[Json] = client.list(
        "organizations",
        "list_policies_for_target",
        "Policies",
        TargetId=target_id,
        Filter="SERVICE_CONTROL_POLICY",
        expected_errors=_expected_errors,
    )

    if not policies:
        return None

    policy_documents = []

    for policy in policies:
        policy_details = client.get(
            "organizations", "describe_policy", "Policy", PolicyId=policy["Id"], expected_errors=_expected_errors
        )
        if not policy_details:
            continue
        policy_document = json_loads(policy_details["Content"])
        policy_documents.append(policy_document)

    return policy_documents


def find_account_scps(client: AwsClient, account_id: str) -> List[List[Json]]:

    def process_children(parent_id: str, parent_scps: List[List[Json]]) -> List[List[Json]]:
        child_ous = client.list(
            "organizations", "list_organizational_units_for_parent", "OrganizationalUnits", ParentId=parent_id
        )
        for child_ou in child_ous:
            # copy the list to avoid modifying the parent list
            parent_scps = list(parent_scps)
            org_scps = get_scps(child_ou["Id"], client)
            if org_scps:
                parent_scps.append(org_scps)
            accounts = client.list(
                "organizations",
                "list_accounts_for_parent",
                "Accounts",
                ParentId=child_ou["Id"],
                expected_errors=_expected_errors,
            )
            for account in accounts:
                if account["Id"] == account_id:
                    account_scps = get_scps(account_id, client)
                    if account_scps:
                        parent_scps.append(account_scps)
                    return parent_scps

            if result := process_children(child_ou["Id"], list(parent_scps)):
                return result

        return []

    roots = client.list("organizations", "list_roots", "Roots", expected_errors=_expected_errors)
    for root in roots:
        root_id = root["Id"]
        parent_scps = []
        root_scps = get_scps(root_id, client)
        if root_scps:
            parent_scps.append(root_scps)
        accounts = client.list(
            "organizations",
            "list_accounts_for_parent",
            "Accounts",
            ParentId=root_id,
            expected_errors=_expected_errors,
        )
        # if an account is attached to the root, return early
        for account in accounts:
            if account["Id"] == account_id:
                account_scps = get_scps(account_id, client)
                if account_scps:
                    parent_scps.append(account_scps)
                return parent_scps

        if result := process_children(root["Id"], list(parent_scps)):
            return result

    return []


def is_allow_all_scp(scp: Json) -> bool:
    for statement in scp.get("Statement", []):
        if all(
            [
                statement.get("Effect") == "Allow",
                statement.get("Action") == "*",
                statement.get("Resource") == "*",
            ]
        ):
            return True

    return False


def filter_allow_all(levels: List[List[Json]]) -> List[List[Json]]:
    return [[scp for scp in level if not is_allow_all_scp(scp)] for level in levels]


def collect_account_scps(account_id: str, scrape_org_role_arn: Optional[str], client: AwsClient) -> List[List[Json]]:

    try:

        if scrape_org_role_arn:
            scp_client = AwsClient(
                client.config,
                client.account_id,
                role=scrape_org_role_arn,
                profile=client.profile,
                region=client.region,
                partition=client.partition,
                error_accumulator=client.error_accumulator,
            )
        else:
            scp_client = client

        account_scps = find_account_scps(scp_client, account_id)
        account_scps = filter_allow_all(account_scps)
        account_scps = [level for level in account_scps if level]

        return account_scps

    except Exception as e:
        logger.info(f"Error collecting SCPs for account {account_id}", exc_info=e)
        return []
