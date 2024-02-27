from typing import List, Dict, Any
from fix_plugin_gcp.collector import called_collect_apis, called_mutator_apis
from fix_plugin_gcp.gcp_client import GcpApiSpec


def get_policies(collect: bool = True, mutate: bool = True) -> None:
    def iam_role_for(name: str, description: str, calls: List[GcpApiSpec]) -> Dict[str, Any]:
        permissions = sorted({p for api in calls for p in api.iam_permissions})
        result = {"title": name, "description": description, "stage": "GA", "includedPermissions": permissions}
        return result

    policies = []
    if collect:
        c = iam_role_for("fix_access", "Permissions required to collect resources.", called_collect_apis())
        policies.append(c)
    if mutate:
        m = iam_role_for("fix_mutate", "Permissions required to mutate resources.", called_mutator_apis())
        policies.append(m)
    return policies
