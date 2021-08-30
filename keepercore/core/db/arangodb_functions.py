from ipaddress import IPv4Network

from arango.typings import Json

from core.db.model import QueryModel
from core.query.model import FunctionTerm


def has_desired_change(cursor: str, fn: FunctionTerm) -> str:
    return (
        f"{cursor}.desired.{fn.property_path}!=null && "
        + f"{cursor}.reported.{fn.property_path}!={cursor}.desired.{fn.property_path}"
    )


def in_subnet(cursor: str, bind_vars: Json, fn: FunctionTerm, model: QueryModel) -> str:
    """
    Assumptions and requirements:
    - this fn only works for IPv4 addresses
    - ip addresses are stored as 4 octet with digit string in the reported section
    - one argument is given which defines the ip/mask
    :param cursor: the cursor to read from
    :param bind_vars: the bind_vars to send to arango
    :param fn: the function definition
    :param model: the related query model.
    :return: the AQL filter statement
    """
    if len(fn.args) != 1:
        raise AttributeError("Function in_subnet expects exactly one argument. Example: 1.2.3.4/24")
    network = IPv4Network(fn.args[0], strict=False)
    mask = int(network.netmask)
    expected = int(network.network_address) & mask
    length = str(len(bind_vars))
    bind_vars[length] = expected
    section_dot = f"{model.query_section}." if model.query_section else ""
    return f"BIT_AND(IPV4_TO_NUMBER({cursor}.{section_dot}{fn.property_path}), {mask}) == @{length}"


def as_arangodb_function(cursor: str, bind_vars: Json, fn: FunctionTerm, model: QueryModel) -> str:
    if fn.fn == "in_subnet":
        return in_subnet(cursor, bind_vars, fn, model)
    if fn.fn == "has_desired_change":
        return has_desired_change(cursor, fn)
    else:
        raise AttributeError(f"Function {fn} does not exist!")
