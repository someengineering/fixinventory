from ipaddress import IPv4Network

from arango.typings import Json

from resotocore.db.model import QueryModel
from resotocore.query.model import FunctionTerm


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
    return f"BIT_AND(IPV4_TO_NUMBER({cursor}.{fn.property_path}), {mask}) == @{length}"


def has_key(cursor: str, bind_vars: Json, fn: FunctionTerm, model: QueryModel) -> str:
    assert (
        len(fn.args) == 1
    ), "has_key(path.to.property, name_of_prop) or has_key(path.to.property, [name_of_prop_a, name_of_prop_b])"
    args = [fn.args[0]] if isinstance(fn.args[0], str) else fn.args[0]
    for arg in args:
        assert isinstance(arg, str), f"has_key: argument must be string, but got: {arg}"
    prop = f"fn{len(bind_vars)}"
    if len(args) == 0:
        return "true"
    elif len(args) == 1:
        bind_vars[prop] = fn.args[0]
        return f"HAS({cursor}.{fn.property_path}, @{prop})"
    else:
        bind_vars[prop] = args
        return f"@{prop} ALL IN ATTRIBUTES({cursor}.{fn.property_path}, true)"


def as_arangodb_function(cursor: str, bind_vars: Json, fn: FunctionTerm, model: QueryModel) -> str:
    if fn.fn == "has_key":
        return has_key(cursor, bind_vars, fn, model)
    if fn.fn == "in_subnet":
        return in_subnet(cursor, bind_vars, fn, model)
    if fn.fn == "has_desired_change":
        return has_desired_change(cursor, fn)
    else:
        raise AttributeError(f"Function {fn} does not exist!")
