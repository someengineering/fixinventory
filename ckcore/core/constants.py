# key: operation, value: reverse operation
# note: the reverse operation is not the negated operation
# (negation of < would be >=)
from core.model.resolve_in_graph import NodePath

less_greater_then_operations = {
    "<": ">",
    "<=": ">=",
    ">": "<",
    ">=": "<=",
}

# operations that arangodb matches to true, if the value is not existent.
# example foo < 3 would match, if property foo does not exist.
# see: https://www.arangodb.com/docs/stable/aql/fundamentals-type-value-order.html
arangodb_matches_null_ops = {"<", "<=", "not in", "=~"}

# Attribute blacklist to hide in text/plain mode.
plain_text_blacklist = [
    NodePath.node_id,
    NodePath.type,
    NodePath.revision,
    NodePath.kinds,
    NodePath.descendant_count,
    NodePath.descendant_count,
    NodePath.descendant_summary,
    ["metadata", "python_type"],
]
