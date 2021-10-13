# key: operation, value: reverse operation
# note: the reverse operation is not the negated operation
# (negation of < would be >=)
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

# Attribute whitelist to show in text/plain mode.
# This is a biased set of attributes - we probably need something more clever.
plain_text_whitelist = [
    ["reported"],
    ["desired", "clean"],
    ["metadata", "protected"],
    ["metadata", "ancestors"],
    ["kinds"],
]
