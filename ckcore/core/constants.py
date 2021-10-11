# key: operation, value: reverse operation
# note: the reverse operation is not the negated operation
# (negation of < would be >=)
less_greater_then_operations = {
    "<": ">",
    "<=": ">=",
    ">": "<",
    ">=": "<=",
}

# Attribute whitelist to show in text/plain mode.
# This is a biased set of attributes - we probably need something more clever.
plain_text_whitelist = [
    ["reported"],
    ["desired", "clean"],
    ["metadata", "protected"],
    ["metadata", "ancestors"],
    ["kinds"],
]
