less_greater_then_operations = {"<", "<=", ">", ">="}

# Attribute whitelist to show in text/plain mode.
# This is a biased set of attributes - we probably need something more clever.
plain_text_whitelist = [
    ["reported"],
    ["desired", "clean"],
    ["metadata", "protected"],
    ["metadata", "ancestors"],
    ["kinds"],
]
