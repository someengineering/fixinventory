import json
from datetime import date, datetime
from resotolib.utils import utc_str

# subclass JSONEncoder
class DateTimeEncoder(json.JSONEncoder):
        #Override the default method
        def default(self, obj):
            if isinstance(obj, (date, datetime)):
                return utc_str(obj)


# 1. paste the boto3 Response Syntax example here
# 2. find and replace '|' with a space or anything that's not a bitwise operator
# 3. run
response = {}


print (json.dumps(response, indent=4, cls=DateTimeEncoder))
