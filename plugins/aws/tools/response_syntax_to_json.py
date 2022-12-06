import json
from datetime import date, datetime
from resotolib.utils import utc_str

# subclass JSONEncoder
class DateTimeEncoder(json.JSONEncoder):
        #Override the default method
        def default(self, obj):
            if isinstance(obj, (date, datetime)):
                return utc_str(obj)


#1. paste the boto3 Response Syntax example here
#2. find and replace "'|'"" with a space or something
#3. run

response={
    'FieldLevelEncryptionProfileList': {
        'NextMarker': 'string',
        'MaxItems': 123,
        'Quantity': 123,
        'Items': [
            {
                'Id': 'string',
                'LastModifiedTime': datetime(2015, 1, 1),
                'Name': 'string',
                'EncryptionEntities': {
                    'Quantity': 123,
                    'Items': [
                        {
                            'PublicKeyId': 'string',
                            'ProviderId': 'string',
                            'FieldPatterns': {
                                'Quantity': 123,
                                'Items': [
                                    'string',
                                ]
                            }
                        },
                    ]
                },
                'Comment': 'string'
            },
        ]
    }
}


print (json.dumps(response, indent=4, cls=DateTimeEncoder))
