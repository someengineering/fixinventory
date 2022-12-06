import json
from datetime import datetime

#1. paste the boto3 Response Syntax example here
#2. find and replace '|' with a space
#3. run
response={
    'ContinuousDeploymentPolicyList': {
        'NextMarker': 'string',
        'MaxItems': 123,
        'Quantity': 123,
        'Items': [
            {
                'ContinuousDeploymentPolicy': {
                    'Id': 'string',
                    'LastModifiedTime': datetime(2015, 1, 1),
                    'ContinuousDeploymentPolicyConfig': {
                        'StagingDistributionDnsNames': {
                            'Quantity': 123,
                            'Items': [
                                'string',
                            ]
                        },
                        'Enabled': True|False,
                        'TrafficConfig': {
                            'SingleWeightConfig': {
                                'Weight': 0.5,
                                'SessionStickinessConfig': {
                                    'IdleTTL': 123,
                                    'MaximumTTL': 123
                                }
                            },
                            'SingleHeaderConfig': {
                                'Header': 'string',
                                'Value': 'string'
                            },
                            'Type': 'SingleWeight SingleHeader'
                        }
                    }
                }
            },
        ]
    }
}


print (json.dumps(response, indent=4, default=str))
