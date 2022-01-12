# resoto-plugin-cleanup_aws_alarms
AWS Cloudwatch Alarms Cleanup Plugin for resoto

This plugin marks all orphaned Cloudwatch Alarms for cleanup.

The following resources are currently being marked for cleanup
* Instance Alarms

## Usage
Turn on general cleanup using the `--cleanup` argument and activate this plugin by adding `--cleanup-aws-alarms`.
```
$ resoto -v --cleanup --cleanup-aws-alarms
```

Instead of targeting all VPCs that have been marked for cleanup the plugin supports a config file syntax for whitelisting individual accounts.
```
$ resoto -v --cleanup --cleanup-aws-alarms --cleanup-aws-alarms-config cleanup_aws_alarms.yaml
```

The config file is a dict with a cloud ID as key and a list of account IDs as value.
```
'aws':
  - '337834004759'
  - '999867407951'
  - '327650738955'
  - '068564737731'
  - '711585860468'
```

## List of arguments
```
  --cleanup-aws-alarms  Cleanup AWS Cloudwatch Alarms (default: False)
  --cleanup-aws-alarms-config CLEANUP_AWS_ALARMS_CONFIG
                        Path to Cleanup AWS Cloudwatch Alarms Plugin Config
```
