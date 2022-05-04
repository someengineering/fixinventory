# resoto-plugin-cleanup-aws-alarms
AWS Cloudwatch Alarms Cleanup Plugin for Resoto

This plugin marks all orphaned AWS CloudWatch Instance Alarms for cleanup.

The following resources are currently being marked for cleanup

- Instance Alarms

## Usage

In `resh` execute

```
> config edit resoto.worker
```

and find the following section

```
plugin_cleanup_aws_alarms:
  # Dictionary of key cloud with list of account IDs for which the plugin should be active as value
  config:
    aws:
      - '1234567'
      - '567890'
  # Enable plugin?
  enabled: false
```
