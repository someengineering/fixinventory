# resoto-plugin-cleanup_aws_vpcs
AWS VPC Cleanup Plugin for resoto

This plugin marks all VPC dependencies for cleanup. The VPC must have been previously marked for cleanup by another cleanup plugin.

The following resources are currently being marked for cleanup
* AWS VPC Peering Connections
* AWS EC2 Network ACLs
* AWS EC2 Network Interfaces
* AWS ELB
* AWS ALB
* AWS ALB Target Groups
* AWS EC2 Subnets
* AWS EC2 Security Groups
* AWS EC2 Internet Gateways
* AWS EC2 NAT Gateways
* AWS EC2 Route Tables

## Usage
Turn on general cleanup using the `--cleanup` argument and activate this plugin by adding `--cleanup-aws-vpcs`.
```
$ resoto -v --cleanup --cleanup-aws-vpcs
```

Instead of targeting all VPCs that have been marked for cleanup the plugin supports a config file syntax for whitelisting individual accounts.
```
$ resoto -v --cleanup --cleanup-aws-vpcs --cleanup-aws-vpcs-config cleanup_aws_vpcs.yaml
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
  --cleanup-aws-vpcs    Cleanup AWS VPCs (default: False)
  --cleanup-aws-vpcs-config CLEANUP_AWS_VPCS_CONFIG
                        Path to Cleanup AWS VPCs Plugin Config
```
