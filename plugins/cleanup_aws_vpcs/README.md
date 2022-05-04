# resoto-plugin-cleanup-aws-vpcs
AWS VPC Cleanup Plugin for Resoto

This plugin marks all VPC dependencies for cleanup. The VPC must have been previously marked for cleanup by another cleanup plugin.

The following resources are currently being marked for cleanup

- AWS VPC Peering Connections
- AWS EC2 Network ACLs
- AWS EC2 Network Interfaces
- AWS ELB
- AWS ALB
- AWS ALB Target Groups
- AWS EC2 Subnets
- AWS EC2 Security Groups
- AWS EC2 Internet Gateways
- AWS EC2 NAT Gateways
- AWS EC2 Route Tables

## Usage

In `resh` execute

```
> config edit resoto.worker
```

and find the following section

```
plugin_cleanup_aws_vpcs:
  # Dictionary of key cloud with list of account IDs for which the plugin should be active as value
  config:
    aws:
      - '1234567'
      - '567890'
  # Enable plugin?
  enabled: false
```
