# cloudkeeper-plugin-cleanup_aws_vpcs
AWS VPC Cleanup Plugin for Cloudkeeper

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
$ cloudkeeper -v --cleanup --cleanup-aws-vpcs
```

## List of arguments
```
```
