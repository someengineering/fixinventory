# resoto-plugin-cleanup_aws_loadbalancers
AWS Loadbalancers Cleanup Plugin for resoto

This plugin cleans up AWS ALB/ELB load balancers with no instances attached to them.

## Usage
Turn on general cleanup using the `--cleanup` argument and activate this plugin by adding `--cleanup-aws-loadbalancers`.
```
$ resoto -v --cleanup --cleanup-aws-loadbalancers
```

The default load balancer age is 7 days. Meaning if a load balancer is more than 7 days old and does not have any instances/backends
attached it will be deleted.

Optionally change the age cutoff value using the `--cleanup-aws-loadbalancers-age` argument.

The following age units are valid:
```
weeks
days
hours
minutes
```

Each of them can be abbreviated down to one letter. E.g. `7d`, `24h`, `60m`, etc. A space in between the numeric and the unit is optional,
meaning `7d` and `7 days` are equivalent.

### Example:
```
$ resoto -v --cleanup --cleanup-aws-loadbalancers --cleanup-aws-loadbalancers-age 2d
```

## List of arguments
```
  --cleanup-aws-loadbalancers
                        Cleanup unused AWS Loadbalancers (default: False)
  --cleanup-aws-loadbalancers-age CLEANUP_AWS_LOADBALANCERS_AGE
                        Cleanup unused AWS Loadbalancers Age (default: 7 days)
```
