# resoto-plugin-cleanup-aws-loadbalancers
AWS Loadbalancers Cleanup Plugin for Resoto

This plugin cleans up AWS ALB/ELB load balancers with no instances attached to them.

## Usage

```
plugin_cleanup_aws_loadbalancers:
  # Enable plugin?
  enabled: false
  # Minimum age of unused load balancers to cleanup
  min_age: '7 days'
```

The default load balancer age is 7 days. Meaning if a load balancer is more than 7 days old and does not have any instances/backends attached it will be flagged for cleanup.

Optionally change the age cutoff value using the `min_age` option.

Example of valid age units:

```
weeks
days
hours
minutes
```

Each of them can be abbreviated down to one letter. E.g. `7d`, `24h`, `60m`, etc. A space in between the numeric and the unit is optional, meaning `7d` and `7 days` are equivalent.
