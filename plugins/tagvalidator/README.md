# cloudkeeper-plugin-tagvalidator
Tag Validator plugin for Cloudkeeper

This plugin validates the contents of expiration tags. With it you can enforce a max. expiration length
for certain resources in an account. For instance you could have an org policy that says in our "dev" account
compute instances are only allowed to exist for 2 days max. Then this plugin can ensure that the expiration tag
on those instances is set to no more than 2 days. If it is set to e.g. 50h it would be corrected down to 48h.

This in combination with a cleanup job can be used to enforce such an expiration rule org wide.
```
add_job cleanup_plan: query metadata.expires < @NOW@ | clean "Resource is expired"
```

## Usage
Create a YAML file
```
default:
    expiration: 24h

kinds:
    - aws_ec2_instance
    - aws_vpc
    - aws_cloudformation_stack
    - aws_elb
    - aws_alb
    - aws_alb_target_group
    - aws_eks_cluster
    - aws_eks_nodegroup
    - aws_ec2_nat_gateway

accounts:
    aws:
        '123465706934':
            name: 'eng-audit'
        '123479172032':
            name: 'eng-devprod'
        '123453451782':
            name: 'sales-lead-gen'
            expiration: 12h
        '123415487488':
            name: 'sales-hosted-lead-gen'
            expiration: 8d
```

Provide the path to that file to the `--tagvalidator-config` argument.
```
$ cloudkeeper -v --tagvalidator-config /var/local/cloudkeeper/config/tagvalidator.ini
```

## Structure of the config file
The config contains a default section with the expiration that should be used for all accounts by default.
The kinds section contains the list of kinds that these expiration tag rules apply to.
The accounts section contain the cloud ids followed by the account ids. Each account id must contain a `name`
and optionaly an `expiration` that overwrites the global default.


## List of arguments
```
  --tagvalidator-config TAGVALIDATOR_CONFIG
                        Path to Tag Validator Config
  --tagvalidator-dry-run
                        Tag Validator Dry Run
```
