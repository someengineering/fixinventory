# resoto-plugin-cleanup-untagged
Cleanup Untagged Plugin for Resoto

This plugin deletes cloud resources that are missing mandatory tags after a certain amount of time has passed since their creation.

## Usage

In `resh` execute

```
> config edit resoto.worker
```

and find the following section

```
plugin_cleanup_untagged:
  # Configuration for the plugin
  config:
    default:
      age: '2h'
    tags:
      - 'owner'
      - 'expiration'
    kinds:
      - 'aws_ec2_instance'
      - 'aws_ec2_volume'
      - 'aws_vpc'
      - 'aws_cloudformation_stack'
      - 'aws_elb'
      - 'aws_alb'
      - 'aws_alb_target_group'
      - 'aws_eks_cluster'
      - 'aws_eks_nodegroup'
      - 'example_instance'
      - 'example_network'
    accounts:
      aws:
        068564737731:
          name: 'playground'
          age: '7d'
        '575584959047':
          name: 'eng-sre'
      example:
        Example Account:
          name: 'Example Account'
  # Enable plugin?
  enabled: false
```

### Config section format

The config section consists of four sub-sections. `default`, `tags`, `classes` and `accounts`. The `default` section specifies the default `age` a resource must have before we enforce mandatory tags on it. For instance if `age` is set to `2h` this means that whatever mechanism creates a resource has two hours to add those mandatory tags.

The `tags` section is a list of tag names that MUST exist on every resource class specified in `classes`. The `classes` section is a list of resource class names for which tags specified in the `tags` list must exist.

The `accounts` section contains a dictionary with cloud IDs as keys (e.g. `aws`) and account IDs for which tags will be enforced as values (e.g. `068564737731`). Those in turn contain a `name` and optionally an `age` override.

The following age units are valid:

```
weeks
days
hours
minutes
```

Each of them can be abbreviated down to one letter. E.g. `7d`, `24h`, `60m`, etc. A space in between the numeric and the unit is optional, meaning `7d` and `7 days` are equivalent.
