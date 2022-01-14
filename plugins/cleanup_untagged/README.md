# resoto-plugin-cleanup_untagged
Cleanup Untagged Plugin for Resoto

This plugin deletes cloud resources that are missing mandatory tags.

## Usage
Create a yaml config file.
```
default:
    age: 2h

tags:
    - owner
    - expiration

classes:
    - ExampleInstance
    - ExampleNetwork

accounts:
    aws:
        068564737731:
            name: playground
            age: 7d
        575584959047:
            name: eng-sre

    example:
        Example Account:
            name: example_account
```


Turn on general cleanup using the `--cleanup` argument and provide the path to a config file via the `--cleanup-untagged-config` argument.
```
$ resotoworker -v --cleanup --cleanup-untagged-config /var/local/resoto/config/cleanup_untagged.yaml
```

### Config file format

The config file consists of four sections. `default`, `tags`, `classes` and `accounts`.
The `default` section specifies the default `age` a resource must have before we enforce mandatory tags on it. For instance if `age` is set to `2h` this
means that whatever mechanism creates a resource has two hours to add those mandatory tags.

The `tags` section is a list of tag names that MUST exist on every resource class specified in `classes`.
The `classes` section is a list of resource class names for which tags specified in the `tags` list must exist.

The `accounts` section contains a dictionary with cloud IDs as keys (e.g. `aws`) and account IDs for which tag existances will be enforced as values (e.g. `068564737731`).
Those in turn contain a `name` and optionally an `age` override.

The following age units are valid:
```
weeks
days
hours
minutes
```

Each of them can be abbreviated down to one letter. E.g. `7d`, `24h`, `60m`, etc. A space in between the numeric and the unit is optional,
meaning `7d` and `7 days` are equivalent.

## List of arguments
```
  --cleanup-untagged-config CLEANUP_UNTAGGED_CONFIG
                        Path to Cleanup Untagged Plugin Config
```
