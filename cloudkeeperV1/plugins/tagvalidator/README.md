# cloudkeeper-plugin-tagvalidator
Tag Validator plugin for Cloudkeeper

This plugin validates the contents and existance of tags.

## Usage
Create a Python configparser style .ini file
```
[ExampleResource]
expiration: 24h
owner: ops

[example account]
cloud: example
account: Example Account
ExampleResource us-east expiration: 8h
```

Provide the path to that file to the `--tagvalidator-config` argument.
```
$ cloudkeeper -v --tagvalidator-config /var/local/cloudkeeper/config/tagvalidator.ini
```

## Structure of the config file
The config file consists of sections starting with a section name in square brackets `[]` followed by a list of `key: value` pairs.
The section name can either be a Cloudkeeper resource class name for which to configure default tag values, or an account name.

By default the plugin tries to parse any tag value to a time delta. This allows the specificatin of values like `24h` or `7 days`.
The plugin assumes that if the desired value is a time delta, it should be the maximum allowed amount of time. This is useful for
`expiration` tags where you can use another plugin like the [cleanup_expired](https://github.com/lloesche/cloudkeeper/tree/dev/plugins/cleanup_expired)
to delete expired resources and use Tag Validator to enforce the existance of an expiration tag as well as upper limits.

If the secion configures an account it must include the `cloud` and `account` keys which must contain the cloud ID and account ID
of the account this section applies to.

Within an account section the global Cloudkeeper resource class defaults can be overridden.
In our example above we say that for a resource class named `ExampleResource` we want to enforce a tag named `expiration` with a
maximum value of `24h` as well as a tag called `owner` with a default value of `ops`.

In the account section for `example account` then we override the `expiration` value to be only `8h` in region `us-east`.

Check out the [example.ini](https://github.com/lloesche/cloudkeeper/blob/dev/plugins/tagvalidator/example.ini) for more examples.

## List of arguments
```
  --tagvalidator-config TAGVALIDATOR_CONFIG
                        Path to Tag Validator Config
  --tagvalidator-dry-run
                        Tag Validator Dry Run
```
