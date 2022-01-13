# resoto-plugin-protect_snowflakes
Protect Snowflakes Plugin for Resoto

This plugin protects snowflake resources from deletion by Resoto by burning a resources protection fuse.

## Usage
Create a yaml config file.
```
# Format:
# cloud.id:
#   account.id:
#     region.id:
#       kind:
#         - resource.id
'aws':
  '110465657741':
    'us-east-1':
      'aws_ec2_instance':
        - 'i-0fcbe8974615bfd37'
  '119548413362':
    'us-west-2':
      'aws_ec2_instance':
        - 'i-014d033656486fff4'
        - 'i-0404823aade93ac9d'
        - 'i-04f6f4d85af72b440'
        - 'i-05e3e6bb79d8e1df1'
        - 'i-06f0d5b89c42b5615'
```


Provide the path to a config file via the `--protect-snowflakes-config` argument.
```
$ resotoworker -v --protect-snowflakes-config /var/local/resoto/config/protect_snowflakes.yaml
```

### Implementation details
Each Resoto resource has an attributed `protected` which takes on a boolean value. By default it is set to `False`.
Once set to `True` it can not be changed back to `False` essentially burning a protection fuse.
Each Resoto resource inherits BaseResource which contains two methods for cleaning up a resource, `cleanup()` and `delete()`.
Both those methods will refuse to manipulate a resource under any circumstances once the `protected` attribute has been set to `True`.

## List of arguments
```
  --protect-snowflakes-config PROTECT_SNOWFLAKES_CONFIG
                        Path to Protect Snowflakes Plugin Config
```
