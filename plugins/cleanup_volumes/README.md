# resoto-plugin-cleanup_volumes
Volume cleanup plugin for Resoto

This plugin removes unused EBS volumes.

## Usage
Turn on general cleanup using the `--cleanup` argument and activate this plugin by adding `--cleanup-volumes`.
```
$ resotoworker -v --cleanup --cleanup-volumes
```

The default volume age is 14 days. Meaning if a volume is not in use and has not had any read or write IOPS within
the last 14 days it will be deleted.

Optionally change the age cutoff value using the `--cleanup-volumes-age` argument.

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
$ resotoworker -v --cleanup --cleanup-volumes --cleanup-volumes-age 2d
```

## List of arguments
```
  --cleanup-volumes     Cleanup unused Volumes (default: False)
  --cleanup-volumes-age CLEANUP_VOLUMES_AGE
                        Cleanup unused Volumes Age (default: 14 days)
```
