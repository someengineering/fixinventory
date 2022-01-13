# resoto-plugin-cleanup_expired
Resoto plugin for cleanup of expired resources

This plugin looks for resources with the tags `expiration` or `resoto:expires` and deletes them if they are expired.

## Tag format
| Tag | Format | Description |
| --- | --- | --- |
| `resoto:expires` | `2019-09-05T10:40:11+00:00` | ISO 8601 Timestamp |
| `expiration` | `24h` | A timedelta relative to the resource's creation time |

For the `expiration` tag the following units are valid:
```
weeks
days
hours
minutes
```

Each of them can be abbreviated down to one letter. E.g. `7d`, `24h`, `60m`, etc. A space in between the numeric and the unit is optional,
meaning `7d` and `7 days` are equivalent.

## Usage
Turn on general cleanup using the `--cleanup` argument and activate this plugin by adding `--cleanup-expired`.
```
$ resotoworker -v --cleanup --cleanup-expired
```

## List of arguments
```
  --cleanup-expired     Cleanup expired resources (default: False)
```
