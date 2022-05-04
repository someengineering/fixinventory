# resoto-plugin-cleanup-volumes
Volume cleanup plugin for Resoto

This plugin cleans up storage volumes.

## Usage

In `resh` execute

```
> config edit resoto.worker
```

and find the following section

```
plugin_cleanup_volumes:
  # Enable plugin?
  enabled: false
  # Minimum age of unused volumes to cleanup
  min_age: '14 days'
```

The default volume age is 14 days. Meaning if a volume is not in use and has not had any read or write IOPS within the last 14 days it will be deleted.

Optionally change the age cutoff value using the `min_age` option.

Example of valid age units:

```
weeks
days
hours
minutes
```

Each of them can be abbreviated down to one letter. E.g. `7d`, `24h`, `60m`, etc. A space in between the numeric and the unit is optional, meaning `7d` and `7 days` are equivalent.
