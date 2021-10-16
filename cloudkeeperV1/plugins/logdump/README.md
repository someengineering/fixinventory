# cloudkeeper-plugin-logdump
Event Log Dumper Plugin for Cloudkeeper

Whenever cloudkeeper modifies a resource it creates an event log entry. This plugin dumps those logs
into individual resource specific log files once a collect/cleanup run completes.

## Usage
Provide a directory where to dump the event logs. E.g. `--logdump-path /var/local/cloudkeeper/logs/events`

## List of arguments
```
  --logdump-path LOGDUMP_PATH
                        Path to Event Log Dump Directory
```