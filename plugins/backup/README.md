# cloudkeeper-plugin-backup
A graph backup plugin for Cloudkeeper

This plugin creates a backup of the graph whenever a collection and cleanup run finishes.

## Usage
Specify a folder to backup the graph dumps to. E.g. `--backup-to /var/local/cloudkeeper/backups`

At a later point the resulting backups can be loaded into cloudkeeper and explored using [the remote plugin](https://github.com/mesosphere/cloudkeeper/tree/master/plugins/remote) like so:
```
$ cloudkeeper -v --collector remote --remote-endpoint file:///var/local/cloudkeeper/backups/graph_20200601185431595198.bak
```

## List of arguments
```
  --backup-to BACKUP_TO
                        Backup Destination
```
