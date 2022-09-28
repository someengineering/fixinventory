# resoto-plugin-scarf
Scarf Collector Plugin for Resoto

This collector plugin is used to collect data from Scarf. It is used internally at Some Engineering to create metrics about image downloads.

To export the number of image pulls add the following config to `resoto.metrics`
```
resotometrics:
  [...]
  metrics:
    scarf_downloads_total:
      # Metric help text
      help: 'Scarf downloads'
      # Aggregation search to run
      search: 'aggregate(/ancestors.cloud.reported.name as cloud, /ancestors.account.reported.name as namespace, id as repository: sum(pull_count) as scarf_downloads_total): is(scarf_repository)'
      # Type of metric (gauge or counter)
      type: 'counter'
```
