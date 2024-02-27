# fix-plugin-dockerhub
Docker Hub Collector Plugin for Fix

This collector plugin is used to collect data from Docker Hub. It is used internally at Some Engineering to create metrics about image downloads.

To export the number of image pulls add the following config to `fix.metrics`
```
fixmetrics:
  [...]
  metrics:
    dockerhub_downloads_total:
      # Metric help text
      help: 'Docker Hub downloads'
      # Aggregation search to run
      search: 'aggregate(/ancestors.cloud.reported.name as cloud, /ancestors.account.reported.name as namespace, id as repository: sum(pull_count) as dockerhub_downloads_total): is(dockerhub_repository)'
      # Type of metric (gauge or counter)
      type: 'counter'
```
## License
See [LICENSE](../../LICENSE) for details.
