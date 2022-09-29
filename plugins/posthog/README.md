# resoto-plugin-posthog
Posthog Collector Plugin for Resoto

This collector plugin is used to collect data from Posthog. It is used internally at Some Engineering to create metrics about resoto installations and usage.

To export the number of running installations add the following config to `resoto.metrics`
```
resotometrics:
  [...]
  metrics:
    running_installations:
      # Metric help text
      help: 'Number of running installations'
      # Aggregation search to run
      search: 'aggregate(/ancestors.cloud.reported.name as cloud: sum(count) as running_installations): is(posthog_event) and name=model.info'
      # Type of metric (gauge or counter)
      type: 'gauge'
```
