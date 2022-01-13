# resoto-plugin-gcp
An GCP collector plugin for Resoto.

## Usage
When the collector is enabled (`--collector gcp`) it will automatically collect any accounts specified for `--gcp-service-account`. Set to empty string to use default service account discovery on GCE, GKE etc.

## List of arguments
```
  --gcp-zone GCP_ZONE [GCP_ZONE ...]
                        GCP Zone
  --gcp-service-account GCP_SERVICE_ACCOUNT [GCP_SERVICE_ACCOUNT ...]
                        GCP Service Account File
  --gcp-project GCP_PROJECT [GCP_PROJECT ...]
                        GCP Project
  --gcp-collect GCP_COLLECT [GCP_COLLECT ...]
                        GCP services to collect (default: all)
  --gcp-no-collect GCP_NO_COLLECT [GCP_NO_COLLECT ...]
                        GCP services not to collect
  --gcp-project-pool-size GCP_PROJECT_POOL_SIZE
                        GCP Project Thread Pool Size (default: 5)
  --gcp-zone-pool-size GCP_ZONE_POOL_SIZE
                        GCP Zone Thread Pool Size (default: 20)
  --gcp-fork            GCP use forked process instead of threads (default: False)
```

## Scraping multiple accounts
The `--gcp-service-account` argument takes multiple paths to service account JSON files.
