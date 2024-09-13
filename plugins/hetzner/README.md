# fix-plugin-hetzner

Hetzner Collector Plugin for Fix

## Configuration

```
fixworker:
  # List of collectors to run
  collector:
    - 'hetzner'
hetzner:
  # Hetzner Cloud project names - Hetzner has no API to introspect a token, so you need to manually maintain the project name associated with an API token. Provide names in the same order as the corresponding API tokens.
  hcloud_project_names:
    - 'dev'
    - 'global'
  # Hetzner Cloud project API tokens
  hcloud_tokens:
    - '0ytCtPtcyUO1fEwLIYarEQaiY04E9P9tDIowK1JD8mX5K5jsLhPmiwkMLLuDGMxG'
    - 'nt71Kl3pSscVt5Mey1NUfERXeaxHyDru988De7UA4ew48eAvMMsQ8tserBEOwLXq'
```

## License

See [LICENSE](../../LICENSE) for details.