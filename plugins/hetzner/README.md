# fix-plugin-hetzner

Hetzner Collector Plugin for Fix (alpha)

This collector is in alpha stage and may not work as expected. Use at your own risk.

- [x] Resource collection
- [ ] Resource deletion
- [ ] Tag update

## Configuration

Hetzner has no API to introspect a token, so you need to manually maintain the project name associated with an API token. Provide names in the same order as the corresponding API tokens.

```
fixworker:
  collector:
    - 'hetzner'
hetzner:
  hcloud_project_names:
    - 'dev'
    - 'global'
  hcloud_tokens:
    - '0ytCtPtcyUO1fEwLIYarEQaiY04E9P9tDIowK1JD8mX5K5jsLhPmiwkMLLuDGMxG'
    - 'nt71Kl3pSscVt5Mey1NUfERXeaxHyDru988De7UA4ew48eAvMMsQ8tserBEOwLXq'
```

## License

See [LICENSE](../../LICENSE) for details.
