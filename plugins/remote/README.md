# resoto-plugin-remote
Remote graph collector plugin for Resoto

This plugin fetches a graph from a remote Resoto instance and attaches it to the local graph, allowing for distributed resoto setups.

## Usage
Provide a remote `/graph` endpoint:

```
$ resotoworker -v --collector remote --remote-endpoint http://resoto.example.com:8000/graph
```

Multiple endpoints can be specified.

Resoto will merge the remote graph with the local one in two stages. First it attaches the remote graph root to the local graph root.
It then looks one level below the root to find the names of collector plugins. If it finds duplicates, for example because the AWS collector
was run locally and remote, it will merge those two collector nodes into one.

This also means that in the end if you collect graphs of the same cloud provider from multiple remote Resoto instances they will
look as if they were all collected by a single instance.

## Local graphs
The remote plugin can also load files from the local disk using the `file://` URI scheme.
This is useful for development of new plugins or to load old backups of graphs.

## List of arguments
```
  --remote-endpoint REMOTE_ENDPOINT [REMOTE_ENDPOINT ...]
                        Remote Endpoint
```
