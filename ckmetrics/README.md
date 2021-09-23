# `ckmetrics`
Cloudkeeper Prometheus exporter

## Usage
`ckmetrics` uses the following commandline arguments:
```
  --web-port WEB_PORT   TCP port to listen on (default: 9955)
  --keepercore-uri KEEPERCORE_URI
                        Keepercore URI (default: http://localhost:8080)
  --keepercore-ws-uri KEEPERCORE_WS_URI
                        Keepercore Websocket URI (default: ws://localhost:8080)
  --keepercore-graph KEEPERCORE_GRAPH
                        Keepercore graph name (default: ck)
  --timeout TIMEOUT     Metrics generation timeout in seconds (default: 300)
  --verbose, -v         Verbose logging
  --logfile LOGFILE     Logfile to log into
```

Once started `ckmetrics` will register for `generate_metrics` events. When such an event is received it will
generate Cloudkeeper metrics and provide them at the `/metrics` endpoint.

A prometheus config could look like this:
```
scrape_configs:
  - job_name: "ckmetrics"
    static_configs:
      - targets: ["localhost:9955"]
```
