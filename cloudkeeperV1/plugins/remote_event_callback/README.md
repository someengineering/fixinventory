# cloudkeeper-plugin-remote_event_callback
Event Callback Plugin for Cloudkeeper

This plugin posts to a remote http(s) endpoint when an event is dispatched.

## Usage
```
$ cloudkeeper -v --remote-event-callback-endpoint collect_finish:http://cloudkeeper.example.com:8000/callback
```

Optionally specify a preshared key that should be transmitted with the request using the `--remote-event-callback-psk` argument.

### Example
Instance A
```
$ cloudkeeper -v \
    --web-port 8000 \
    --collector example \
    --remote-event-callback-endpoint collect_finish:http://localhost:8001/callback \
    --remote-event-callback-psk somepresharedkey
```
Instance B
```
$ cloudkeeper -v \
    --web-port 8001 \
    --web-psk somepresharedkey \
    --collector remote \
    --remote-endpoint http://localhost:8000/graph
```

Instance A will collect the `example` cloud provider. When done it will send a callback to Instance B. When Instance B receives the callback it will start its
own collection run. In this case fetching the remote graph from Instance A.

Note that the PSK is just a simple secret string that will be transmitted in plain text to the other instance and compared there. If done over the Internet
at the very least you should add TLS proxies in front of all instances and use https instead of http. Better yet establish a VPN or otherwise private link between those networks and do not expose Cloudkeeper instances publicly.

## List of arguments
```
  --remote-event-callback-endpoint REMOTE_EVENT_ENDPOINT [REMOTE_EVENT_ENDPOINT ...]
                        Remote Event Callback Endpoint
  --remote-event-callback-psk REMOTE_EVENT_CALLBACK_PSK
                        Remote Event Callback pre-shared-key
```
