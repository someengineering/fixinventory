# `fixcore`
Fix Inventory core graph platform


## Table of contents

* [Overview](#overview)
* [Usage](#usage)
* [Contact](#contact)
* [License](#license)


## Overview
The Fix Inventory graph platfrom `fixcore` is the persistance and search backend of fix. It maintains the graph
of resources and provides APIs to update and access them. Within `fixcore` there are workflows consisting of steps
that result in actions like `collect`, `cleanup` or `generate_metrics`. These actions are being received by components
like [`fixworker`](../fixworker/) and [`fixmetrics`](../fixmetrics/).

`fixcore` also provides the CLI API that [`fixshell`](../fixshell/) calls.

More information can be found in [the docs](https://inventory.fix.security/docs/concepts/components/core).


## Usage
```
  --psk PSK             Pre-shared key
  --graphdb-server GRAPHDB_SERVER
                        Graph database server (default: http://localhost:8529)
  --graphdb-database GRAPHDB_DATABASE
                        Graph database name (default: fix)
  --graphdb-username GRAPHDB_USERNAME
                        Graph database login (default: fix)
  --graphdb-password GRAPHDB_PASSWORD
                        Graph database password (default: "")
  --graphdb-root-password GRAPHDB_ROOT_PASSWORD
                        Graph root database password used for creating user and database if not existent.
  --graphdb-bootstrap-do-not-secure
                        Leave an empty root password during system setup process.
  --graphdb-type GRAPHDB_TYPE
                        Graph database type (default: arangodb)
  --graphdb-no-ssl-verify
                        If the connection should not be verified (default: False)
  --graphdb-request-timeout GRAPHDB_REQUEST_TIMEOUT
                        Request timeout in seconds (default: 900)
  --no-tls              Disable TLS and use plain HTTP.
  --cert CERT           Path to a single file in PEM format containing the host certificate. If no certificate is provided, it is created using the CA.
  --cert-key CERT_KEY   In case a --cert is provided. Path to a file containing the private key.
  --cert-key-pass CERT_KEY_PASS
                        In case a --cert is provided. Optional password to decrypt the private key file.
  --ca-cert CA_CERT     Path to a single file in PEM format containing the CA certificate.
  --ca-cert-key CA_CERT_KEY
                        Path to a file containing the private key for the CA certificate. New certificates can be created when a CA certificate and private key is provided. Without the private key, the
                        CA certificate is only used for outgoing http requests.
  --ca-cert-key-pass CA_CERT_KEY_PASS
                        Optional password to decrypt the private ca-cert-key file.
  --version             Print the version of fixcore and exit.
  --override CONFIG_OVERRIDE [CONFIG_OVERRIDE ...], -o CONFIG_OVERRIDE [CONFIG_OVERRIDE ...]
                        Override configuration parameters. Format: path.to.property=value. The existing configuration will be patched with the provided values. A value can be a simple value or a comma
                        separated list of values if a list is required. Note: this argument allows multiple overrides separated by space. Example: --override
                        fixcore.api.web_hosts=localhost,some.domain fixcore.api.web_port=12345
  --verbose, -v         Enable verbose logging.
  --debug               Enable debug mode. If not defined use configuration.
  --ui-path UI_PATH     Path to the UI files. If not defined use configuration..
```


## Contact
If you have any questions feel free to [join our Discord](https://discord.gg/fixsecurity) or [open a GitHub issue](https://github.com/someengineering/fix/issues/new).


## License
See [LICENSE](../LICENSE) for details.

