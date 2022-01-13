# `resotocore`
Resoto core graph platform


## Table of contents

* [Overview](#overview)
* [Usage](#usage)
* [Contact](#contact)
* [License](#license)


## Overview
The Resoto graph platfrom `resotocore` is the persistance and query backend of resoto. It maintains the graph
of resources and provides APIs to update and access them. Within `resotocore` there are workflows consisting of steps
that result in actions like `collect`, `cleanup` or `generate_metrics`. These actions are being received by components
like [`resotoworker`](../resotoworker/) and [`resotometrics`](../resotometrics/).

`resotocore` also provides the CLI API that [`resotosh`](../resotosh/) calls.


## Usage
```
  -h, --help            show this help message and exit
  --log-level LOG_LEVEL
                        Log level (default: info)
  --graphdb-server GRAPHDB_SERVER
                        Graph database server (default: http://localhost:8529)
  --graphdb-database GRAPHDB_DATABASE
                        Graph database name (default: resoto)
  --graphdb-username GRAPHDB_USERNAME
                        Graph database login (default: resoto)
  --graphdb-password GRAPHDB_PASSWORD
                        Graph database password (default: "")
  --graphdb-type GRAPHDB_TYPE
                        Graph database type (default: arangodb)
  --graphdb-no-ssl-verify
                        If the connection should be verified (default: False)
  --graphdb-request-timeout GRAPHDB_REQUEST_TIMEOUT
                        Request timeout in seconds (default: 900)
  --psk PSK             Pre-shared key
  --host HOST [HOST ...]
                        TCP host(s) to bind on (default: 127.0.0.1)
  --port PORT           TCP port to bind on (default: 8900)
  --plantuml-server PLANTUML_SERVER
                        PlantUML server URI for UML image rendering (default: https://www.plantuml.com/plantuml)
  --jobs [JOBS ...]
```


## Contact
If you have any questions feel free to [join our Discord](https://discord.gg/someengineering) or [open a GitHub issue](https://github.com/someengineering/resoto/issues/new).


## License
```
Copyright 2022 Some Engineering Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
