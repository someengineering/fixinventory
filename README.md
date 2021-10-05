<p align="center"><img src="https://raw.githubusercontent.com/someengineering/cloudkeeper/main/misc/cloudkeeper_200.png" />
<h1 align="center">Cloudkeeper</h1></p>

# Housekeeping for Clouds!

## Table of contents

* [Overview](#overview)
* [Quick Start](#quick-start)
* [Component list](#component-list)
* [Contact](#contact)
* [License](#license)


## Overview
Cloudkeeper is “housekeeping for clouds” - find leaky resources, manage quota limits, detect drift and clean up. 

Cloudkeeper indexes resources, captures dependencies and maps out your infrastructure in a graph so that it’s understandable for a human. The graph contains metrics for each resource. Developers and SREs can search the graph with a query language, and create alerting and clean-up workflows. Metrics can be aggregated and exported to a time series database like Prometheus.

Cloudkeeper consists of multiple components described in [the component list below](#component-list)

The latest Docker image is: `ghcr.io/someengineering/cloudkeeper:2.0.0a3`


## Quick start
In this quick start guide, we’re showing you three things, how to:

    1. install Cloudkeeper for AWS with docker
    2. use the Cloudkeeper CLI to run your first collect process
    3. query the results of the collect process 

The docker set-up takes 2-5 minutes. The duration of the first collect process depends on the size of your environment - usually 5-10 minutes. 

Examples and data in this documentation are based on a small AWS [Cloud9](https://aws.amazon.com/cloud9/) environment.  
To start exploring you need AWS credentials and a working Docker environment with access to AWS APIs.  
We assume you are familiar with basic Docker operations and how to operate a Linux shell.

**Continue reading the Quick Start Guide**  
--> https://docs.some.engineering


# Component list
- [`ckcore`](ckcore/) the platform maintaining the [MultiDiGraph](https://en.wikipedia.org/wiki/Multigraph#Directed_multigraph_(edges_with_own_identity)).
- [`cksh`](cksh/) the Cloudkeeper shell to interact with the core.
- [`ckworker`](ckworker/) provides workers that load [plugins](plugins/) to perform collect and cleanup operations.
- [`ckmetrics`](ckmetrics/) is a [Prometheus](https://prometheus.io/) [exporter](https://prometheus.io/docs/instrumenting/exporters/).
- [`plugins`](plugins/) are a collection of worker plugins like [AWS](plugins/aws/)


## Contact
If you have any questions feel free to [join our Discord](https://discord.gg/3G3sX6y3bt) or [open a GitHub issue](https://github.com/someengineering/cloudkeeper/issues/new).


## License
```
Copyright 2021 Some Engineering Inc.

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
