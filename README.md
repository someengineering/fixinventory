<p align="center"><img src="https://raw.githubusercontent.com/someengineering/resoto/main/misc/resoto_200.png" alt="Resoto"/>
<h1 align="center">Automate tedious infrastructure tasks, remarkably fast!</h1></p>

<p align="center"><img src="https://raw.githubusercontent.com/someengineering/resoto/main/misc/resoto_banner.png" /></p>

[![Version](https://img.shields.io/github/v/tag/someengineering/resoto?label=latest)](https://github.com/someengineering/resoto/tags/)
[![Build](https://img.shields.io/github/workflow/status/someengineering/resoto/Build%20Docker%20Images/main)](https://github.com/someengineering/resoto/commits/main)
[![Docs](https://img.shields.io/badge/docs-latest-<COLOR>.svg)](https://resoto.com/docs)
[![Discord](https://img.shields.io/discord/778029408132923432?label=discord)](https://discord.gg/someengineering)
[![CodeCoverage](https://img.shields.io/codecov/c/github/someengineering/resoto?token=ZEZW5JAR5J)](https://app.codecov.io/gh/someengineering/resoto/)

## Table of contents

* [Overview](#overview)
* [Getting started](#getting-started)
* [Component list](#component-list)
* [Contact](#contact)
* [License](#license)


## Overview
🔍 Search Infrastructure: Resoto maps out your cloud infrastructure in a [graph](https://resoto.com/docs/concepts/graph) and provides a simple [search syntax](https://resoto.com/docs/concepts/search).

📊 Generate Reports: Resoto keeps track of and reports infrastructure changes over time, making it easy to [audit resource usage and cleanup](https://resoto.com/docs/concepts/search/aggregation).

🤖 Automate Tasks: Tedious tasks like rule enforcement, resource tagging, and cleanup can be [automated using jobs](https://resoto.com/docs/concepts/automation/job).


If you ever
* had a standstill in your CI pipeline because a broken job leaked cloud resources which triggered a quota limit
* wanted to find all expired certificate
* had to change the tags of thousands of EC2 instances
* needed to delete all unused EBS volumes that had no I/O for a while
* wished for a god view that lets you explore all cloud usage across all clouds
* reported the cost of a project across different accounts or even across clouds
* cleaned up orphaned load balancers that had no active backends
* wanted to automate any of the above

Those are the kinds of situations Resoto was built for.

Currently it can collect [AWS](plugins/aws/), [Google Cloud](plugins/gcp/),[DigitalOcean](plugins/digitalocean/), [VMWare Vsphere](plugins/vsphere/), [OneLogin](plugins/onelogin/) and [Slack](plugins/slack/) resources. If the cloud you are using is not listed it is easy to write your own collectors. An example can be found [here](plugins/example_collector/).

## Getting started

**Continue reading the Quick Start Guide**
--> [https://resoto.com/docs/getting-started/](https://resoto.com/docs/getting-started/)


# Component list
- [`resotocore`](resotocore/) the platform maintaining the [MultiDiGraph](https://en.wikipedia.org/wiki/Multigraph#Directed_multigraph_(edges_with_own_identity)).
- [`resotoshell`](resotoshell/) the Resoto shell to interact with the core.
- [`resotoworker`](resotoworker/) provides workers that load [plugins](plugins/) to perform collect and cleanup operations.
- [`resotometrics`](resotometrics/) is a [Prometheus](https://prometheus.io/) [exporter](https://prometheus.io/docs/instrumenting/exporters/).
- [`plugins`](plugins/) are a collection of worker plugins like [AWS](plugins/aws/)


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
