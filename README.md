<p align="center"><img src="https://raw.githubusercontent.com/someengineering/cloudkeeper/main/misc/cloudkeeper_200.png" />
<h1 align="center">Cloudkeeper</h1></p>

# Housekeeping for Clouds!

<p align="center"><img src="https://raw.githubusercontent.com/someengineering/cloudkeeper/main/misc/cloudkeeper_banner.png" /></p>

## Table of contents

* [Overview](#overview)
* [Docker based quick start](#docker-based-quick-start)
* [Cloning this repository](#cloning-this-repository)
* [Component list](#component-list)
* [Contact](#contact)
* [License](#license)


## Overview
Cloudkeeper is “housekeeping for clouds” - find leaky resources, manage quota limits, detect drift and clean up. 

Cloudkeeper indexes resources, captures dependencies and maps out your infrastructure in a graph so that it’s understandable for a human. The graph contains metrics for each resource. Developers and SREs can search the graph with a query language, and create alerting and clean-up workflows. Metrics can be aggregated and exported to a time series database like Prometheus.

If you ever
* had a standstill in your CI pipeline because a broken job leaked cloud resources which triggered a quota limit
* wanted to find all expired certificate
* had to change the tags of thousands of EC2 instances at once
* needed to delete all unused EBS volumes that had no I/O in the past month
* wished for a god view that lets you explore all cloud usage across all clouds
* reported the cost of a project across different accounts or even across clouds
* cleaned up orphaned load balancers that had no active backends
* wanted to automate any of the above

Those are the kinds of situations Cloudkeeper was built for.  

Currently it can collect [AWS](plugins/aws/), [Google Cloud](plugins/gcp/), [VMWare Vsphere](plugins/vsphere/), [OneLogin](plugins/onelogin/) and [Slack](plugins/slack/). The later can also be used for notification of resource cleanups. If the cloud you are using is not listed it is easy to write your own collectors. An example can be found [here](plugins/example_collector/).  


Cloudkeeper consists of multiple components described in [the component list below](#component-list)

The latest Docker image is: `ghcr.io/someengineering/cloudkeeper:2.0.0a6`  
The latest Documentation can be found on [https://docs.some.engineering](https://docs.some.engineering)


## Docker based quick start
In this quick start guide, we’re showing you three things, how to:

    1. install Cloudkeeper for AWS with docker
    2. use the Cloudkeeper CLI to run your first collect process
    3. query the results of the collect process 

The docker set-up takes 2-5 minutes. The duration of the first collect process depends on the size of your environment - usually 5-10 minutes. 

Examples and data in this guide are based on a small AWS [Cloud9](https://aws.amazon.com/cloud9/) environment.  
To start exploring you need AWS credentials and a working Docker environment with access to AWS APIs.  
We assume you are familiar with basic Docker operations and how to operate a Linux shell.

**Continue reading the Quick Start Guide**  
--> [https://docs.some.engineering/getting_started/quick_start.html](https://docs.some.engineering/getting_started/quick_start.html)


# Cloning this repository
This Git repo uses [Git Large File Storage (LFS)](https://git-lfs.github.com/).

If you would like to work on the UI [`ckui`](ckui/), before cloning the repo make sure to have [`git-lfs`](https://git-lfs.github.com/) installed!

One time setup:
```
$ git clone https://github.com/someengineering/cloudkeeper.git
$ cd cloudkeeper/
$ git lfs install  # installs git-lfs hooks
```

Once set up you can interact with the repo like any other Git project. All large UI assets will be retrived from [Github's LFS servers](https://docs.github.com/en/repositories/working-with-files/managing-large-files).


If you have no need for the UI assets git-lfs is optional.


# Component list
- [`ckcore`](ckcore/) the platform maintaining the [MultiDiGraph](https://en.wikipedia.org/wiki/Multigraph#Directed_multigraph_(edges_with_own_identity)).
- [`cksh`](cksh/) the Cloudkeeper shell to interact with the core.
- [`ckui`](ckui/) a UI prototype that can load ckcore exported data but has no backend connection yet.
- [`ckworker`](ckworker/) provides workers that load [plugins](plugins/) to perform collect and cleanup operations.
- [`ckmetrics`](ckmetrics/) is a [Prometheus](https://prometheus.io/) [exporter](https://prometheus.io/docs/instrumenting/exporters/).
- [`plugins`](plugins/) are a collection of worker plugins like [AWS](plugins/aws/)


## Contact
If you have any questions feel free to [join our Discord](https://discord.gg/someengineering) or [open a GitHub issue](https://github.com/someengineering/cloudkeeper/issues/new).


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
