# `ckmetrics`
Cloudkeeper Prometheus exporter


## Table of contents

* [Overview](#overview)
* [Usage](#usage)
* [Details](#details)
    * [Example](#example)
    * [Taking it one step further](#taking-it-one-step-further)
* [Contact](#contact)
* [License](#license)


## Overview
`ckmetrics` takes [`ckcore`](../ckcore/) graph data and runs aggregation functions on it. Those aggregated metrics
are then exposed in a [Prometheus](https://prometheus.io/) compatible format. The default TCP port is `9955` but
can be changed using the `--web-port` argument.


## Usage
`ckmetrics` uses the following commandline arguments:
```
  --web-port WEB_PORT   TCP port to listen on (default: 9955)
  --ckcore-uri CKCORE_URI
                        ckcore URI (default: http://localhost:8900)
  --ckcore-ws-uri CKCORE_WS_URI
                        ckcore Websocket URI (default: ws://localhost:8900)
  --ckcore-graph CKCORE_GRAPH
                        ckcore graph name (default: ck)
  --timeout TIMEOUT     Metrics generation timeout in seconds (default: 300)
  --verbose, -v         Verbose logging
  --logfile LOGFILE     Logfile to log into
```

ENV Prefix: `CKMETRICS_`  
Every CLI arg can also be specified using ENV variables.

For instance the boolean `--verbose` would become `CKMETRICS_VERBOSE=true` or `--timeout 300` would become `CKMETRICS_TIMEOUT=300`.

Once started `ckmetrics` will register for `generate_metrics` core events. When such an event is received it will
generate Cloudkeeper metrics and provide them at the `/metrics` endpoint.

A prometheus config could look like this:
```
scrape_configs:
  - job_name: "ckmetrics"
    static_configs:
      - targets: ["localhost:9955"]
```

## Details
Cloudkeeper core supports aggregated queries to produce metrics. Our common library [`cklib`](../cklib/) define a number of base resources that are common to a lot of cloud proviers, like say compute instances, subnets, routers, load balancers, and so on. All of those ship with a standard set of metrics specific to each resource.

For example, instances have CPU cores and memory, so they define default metrics for those attributes. Right now metrics are hard coded and read from the base resources, but future versions of Cloudkeeper will allow you to define your own metrics in `ckcore` and have `ckmetrics` export them.

For right now you can use the aggregate API at `{ckcore}:8900/graph/{graph}/reported/query/aggregate` or the `aggregate` CLI command to generate your own metrics. For API details check out the `ckcore` API documentation as well as the Swagger UI at `{ckcore}:8900/api-doc/`.

In the following we will be using the Cloudkeeper shell `cksh` and the `aggregate` command.


### Example
Enter the following commands into `cksh`
```
query is(instance) | merge_ancestors cloud,account,region | aggregate reported.cloud.name as cloud, reported.account.name as account, reported.region.name as region, reported.instance_type as type : sum(1) as instances_total, sum(reported.instance_cores) as cores_total, sum(reported.instance_memory*1024*1024*1024) as memory_bytes
```

Here is the same query with line feeds for readability (can not be copy'pasted)
```
query is(instance) |
  merge_ancestors
    cloud,account,region |
  aggregate
    reported.cloud.name as cloud,
    reported.account.name as account,
    reported.region.name as region,
    reported.instance_type as type :
  sum(1) as instances_total,
  sum(reported.instance_cores) as cores_total,
  sum(reported.instance_memory*1024*1024*1024) as memory_bytes
```

If your graph contains any compute instances the resulting output will look something like this
```
---
group:
  cloud: aws
  account: someengineering-platform
  region: us-west-2
  type: m5.2xlarge
instances_total: 6
cores_total: 24
memory_bytes: 96636764160
---
group:
  cloud: aws
  account: someengineering-platform
  region: us-west-2
  type: m5.xlarge
instances_total: 8
cores_total: 64
memory_bytes: 257698037760
---
group:
  cloud: gcp
  account: someengineering-dev
  region: us-west1
  type: n1-standard-4
instances_total: 12
cores_total: 48
memory_bytes: 193273528320
```

Let us dissect what we've written here:
- `query is(instance)` fetch all the resources that inherit from base kind `instance`. This would be compute instances like `aws_ec2_instance` or `gcp_instance`.
- `merge_ancestors cloud,account,region` merge the resulting instances with their ancestor resources (meaning their parents and parent parents higher up the graph going towards the graph root) so that we can aggregate by cloud name, account name and so on.
- `aggregate reported.cloud.name as cloud, reported.account.name as account, reported.region.name as region, reported.instance_type as type` aggregate the instance metrics by `cloud`, `account`, and `region` name as well as `instance_type` (think `GROUP_BY` in SQL).
- `sum(1) as instances_total, sum(reported.instance_cores) as cores_total, sum(reported.instance_memory*1024*1024*1024) as memory_bytes` sum up the total number of instances, number of instance cores and memory. The later is stored in GB and here we convert it to bytes as is customary in Prometheus exporters.


### Taking it one step further
```
query is(instance) and reported.instance_status = running | merge_ancestors cloud,account,region,instance_type as parent_instance_type | aggregate reported.cloud.name as cloud, reported.account.name as account, reported.region.name as region, reported.instance_type as type : sum(reported.parent_instance_type.ondemand_cost) as instances_hourly_cost_estimate
```

Again the same query with line feeds for readbility (can not be copy'pasted)
```
query is(instance) and reported.instance_status = running |
  merge_ancestors
    cloud,account,region,instance_type as parent_instance_type |
  aggregate
    reported.cloud.name as cloud,
    reported.account.name as account,
    reported.region.name as region,
    reported.instance_type as type :
  sum(reported.parent_instance_type.ondemand_cost) as instances_hourly_cost_estimate
```

Outputs something like
```
---
group:
  cloud: gcp
  account: maestro-229419
  region: us-central1
  type: n1-standard-4
instances_hourly_cost_estimate: 0.949995
```

What did we do here? We told Cloudkeeper to find all resource of type compute instance (`query is(instance)`) with a status of `running` and then merge the result with ancestors (parents and parent parents) of type `cloud`, `account`, `region` and now also `instance_type`.

Let us look at two things here. First, in the previous example we already aggregated by `instance_type`. However this was the string attribute called `instance_type` that is part of every instance resource and contains strings like `m5.xlarge` (AWS) or `n1-standard-4` (GCP).

Example
```
> query is(instance) | tail -1 | format {reported.kind} {reported.name} {reported.instance_type}
aws_ec2_instance i-039e06bb2539e5484 t2.micro
```

What we did now was ask Cloudkeeper to go up the graph and find the directly connected resource of kind `instance_type`.

An `instance_type` resource looks something like this
```
> query is(instance_type) | tail -1
reported:
  kind: aws_ec2_instance_type
  id: t2.micro
  tags: {}
  name: t2.micro
  instance_type: t2.micro
  instance_cores: 1
  instance_memory: 1
  ondemand_cost: 0.0116
  ctime: '2021-09-28T13:10:08Z'
```

As you can see, the instance type resource has a float attribute called `ondemand_cost` which is the hourly cost a cloud provider charges for this particular type of compute instance. In our aggregation query we now sum up the hourly cost of all currently running compute instances and export them as a metric named `instances_hourly_cost_estimate`. If we now export this metric into a timeseries DB like Prometheus we are able to plot our instance cost over time.

This is the core functionality `ckmetrics` provides.


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
