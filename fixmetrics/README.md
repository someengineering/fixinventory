# `fixmetrics`
Fix Prometheus exporter


## Table of contents

* [Overview](#overview)
* [Usage](#usage)
* [Details](#details)
    * [Example](#example)
    * [Taking it one step further](#taking-it-one-step-further)
* [Contact](#contact)
* [License](#license)


## Overview
`fixmetrics` takes [`fixcore`](../fixcore/) graph data and runs aggregation functions on it. Those aggregated metrics
are then exposed in a [Prometheus](https://prometheus.io/) compatible format. The default TCP port is `9955` but
can be changed using the `fixmetrics.web_port` config attribute.

More information can be found below and in [the docs](https://inventory.fix.security/docs/concepts/components/metrics).


## Usage
`fixmetrics` uses the following commandline arguments:
```
  --subscriber-id SUBSCRIBER_ID
                        Unique subscriber ID (default: fix.metrics)
  --override CONFIG_OVERRIDE [CONFIG_OVERRIDE ...]
                        Override config attribute(s)
  --fixcore-uri fixCORE_URI
                        fixcore URI (default: https://localhost:8900)
  --verbose, -v         Verbose logging
  --quiet               Only log errors
  --psk PSK             Pre-shared key
  --ca-cert CA_CERT     Path to custom CA certificate file
  --cert CERT           Path to custom certificate file
  --cert-key CERT_KEY   Path to custom certificate key file
  --cert-key-pass CERT_KEY_PASS
                        Passphrase for certificate key file
  --no-verify-certs     Turn off certificate verification
```

ENV Prefix: `fixMETRICS_`
Every CLI arg can also be specified using ENV variables.

For instance the boolean `--verbose` would become `fixMETRICS_VERBOSE=true`.

Once started `fixmetrics` will register for `generate_metrics` core events. When such an event is received it will
generate Fix metrics and provide them at the `/metrics` endpoint.

A prometheus config could look like this:
```
scrape_configs:
  - job_name: "fixmetrics"
    static_configs:
      - targets: ["localhost:9955"]
```

## Details
Fix core supports aggregated queries to produce metrics. Our common library [`fixlib`](../fixlib/) define a number of base resources that are common to a lot of cloud proviers, like say compute instances, subnets, routers, load balancers, and so on. All of those ship with a standard set of metrics specific to each resource.

For example, instances have CPU cores and memory, so they define default metrics for those attributes. Right now metrics are hard coded and read from the base resources, but future versions of Fix will allow you to define your own metrics in `fixcore` and have `fixmetrics` export them.

For right now you can use the aggregate API at `{fixcore}:8900/graph/{graph}/reported/search/aggregate` or the `aggregate` CLI command to generate your own metrics. For API details check out the `fixcore` API documentation as well as the Swagger UI at `{fixcore}:8900/api-doc/`.

In the following we will be using the Fix shell `resh` and the `aggregate` command.


### Example
Enter the following commands into `resh`
```
search is(instance) | aggregate /ancestors.cloud.reported.name as cloud, /ancestors.account.reported.name as account, /ancestors.region.reported.name as region, instance_type as type : sum(1) as instances_total, sum(instance_cores) as cores_total, sum(instance_memory*1024*1024*1024) as memory_bytes
```

Here is the same query with line feeds for readability (can not be copy'pasted)
```
search is(instance) |
  aggregate
    /ancestors.cloud.reported.name as cloud,
    /ancestors.account.reported.name as account,
    /ancestors.region.reported.name as region,
    instance_type as type :
  sum(1) as instances_total,
  sum(instance_cores) as cores_total,
  sum(instance_memory*1024*1024*1024) as memory_bytes
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
- `search is(instance)` fetch all the resources that inherit from base kind `instance`. This would be compute instances like `aws_ec2_instance` or `gcp_instance`.
- `aggregate /ancestors.cloud.reported.name as cloud, /ancestors.account.reported.name as account, /ancestors.region.reported.name as region, instance_type as type` aggregate the instance metrics by `cloud`, `account`, and `region` name as well as `instance_type` (think `GROUP_BY` in SQL).
- `sum(1) as instances_total, sum(instance_cores) as cores_total, sum(instance_memory*1024*1024*1024) as memory_bytes` sum up the total number of instances, number of instance cores and memory. The later is stored in GB and here we convert it to bytes as is customary in Prometheus exporters.


### Taking it one step further
```
search is(instance) and instance_status = running | aggregate /ancestors.cloud.reported.name as cloud, /ancestors.account.reported.name as account, /ancestors.region.reported.name as region, instance_type as type : sum(/ancestors.instance_type.reported.ondemand_cost) as instances_hourly_cost_estimate
```

Again the same query with line feeds for readability (can not be copy'pasted)
```
search is(instance) and instance_status = running |
  aggregate
    /ancestors.cloud.reported.name as cloud,
    /ancestors.account.reported.name as account,
    /ancestors.region.reported.name as region,
    instance_type as type :
  sum(/ancestors.instance_type.reported.ondemand_cost) as instances_hourly_cost_estimate
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

What did we do here? We told Fix to find all resource of type compute instance (`search is(instance)`) with a status of `running` and then merge the result with ancestors (parents and parent parents) of type `cloud`, `account`, `region` and now also `instance_type`.

Let us look at two things here. First, in the previous example we already aggregated by `instance_type`. However this was the string attribute called `instance_type` that is part of every instance resource and contains strings like `m5.xlarge` (AWS) or `n1-standard-4` (GCP).

Example
```
> search is(instance) | tail -1 | format {kind} {name} {instance_type}
aws_ec2_instance i-039e06bb2539e5484 t2.micro
```

What we did now was ask Fix to go up the graph and find the directly connected resource of kind `instance_type`.

An `instance_type` resource looks something like this
```
> search is(instance_type) | tail -1 | dump
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

This is the core functionality `fixmetrics` provides.


## Contact
If you have any questions feel free to [join our Discord](https://discord.gg/fixsecurity) or [open a GitHub issue](https://github.com/someengineering/fix/issues/new).


## License
See [LICENSE](../LICENSE) for details.
