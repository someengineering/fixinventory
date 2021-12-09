
# Release Notes 2.0.0a9 (Dec 9th, 2021)

We are very happy to announce that we are now another small step closer to a stable 2.0 release!

Here are some highlights from this release:

**The UI is now shipped as part of every release**<br/>
This is the first version that ships with our gorgeous UI.
Please try it out by downloading the latest version and navigating to `https://path.to.cloudkeeper:8900/ui` in your browser.
The main graph view has been upgraded from 2D to 3D, and shows Treemap charts (#457)!

**We now have a helm chart**<br/>
Thanks to a contribution from @yuval-k, we now have a Helm chart (#428)!
With this chart, it is easier to deploy Cloudkeeper in Kubernetes.
Try it out yourself by following the [Kubernetes setup tutorial in our documentation](https://docs.some.engineering/getting_started/setup_kubernetes.html).

**All cleanup plugins are now available**<br/>
We needed to migrate all cleanup plugins to the 2.0 infrastructure.
With this release, all cleanup plugins have been ported (#422) and (#439).

**Analytics sensors were added**
At Some Engineering, we believe that it is important to know how Cloudkeeper is used, and thus how we can improve.
As such, we have added analytics to our codebase.
The data that is anonymized and purely focused on providing product insights.
It is possible to opt out of sending this data by specifying the command line flag `--analytics-opt-out`.


**Query language improvements**
There are several significant improvements in this area.
It is now possible to define sub-queries (#412) which allow merging nodes with other nodes in the graph.
Additionally, the first step toward a full-featured query template engine has been implemented in #431.
This feature allows defining queries as a template and reusing those templates in other queries, greatly simplifying more complex queries.

**Other improvements**

- `[ckcore]` In the CLI the default output style is now the list style. Every node is printed as one line. To show all available data as yaml node, we introduced the dump command. (#425)
- `[plugin/gcp]` only collect referenced type and service resources, so the graph only contains used resources. (#430)
- `[ckcore]` Add support for array modifiers `all, any, none`. Example: `reported.array all > 3`, which selects all nodes where the property `reported.array` points to an array of integers and all integers in that array are bigger than 3. (#427)
- `[ckcore]` arangodb 3.8.2 or later is now the minimum required version to run cloudkeeper. (#445)
- `[ckcore]` `tag` command can be backgrounded. (#437)
- `[ckcore]` `is()` now also supports multiple kinds, with an or meaning. Example `is(volume, instance) (#432)


#  Release Notes 2.0.0a3 (Oct 4th, 2021)


July 1st, 2021 was a big day for Cloudkeeper. We started a new company to focus 100% on building out Cloudkeeper. The new company’s name is “Some Engineering Inc.”, and going forward we are the maintainers of the open-source project.

Cloudkeeper started as an internal project in late 2019 at D2iQ, the Enterprise Kubernetes Platform, to solve the problem of “better housekeeping” for D2iQ’s cloud accounts. Find leaky resources, manage quota limits, detect drift, clean up and reduce cost. It’s the stuff no engineer wants to deal with. Our co-founder Lukas was a Site Reliability Engineer at D2iQ, and he was in charge of the cleanup project. He needed a tool to give him the big picture of all cloud resources running. And then use that inventory to identify and clean up the resources not in use anymore.

Fast forward to today, and Cloudkeeper has been in production at D2iQ for almost two years. It has grown “organically'' to its current functionality. The SRE team at D2iQ knows all the ins and out of the project. But for somebody new to the project, the bar to start was quite high.

For the past two months, we’ve been busy changing that. And the result is release 2.0.0a3. With this new release, we took out the friction to get Cloudkeeper running in a cloud account. At the same time, we also built a lot of new functionalities that make Cloudkeeper more useful.

**There are six things in particular that deserve a highlight.**

1. Architecture - from monolith to distributed system

2. Graph storage - from in-memory to on-disk persistence

3. Query language - from constrained to flexible

4. Metrics - from hard-coded to query-based

5. CLI - from local to remote execution

6. Workflows - from hard-coded to extendable

We also wrote a lot of new documentation to make it easier for a new user to start with Cloudkeeper. It’s far from done yet, and we’re adding new sections every day.

But let’s dive into the updates!

##  Architecture - From Monolith To Distributed System

We rebuilt Cloudkeeper from the ground up to make it extensible and scalable. The first version of Cloudkeeper was monolithic with a single binary and ran in-memory locally on a laptop. We broke down the single binary and now provide four different binaries:

`ckcore` - maintains cloud-agnostic data in a graph

`ckworker` - infrastructure-specific plug-ins

`cksh` - starts the Cloudkeeper shell

`ckmetrics` - calculates metrics in Prometheus format

The benefit of this approach is that it scales. The length of a full Cloudkeeper run is subject to the number of accounts in a cloud. If you have hundreds or even thousands of accounts - it just takes longer to collect all resources. With this new architecture, you can now add more `ckworker` for faster processing.

This distributed architecture is also more flexible. A clear and simple API helps deal with cloud-specific data. Right now we support AWS, but eventually, we will also build support for GCP, Azure, Alicloud, etc. Different workers give you the freedom of choice to allocate workers, with different configurations. For example, you can have different workers for different clouds, and split the workloads that way. Or, you assign a worker for each individual login. In other words, you can run workers in whatever combination, to reflect e.g. your multi-cloud, geo, account or login structure of your cloud.

###  Components

A bit more detail on the four components of the architecture.

`ckcore` aka “the core” maintains the graph. Data collection happens via `ckworker`. The workers push data into `ckcore`, after the core has told the workers to start collecting data. In the graph, nodes are individual resources, edges are logical dependencies. Cloudkeeper stores a resource’s attributes in the node. These attributes are the basis for the dependencies that Cloudkeeper creates.

We built `ckcore` with a scheduler and a message bus. The message bus has topics and queues. The scheduler runs internally in the core, by default the collect event gets triggered once per hour. A user can however define their own schedule by using the Cloudkeeper shell `cksh`

`ckworker` does all the collection and cleanup work in Cloudkeeper. It waits for instructions from ckcore over a WebSocket connection. By default ckworker subscribes to collect, clean up and tag tasks.

`cksh` is our command-line interface, aka “the shell”. The CLI allows you to execute a variety of commands (see query language) to explore the graph, find resources of interest, mark them for cleanup, fix their tagging, aggregate over their metadata to create metrics and format the output for use in a 3rd party script or system.

`ckmetrics` ckmetrics takes graph data from ckcore and runs aggregation functions on it. The aggregated metrics are then exposed in a Prometheus-compatible format for consumption in other services. For example, D2iQ uses Grafana dashboards to visualize infrastructure metrics for Engineering, Finance and the CEO.

##  Graph storage - From In-Memory To On-Disk Persistence

One of the biggest asks by early users has been data persistence. With the new version of Cloudkeeper, we migrated from a locally maintained in-memory graph to a backend where we now persist the graph after each collect run. Under the hood, we use ArangoDB for that.

Data persistence has three major advantages.

* It’s the foundation to create a history and different versions of the graph. In the past, with the in-memory only version, a restart would make Cloudkeeper lose all history. Right now Cloudkeeper persists the latest collected snapshot, and we have history on our roadmap.

* By persisting the graph we can also provide an audit trail of all changes. Cloudkeeper attaches the changelog to the node that represents the resource. In the previous version, you lost the changelog associated with each node once a new collect run started. Once we keep a history of snapshots, we can also provide a history of changes. Particularly users in the financial services industry have asked for that capability.

* The size of the data set Cloudkeeper collects and stores is not limited anymore by available memory. It’s essentially unlimited now by adding more storage at the database layer. This means Cloudkeeper can work with the largest cloud and multi-cloud infrastructure(s).

Data persistence also means better collaboration, because two people can now look at the same version of the graph. Previously, their local versions of the graph would be different from each other, simply because the information was collected at different points in time.

We also switched to incremental updates. Every time a collector runs, it collects all resources in your entire cloud and sends the information to the core. The old version would push the entire new graph, which is fine for an in-memory store. But now with data persistence and disk, we wanted to optimize for fewer writes. In this new version, the core compares what a new collect run delivered with the current state of the graph, and only stores the delta between the two.

##  Query Language - From Constrained To Flexible

In the previous version of Cloudkeeper, plug-ins delivered much of the rich functionality. The issue with that approach is that for each new use case, you need to create a new plug-in. Plug-ins are useful, but they require writing code and deploying the change. It also means the number of plug-ins keeps going up as you add more use cases, and it gets confusing pretty fast.

Instead, we evolved the query language to include more commands and richer query syntax. The benefit for the users is that you don’t have to write and maintain yet another plug-in - you just write a single query.

A really nice new functionality of the query language is graph traversal over multiple nodes. In the old version of Cloudkeeper, you could only match and filter by attributes for an individual resource. Now, with graph traversal, you can also filter and match based on the state of all predecessor and successor nodes. This is a super powerful capability to navigate the graph, express complex conditions across multiple resources in a single query, and take action on resources that match those conditions.

###  Query Example

Let’s illustrate this with a specific use case - cleaning up unused application load balancers (“ALB”) in AWS. Load balancers distribute incoming application traffic across multiple targets, such as EC2 instances, which are attached to multiple target groups. In short, *load balancer → target group(s) → compute instances*.

To determine if a load balancer is still in use or not, you have to know if there are no more backend instances, or if they are still connected but terminated (which is particular to AWS). This may seem easy, but in a multi-account structure - for every account you would have to look for load balancers in every region, understand which ones have target groups, which target groups have instances, and understand the state of each instance. If there is an instance still running, we can’t delete the target group of the load balancer, because it might still be in use. Going through that decision loop for every load balancer is impossible without automation. Unless you want to spend your time clicking through the account structure of your AWS console.

Why would this matter? Load balancers are not that expensive. But companies usually have thousands of them - it adds up, and there are quotas. The default is 50 ALBs and 100 ALB target groups per region. You can increase the quota by 10x or even 100x. But when you leak resources, it’s easy to hit even a high limit like 5,000.

And so going through that decision loop to find unused ALBs without any automation is almost impossible. With graph traversal, we can write a query that finds unused load balancers, by determining if the target groups are empty, if the instances are not running anymore, or if they are connected but terminated. We define “unused” as “older than 7 days” `ctime < -7d` and “no backends attached”.

```
is(aws_alb) and ctime < -7d with(empty, <-- is(aws_alb_target_group)
  and target_type = instance and ctime < -7d with(empty, <-- is(aws_ec2_instance)
  and instance_status != terminated)) <-[0:1]- is(aws_alb_target_group) or is(aws_alb)
```

That’s it! This query will generate a list of all orphaned load balancers that are candidates for clean-up. To actually clean up, we only need to add a ``| clean`` command at the end of the query.

```
is(aws_alb) and ctime < -7d with(empty, <-- is(aws_alb_target_group)
  and target_type = instance and ctime < -7d with(empty, <-- is(aws_ec2_instance)
  and instance_status != terminated)) <-[0:1]- is(aws_alb_target_group) or is(aws_alb) | clean
```

##  Metrics - From Hard-coded To Query-Based


In the old version of Cloudkeeper, the metrics for each resource were hard-coded. At D2iQ, you would literally have to ask Lukas to write the code for a new metric. Obviously, that's not a great long-term solution. The new query language can now do selection and aggregation, and a user can write queries that generate custom metrics.

The benefit is that each audience (engineering, product, finance, etc. ) can create the exact metric they need. Let’s pick an example to illustrate how to write a query that generates metrics.

Assume a CFO wants to know the cost of all AWS compute instances that are running, in nearn The query below calculates a total hourly on-demand cost estimate for all EC2 instances running in all AWS accounts, and aggregates the result by account, region and instance type.

```
 query is(aws_ec2_instance) and reported.instance_status = running |
    merge_ancestors
      account,region,instance_type |
    aggregate
      reported.account.name as account,
      reported.region.name as region,
      reported.instance_type.name as type :
    sum(reported.instance_type.ondemand_cost) as instances_hourly_cost_estimate
```

`instance_type` is a resource in the Cloudkeeper graph. The node for the resource contains a field for the on-demand cost. Cloudkeeper fetches the data for that field from the AWS Pricing API during each collection run.

The query then generates a new metric `instances_hourly_cost_estimate` - a total hourly cost estimate, broken down by account, region and instance type. It’s a simple way to understand which AWS accounts and the teams responsible for the accounts drive compute cost. And the nice thing is that Finance doesn’t have to bother engineering to get these metrics. They can just run the queries themselves in the Cloudkeeper CLI.

Writing queries may not be everyone’s thing though. For those users, we also maintain several pre-configured metrics per resource in Cloudkeeper.

These pre-configured metrics are running as queries in `ckmetrics`. `ckmetrics` connects to the core, runs the queries and recalculates the metrics automatically every time something has changed in the graph, e.g. after a collect or a clean-up. The results are cached in `ckmetrics` and exported to Prometheus where they can be queried via PromQL. From there - you can send them to any visualization tool that understands the prometheus format, such as Grafana. Future versions of `ckmetrics` will allow a user to edit the pre-defined metrics as well as define their own.

##  CLI - From Local To Remote Execution

The old CLI ran locally on a user’s desktop. That implied that two different users would never look at the same version of a graph - because it was their own “local” version that Cloudkeeper had generated at a specific point in time.

The new CLI executes commands remotely in the core. That means everyone now looks at the same version of a graph, which opens up new collaboration use cases.

##  Workflows - From Hard-Coded to Event-Based

Currently we support three different workflows - collect, clean up and metrics. Workflows consist of steps that perform a specific action.

In the old Cloudkeeper, the execution order of these workflows and their steps was hard-coded. Collect, clean-up, metrics. If you wanted to update your metrics - you had to execute the whole thing again. You couldn’t flexibly re-arrange the steps, skip a step, or call one on-demand.

Now - you can schedule and execute workflows in whatever scope and order you want. For example, once Cloudkeeper has collected and generated a new graph, you can look at the graph, write a query that flags certain resources for clean-up, and trigger the clean-up.

Workflows are an area that we’re investing strongly in. If you have ideas - please let us know!
**The best is to [join our Discord channel](https://discord.gg/3G3sX6y3bt).**

##  What’s Next?

This current release makes it much easier to use Cloudkeeper to keep your cloud clean of drift. We made it easier and more intuitive for first-time users to start with Cloudkeeper. And we have a lot more ideas to keep going in that direction. For example, the next release will have a built-in library of useful query templates to give users a jump start. We’re also working on authentication, authorization and encrypted communication.

Meanwhile - please let us know what’s important for you as we continue building out Cloudkeeper. We also offer custom onboarding sessions - **again, reach out to us via our [Discord channel](https://discord.gg/3G3sX6y3bt).**
