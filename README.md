<p align="center"><img src="https://raw.githubusercontent.com/someengineering/cloudkeeper/master/misc/cloudkeeper_200.png" /><h1 align="center">Cloudkeeper</h1></p>

# Housekeeping for Clouds!

## Introduction
Cloudkeeper is a standalone CLI tool that periodically collects a list of resources in cloud accounts, provides metrics about them, and can clean them up.

If you ever
* had a standstill in your CI pipeline because a broken job leaked cloud resources which triggered a quota limit
* wanted to find all the places an expired certificate is used in
* had to change the tags of thousands of EC2 instances at once
* needed to delete all unused EBS volumes that had no I/O in the past month
* wished for a god view that lets you explore all cloud usage across all clouds
* reported the cost of a project across different accounts or even across clouds
* cleaned up orphaned load balancers that had no active backends
* wanted to automate any of the above

Those are the kinds of situations Cloudkeeper was built for.  

Currently it can collect [AWS](plugins/aws/), [Google Cloud](plugins/gcp/), [VMWare Vsphere](plugins/vsphere/), [OneLogin](plugins/onelogin/) and [Slack](plugins/slack/). The later can also be used for notification of resource cleanups. If the cloud you are using is not listed it is easy to write your own collectors. An example can be found [here](plugins/example_collector/).  

Resource collection is performed in intervals (`--interval`) for each activated collector plugin (`--collector`).
When resource collection is finished a resource cleanup can be performed (`--cleanup`). By default nothing will be cleaned!
Cleanup plugins have to be installed and configured, or resources manually flagged for cleanup using the built-in CLI.
Read more about collector, cli and cleanup plugins in the [Plugins](#plugins) section below.


## Who is it for?
Cloudkeeper was made for people responsible for their organizations Cloud Accounts usage and spending, who are comfortable with the Linux shell. It is assumed that users want to create their own Plugins fitting the needs of their particular use case and organization.  
It can however be used without any programming experience just using the included CLI and Plugins.


## tl;dr - show me something worthwhile
```
$ docker run -it ghcr.io/someengineering/cloudkeeper --verbose \
    --cleanup --no-cli --one-shot --interval 0 \
    --collector aws \
    --aws-access-key-id AKIAIO5FODNN7EXAMPLE \
    --aws-secret-access-key 'ABCDEF+c2L7yXeGvUyrPgYsDnWRRC1AYEXAMPLE' \
    --register-cli-action " \
        cleanup_plan: \
          match kind = aws_ec2_volume \
        | match volume_status = available \
        | match age > 7d \
        | match last_access > 7d \
        | match last_update > 7d \
        | clean" \
    --cleanup-dry-run
```
This will collect all known resources in all regions in the AWS account. Once the collection phase finishes and the cleanup phase begins it will run the registered CLI action. In this case it selects all AWS EBS Volumes that are not in use, older than 7 days, and have not had any read or write IOPS in the past week, and marks them for cleanup. In the next step cloudkeeper would delete all resources that have been marked for cleanup if it was not for the `--cleanup-dry-run` flag.

If you only want to collect specific regions, eg. us-east-1 and us-west-2 you could specify `--aws-region us-east-1 us-west-2`.

If you would like for cloudkeeper to do the same on an organization wide level, use credentials for your root account or instead of specifying them as CLI args export `AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY` or `AWS_PROFILE`. If you are running this inside EC2 you can also assign an instance profile and export `AWS_CONFIG_FILE`. Then provide the `--aws-role` and `--aws-scrape-org` args so cloudkeeper will discover all your organization's AWS subaccounts and assume the role in them.

Lastly the args `--cleanup --no-cli --one-shot --interval 0` turn on the cleanup code (as opposed to just collecting resources and generating metrics), turn off the built-in CLI, tell cloudkeeper to run one resource collection loop and then quit (instead of running forever) and set the loop interval to 0 seconds (instead of the default 1h) so that once the collection loop is done cloudkeeper quits immediately instead of waiting for the interval to be over.


## Status
Cloudkeeper was developed as an internal tool at D2iQ for collection and cleanup of the most costly AWS resources. We are open sourcing it in its current state because over the past couple of months it has been very helpful for us in drastically reducing our cloud spent and we thought that especially now during the Covid-19 pandemic it might be useful for others as well.

As mentioned the main focus of Cloudkeeper right now is collecting and cleaning AWS resources because that is the Cloud we are spending the most on. However the infrastructure is there to implement other Cloud Collectors. There is an example one in [plugins/example_collector/](plugins/example_collector/) and two others, [plugins/onelogin/](plugins/onelogin/) and [plugins/slack/](plugins/slack/) that we are using for notification purposes.

In addition Cloudkeeper can run distributed using the `remote` plugin. One could for instance run one cloudkeeper per AWS account and then merge those individually collected resources in a central location. Or run one cloudkeeper for collection and another one for cleanup. The collection instance would only require reading access to your cloud accounts and the cleanup instance could retrieve the collected data from the collection instances and remove unused resources.

There are also a number of cleanup plugins to be found in the [plugins/](plugins/) folder. The Docker image by default contains all the plugins from that folder.

In the [TODO](#todo) section below you will find a list of the most immediate open tasks. Those include implementing more cloud providers, more resource types for the existing ones, writing better tests and more extensive Plugin documentation.


## Metrics
![Cloudkeeper Metrics](https://raw.githubusercontent.com/someengineering/cloudkeeper/master/misc/cloudkeeper_dash.png "Cloudkeeper Metrics")
As a by-product of our resource collection we are able to export Prometheus metrics at the /metrics endpoint.  
The default listening port (`--web-port`) is 8000.  
Custom metric labels based on resource tags can be defined using the `--tag-as-metrics-label` arg.  
Example: `--tag-as-metrics-label project subproject` would ensure that every metric has two additional labels based on the contents of a resources 'project' and 'subproject' tags resulting in metrics output like:
```
cloudkeeper_volumes_total{account="eng-sre (327650738955)",cloud="aws",project="",subproject="",region="us-west-2",status="available",type="gp2"} 36.0
cloudkeeper_volume_bytes{account="eng-sre (327650738955)",cloud="aws",project="",subproject="",region="us-west-2",status="available",type="gp2"} 1.571958030336e+012
cloudkeeper_volume_bytes{account="eng-sre (327650738955)",cloud="aws",project="",subproject="",region="us-west-2",status="in-use",type="io1"} 4.294967296e+011
cloudkeeper_volume_bytes{account="eng-sre (327650738955)",cloud="aws",project="",subproject="",region="us-west-2",status="in-use",type="gp2"} 4.544075399168e+012
cloudkeeper_volumes_monthly_cost_estimate{account="eng-sre (327650738955)",cloud="aws",project="",subproject="",region="us-west-2",status="available",type="gp2"} 146.40000000000003
cloudkeeper_volumes_monthly_cost_estimate{account="eng-sre (327650738955)",cloud="aws",project="",subproject="",region="us-west-2",status="in-use",type="io1"} 50.0
```

Because of the way metrics are collected resources currently only expose `Gauge` metrics. A single resource can either increase or decrease the `Gauge`. Within a plugin any type of metrics can be defined. Cloudkeeper itself is making heavy use of `Summary` and `Counter` metrics to benchmark its own performance.


## Docker Image
A Docker image is available as [`ghcr.io/someengineering/cloudkeeper`](https://github.com/someengineering/cloudkeeper/pkgs/container/cloudkeeper) or by building the included Dockerfile.


## Development Setup
### Installing build dependencies
Alpine 3.12
```
# apk add build-base linux-headers findutils libtool automake autoconf git python3 python3-dev py3-pip
```

Debian 11
```
# apt install build-essential python3 python3-venv python3-pip git libtool autoconf automake
```

CentOS 8
```
# dnf -y groupinstall "Development Tools"
# dnf -y install python38 python38-devel
```
### Option 1) Installing Cloudkeeper for local development
```
$ git clone https://github.com/someengineering/cloudkeeper.git
$ cd cloudkeeper
$ python3 -m venv venv   # ensure Python 3.8 or later is installed
$ source venv/bin/activate
$ pip install --editable cloudkeeper/
$ pip install --editable plugins/aws/  # one of the other plugins depends on aws
$ find plugins/ -maxdepth 1 -mindepth 1 -type d -exec pip install --editable "{}" \+
```
The contents of the cloned git repo can now be modified and changes will be immediatelly
reflected when running `cloudkeeper`.

### Option 2) Building binary wheels
```
$ mkdir ~/packages
$ git clone https://github.com/someengineering/cloudkeeper.git
$ cd cloudkeeper
$ python3 -m venv venv   # ensure Python 3.8 or later is installed
$ source venv/bin/activate
$ pip install wheel
$ pip wheel -w ~/packages cloudkeeper/
$ pip wheel -w ~/packages -f ~/packages plugins/aws/
$ find plugins/ -maxdepth 1 -mindepth 1 -type d -print0 | xargs -0 pip wheel -w ~/packages -f ~/packages
```

Copy the contents of ~/packages/ to any other system and install using e.g.
```
$ pip install -f ~/packages ~/packages/cloudkeeper*.whl
```
The target system does not require above installed compilers and build tools as the resulting wheels
contain all of the binary dependencies. Only a basic Python 3.8+ setup is required.


## Example usage
```
# $ is your shell
# > is the cloudkeeper shell

# If you have the aws cli installed ($ pip install awscli) setup AWS CLI credentials so you are
# logged into an account or alternatively provide --aws-access-key-id/--aws-secret-access-key
# You can also export AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY env variables or define them in
# ~/.aws/credentials and export AWS_PROFILE.
$ aws configure

$ cloudkeeper                                       # Run cloudkeeper with defaults and wait for it to complete
> count kind                                        # Count all collected resources by kind
> match kind = aws_ec2_instance                     # Lists all discovered EC2 Instances
> match kind = aws_ec2_instance | match age > 30d   # List all EC2 Instances that are older than 30 days
> match kind = aws_ec2_volume | count               # Find all EC2 Volumes and count them
> match kind ~ ^aws_ | match tags[owner] ~ sre      # List all AWS resources that have an 'owner' tag containing 'sre'
> backup /tmp/graph                                 # Store a backup of the currently loaded graph to /tmp/graph

# load the previously collected graph and activate the cleanup code in dry run mode
$ cloudkeeper --collector remote --remote-endpoint file:///tmp/graph --cleanup --cleanup-dry-run

> match kind = aws_ec2_volume | head -10  # list the first ten EC2 volumes
> match tags[owner] ~ sre | count kind    # find all resources where tag 'owner' contains 'sre' and count them by kind

# Count by account.name all AWS EC2 Instances, ALBs and ELBs that do not have an 'owner' tag
> match kind ~ ^(aws_[ae]lb\|aws_ec2_instance)$ | has not tags[owner] | count account.name

> match kind = aws_elb | head -1 | dump  # find the first Elastic Loadbalancer (Classic) and dump the object
> match name = sometestinstance | successors      # find a resource with name 'sometestinstance' and list its child resources
> match name = sometestinstance | predecessors    # find a resource with name 'sometestinstance' and list its parent resources
```


## CLI
Cloudkeeper comes with a built-in CLI. Initially only used for debugging the internal data structures it can now also be used to perform simple searches and mark resources for cleanup. Entering `help` will give a list of all commands. `help <command>` will provide additional help for that command.
Commands can be piped into one another using "`|`". Multiple commands can be run after one another using "`;`". If you need to use the pipe or semicolon characters in your commands make sure to escape them using a backslash "`\`" character.
Internally commands take in and output Iterables often consisting of the Cloud resources. Commands can match any attribute of those resources. So for instance if an AWS EBS volume has an attribute `volume_size` then you could query all EBS volumes larger than 100GB using: `match kind = aws_ec2_volume | match volume_size > 100`.

By default all resources have Unix like `ctime`, `mtime`, `atime` attributes represented as Python datetime objects. From those attributes derived are `age`, `last_update`, `last_access`. Right now most resources support the `ctime` attribute, but fewer support `mtime` and `atime`. By default if a Cloud API does not return a modification time the value for `mtime` and `atime` is set to the current timestamp. The reasoning there is that those attributes are used to determine when a resource was last used. Typically I would want to clean up resources that have not been used in a long time not the most recent ones.

When the CLI sees that an attribute is of a certain data type it tries to convert the input value to that type as to allow comparison operations.
In the next example we will delete all unused EBS volumes larger than 100 GiB that were created before the 1st of Januar 2020 and have not been written to or read from in the past 7 days.
```
> match kind = aws_ec2_volume | match volume_size > 100 | match volume_status = available | match ctime < 2020-01-01 | match last_access > 7d | match last_update > 7d | clean
> cleanup
```

The `dump` command is useful for getting a list of a resource's attributes and event log. To dump all resources to a json file one can use `dump --json | write resources.json`

The CLI has a clipboard which can copy and paste resources. For instance: `match name ~ sre | clipboard copy; match name ~ eng | clipboard append; match name ~ sales | clipboard paste passthrough` would list all the resources with the strings 'sre', 'eng' or 'sales' in the name. The ones with name containing the strings 'sre' and 'eng' are copied to the clipboard while the ones with 'sales' are passed through after the paste.
Side note: the same could have been written as `match name ~ (sre\|eng\|sales)`. This was just to demonstrate the functionality of the clipboard command.

Now the CLI is useful for exploring collected data but if you have a repeating cleanup query it would be tedious to manually run it periodically. To that end Cloudkeeper supports an argument `--register-cli-action` which takes a lowercased event name (see [Events](#events) below) followed by a colon : and the CLI command that should be executed when that event is dispatched.
If we wanted to run our volume cleanup from earlier every time cloudkeeper has finished collecting resources, we could call it like so:
```
$ cloudkeeper --collector aws --cleanup --register-cli-action "cleanup_plan:match kind = aws_ec2_volume | match volume_size > 100 | match volume_status = available | match ctime < 2020-01-01 | match last_access > 7d | match last_update > 7d | clean"
```
As a side note, there is a plugin [plugins/cleanup_volumes/](plugins/cleanup_volumes/) that does just that. It was written before cloudkeeper had its own CLI.

Instead of passing CLI actions as commandline arguments they can also be stored in a text file and passed using the `--cli-actions-config`.


## Warning
Cloudkeeper is designed to clean up resources. As such act with caution when selecting and filtering resources for cleanup. **The default input to any CLI command is the list of all cloud resources.** Meaning when you run `match kind = aws_ec2_volume` it runs this match against all resources.
This however also means if you run `delete --yes` without any `match` or other filter before it, cloudkeeper sequentially runs the delete against all cloud resources.  
**It is the equivalent of `rm -rf /` for your cloud.**  
An even more efficient destructive command is `clean; cleanup`. In this case cloudkeeper would first mark all resources for cleaning, create a cleanup plan and then delete them in a very efficient and parallelized manner.

When doing a resource cleanup selection for the first time it is good practice to confirm the list of selected resources for plausibility using something like `match clean = true | count` or `match clean = true | count kind` before issuing the `cleanup` command.


## Data Structure
![Cloudkeeper Graph](https://raw.githubusercontent.com/someengineering/cloudkeeper/master/misc/cloudkeeper_graph.png "Cloudkeeper Graph")
Internally Cloudkeeper stores all resources inside a directed acyclic graph (DAG). Each node (resource) that is added to the graph must inherit [BaseResource](cloudkeeper/cloudkeeper/baseresources.py). Dependencies within the graph are used to determine the order of resource cleanup. Meaning a resource likely can not be deleted if it has children (successors).
During collection a new staging graph is created in parallel to the current live graph and its branches are being built up as collector plugins return their own local graphs. Once all collectors finish their work the old live graph is swapped with the staging graph making it the new live graph. This means that when querying metrics or performing CLI queries you're always working on a complete picture of all cloud resources.

Using the endoints mentioned in [Distributed Instances](#distributed-instances) this also gives you the ability to export the graph in various formats (GraphML, GEXF, JSON, etc.) and take a look at and explore your "Cloud".
![Cloudkeeper Cloud](https://raw.githubusercontent.com/someengineering/cloudkeeper/master/misc/cloudkeeper_cloud.png "Cloudkeeper Cloud")


## Plugins
Cloudkeeper knows three types of Plugins, CLI, COLLECTOR and PERSISTENT. You can find example code for each type in [plugins/example_cli/](plugins/example_cli/), [plugins/example_collector/](plugins/example_collector/) and [plugins/example_persistent/](plugins/example_persistent/).
COLLECTOR Plugins collect cloud resources and are being instanciated on each collect run. PERSISTENT plugins are instanciated once at startup and are mostly used for resource cleanup decissions or for notification (e.g. to send a Slack message to the owner of an instance that has just been deleted). CLI plugins extend the built-in CLI with new commands.

### Collector Plugins
Each collector plugin has a local graph. A collector plugin implements resource collection for a cloud provider (e.g. AWS, GCP, Azure, Alicloud, etc.).
During collection the plugin adds resources (e.g. instances, load balancers, volumes, users, etc.) to that graph. At the root of the plugin's graph is the cloud itself (e.g. 'aws'). Below that one would add one or more accounts. Below accounts Cloudkeeper expects to find regions. And within regions the plugin would add any resources as it sees fit.
The plugin can create directed edges (connections) between resources to mark a dependency. When we are talking about dependencies we are always talking about deletion dependencies not logical ones. This means that a resource that has children can not be deleted without its children being deleted first.
This sounds logical but can be rather unintuitive. For example an AWS EC2 instance would be the child of a EBS volume and not the other way around, because you can delete the instance without deleting the volume, but you can not delete the volume while it is still in use by the instance.

Once the collector finishes Cloudkeeper will take the collector plugin's graph and merge it with its own graph. In that way each plugin can independently operate on its own graph without any concurrency issues. The same pattern can be used within the plugin itself. For instance if the plugin wants to collect multiple accounts and/or multiple regions in parallel it can create a graph per account and region and merge those whenever a region has been collected.

### Persistent Plugins
Persistent plugins run on startup and can register with one or more events. This way a plugin can be notified when e.g. cleanup is about to begin.
As part of the event it would be handed a reference to the current live graph. It could then look at the resources in that graph, search for them, filter them, look at their attributes, etc. and perform actions like protecting a resource from deletion or flagging a resource for deletion.
It could also register with the event that signals the end of a run and look at which resources have been cleaned up to generate a report that could be emailed or notify resource owners on Slack that their resources have been cleaned.

### CLI Plugins
CLI plugins extend the functionality of the built-in CLI with new commands. They can act on and filter resources and have full access to the current graph, the scheduler and the CLI clipboard. CLI commands can also be used in scheduled jobs (`--scheduler-config`) and CLI actions (`--register-cli-action` and `--cli-actions-config`).


## Events
Cloudkeeper implements a simple event system. Plugins can register with and dispatch events.  
  
The current list and order of events is:
```
EventType: Data
    STARTUP: None
    START_COLLECT: None
    PROCESS_BEGIN: cloudkeeper.graph.Graph
    COLLECT_BEGIN: cloudkeeper.graph.Graph
    GENERATE_METRICS: cloudkeeper.graph.Graph
    COLLECT_FINISH: cloudkeeper.graph.Graph
    CLEANUP_PLAN: cloudkeeper.graph.Graph
    CLEANUP_BEGIN: cloudkeeper.graph.Graph
    CLEANUP_FINISH: cloudkeeper.graph.Graph
    PROCESS_FINISH: cloudkeeper.graph.Graph
    SHUTDOWN: {'reason': 'reason for shutdown', 'emergency': True/False}
```

A plugin can dispatch `START_COLLECT` if it wants Cloudkeeper to start its collect run without waiting for `--interval` seconds to pass.  
`PROCESS_BEGIN` signals the start of a loop. Within that loop resource collection, metrics generation and resource cleanup are being performed.  
`GENERATE_METRICS` is a signal for plugins that allows them to modify existing or add new metrics to the resources in the staging graph.  
`CLEANUP_PLAN` is the point that persistent cleanup plugins would usually be called. Here they can look at the tags and age of all resources and decide which ones to clean.  
`CLEANUP_BEGIN` signals the start of the cleanup process. This hook is useful for plugins that want to look at or modify the cleanup plan that was previously created.  
`SHUTDOWN` is being dispatched when the user enters `quit` or Ctrl+c in the CLI or a signal (INT/TERM) to shutdown is received. Plugins can also cause a shutdown although this function should be used sparingly. Right now there is only a single plugin [plugins/snowflake_protection/](plugins/snowflake_protection/) that makes use of this event. It is responsible for snowflake protection (protecting very special resources from deletion) and if it can not parse its config it will dispath an emergency SHUTDOWN event. This makes Cloudkeeper instantly kill the Python interpreter to ensure that no protected resources accidentally get deleted.


## Scheduling
Cloudkeeper supports scheduling of CLI commands either using the `jobs`, `add_job` and `remove_job` CLI commands or in a crontab style config file supplied to the `--scheduler-config` arg. A scheduled CLI command can be prefixed with an event name in lowercase letters followed by a colon which will make Cloudkeeper associate the command at the specified point in time to run once when the event is next triggered.

Example scheduler config file:
```
0 5 * * sat cleanup_plan:match account.id = 119548413362 | match kind ~ ^(aws_ec2_instance\|aws_alb\|aws_elb)$ | match ctime < @NOW@ | clean
0 0 * * * count kind | tee /var/log/cloudkeeper/resource_count-@TODAY@.txt
```
* First line: every Saturday at 5am schedule a command to run the next time a CLEANUP_PLAN event is dispatched. This particular command would wipe all EC2 instances and load balancers in an account with ID 119548413362 that were created before 5am that day.
* Second line: every day at midnight count the number of resources by resource type, log the output and also write it to a file with today's date in the filename.

When a command is not prefixed with an event name it is executed at the specified point in time immediately.


## Distributed Instances
Cloudkeeper comes with a built-in development webserver (defaults to Port 8000). It is meant for few internal requests (i.e. do not expose it publicly) and provides a number of endpoints:
```
  /health           # GET Returns a static 200 ok
  /metrics          # GET Returns Prometheus Metrics
  /collect          # POST Tells Cloudkeeper to do a collect run
  /graph            # GET Returns a pickled representation of the live Graph
  /graph.gexf       # GET Returns a GEXF representation of the live Graph
  /graph.graphml    # GET Returns a GraphML representation of the live Graph
  /graph.json       # GET Returns a JSON representation of the live Graph
  /graph.txt        # GET Returns a Text representation of the live Graph
```
The most useful of those will be `/metrics` and `/graph`. In our own setup we have an authentication and TLS proxy in front of our Cloudkeeper instances.
Because a single collect run can take quite a while depending on the number of accounts that need to be scraped I have gotten to a development workflow where I download the live graph to my local system and then work on that local copy.  

```
$ cloudkeeper --collector remote --remote-endpoint https://somelogin:somepassword@cloudkeeper.example.com/graph
or
$ curl -o graph https://somelogin:somepassword@cloudkeeper.example.com/graph
$ cloudkeeper --collector remote --remote-endpoint file://graph
```

The remote graph will be somewhat intelligently merged into the local graph. You can create arbitrarily deep chains of Cloudkeeper instances collecting and merging accounts in parallel from another and on the end machine they will look like all accounts were collected by a single Cloudkeeper instance.

Note that there is currently no HMAC signing or any form of authentication or data integrity verification performed inside cloudkeeper. It will serve the pickled graph at `/graph` and load whatever pickled object is provided at `--remote-endpoint`. So do not use this function over untrusted links. Otherwise a man-in-the-middle attack could lead to arbitrary code execution in the loading cloudkeeper instance.

Also note that the remote graph never contains any authentication credentials. It is just the metadata describing the resources in your account. If you want to act on those resources in a cloudkeeper cleanup instance, this instance will require its own local credentials. Think of it as me emailing you a list of resources that I want you to clean up. You will still need your own credentials to actually clean them up.
The only credential related thing that is stored within the graph is the name of the AWS role that was originally used to collect the resource - if a role was originally specified. By default Cloudkeeper would try and assume the same role again when cleaning up resources using the credentials you provide. This can be turned off and/or overridden by optionally providing your own `--aws-role` and using the `--aws-role-override` cli arg.

The `/callback` endpoint can be used together with the [remote_event_callback](plugins/remote_event_callback/) plugin to let chained instances know when to collect an updated graph.

Collector Instance
```
$ cloudkeeper -v --collector aws --remote-event-callback-endpoint process_finish:http://cleanup-instance.local:8000/callback --remote-event-callback-psk somepsk
```

Cleanup instance
```
$ cloudkeeper -v --collector remote --remote-endpoint http://collector-instance.local:8000/graph --web-psk somepsk --cleanup
```

## Docker image
Building
```
$ docker build --build-arg TESTS=true -t cloudkeeper .
```
By default the build will run the full test suite of syntax and unit tests. Specify `--build-arg TESTS=false` to skip testing.

The resulting Docker image contains a DNS cache. Running Cloudkeeper in a highly parallelized way (e.g. `--aws-fork --aws-account-pool-size 50 --gcp-fork --gcp-project-pool-size 50`) results in many API calls and as such DNS requests. When exporting the environment variable `USE_DNS_CACHE=true` into the Docker container an internal dnsmasq DNS cache will be started to reduce load on the upstream resolvers.

If instead of running Cloudkeeper permanently you would prefer to run it only at very specific points in time the Docker image supports two environment variables `USE_CROND=true` and `CRONTAB="0 */3 * * * cloudkeeper --cleanup --no-cli --one-shot --interval 0 --logfile /var/log/cloudkeeper.log --register-cli-action 'cleanup_plan:...'"` which will write the contents of `$CRONTAB` to the user's crontab and run `crond` instead of cloudkeeper. On stdout it'll tail the contents of the `/var/log/cloudkeeper.log` file. It is up to the user to instruct their cloudkeeper cron jobs to write to that file using the `--logfile` argument.


## Design Goals
- Allow easy capability extension via plugins for developers.
- Allow for useful one-liners for non-developers.
- Design CLI commands with Linux Sysadmins in mind.
- Have no external dependencies (like databases).
- Be stateless where possible.
- If there absolutely is a need for state try to persist it close to the resource (e.g. if the API does not provide a creation time, upon first discovery maybe store it in a tag but not a local json file or a shared database that users would need to have credentials for and know the configuration of).
- Allow collection to be scaled up by distributing instances.
- Assume that plugin authors know what they are doing and let them do it.
- A failure in a single plugin should not affect execution of the other plugins.
- Unhandled failure in a collector plugin should lead to all information from that plugin being discarded but not affect collection of others.
- Fail gracefully where possible. Log the error, increment an exception metrics counter and then continue the work.
- Instrument all code and create alerts and dashboards for those metrics.
- Expose complete metrics or no metrics. Do not expose partial metrics or wrong metrics.
- Implement cleanup for the most expensive resources first.
- Some cleanup is better than no cleanup.
- Usefulness over performance. E.g. if you can provide better data by making extra API calls but API calls make collection slower then default to making the calls and provide a CLI arg to turn the extra data off.
- Usefulness over resource consumption. But keep an eye on those instrumentation metrics and understand when and why you are consuming resources. Using that extra GiB of core memory is fine if I know what I am getting for it.
- Usefulness over Design Goals. Do not be dogmatic. These Design Goals are a guideline but not set in stone. Cloudkeeper and technology in general is no end in itself. If something is ugly but useful try to isolate it as much as possible. Keep the uglyness away from the core and maybe put it in a plugin that can be discarded at a later stage. Mark the code with something like a `# todo: refactor all of this` so we do not forget about it.


## Non Goals
As mentioned Cloudkeeper collects in intervals. As such it will not see resources that are created and deleted in between those intervals. If your use case for example is tracking of very short lived instances and not missing a single one of them, then Cloudkeeper is not for you. You would want something that is tighter integrated with your cloud provider and receives messages as soon as resources are created or parses an audit log. See below for a list of [Similar Projects](#similar-projects) that might be a better fit.


## TODO
- ~~Document all plugins in their README.md~~ ✔️
- Update docstrings for pdoc3 and configure automated generation/export
- Better tests for Cloudkeeper core and plugins
  - The basic test infrastructure is there and runs as part of the Docker image build
  - ~~flake8 syntax checks run with very lenient settings~~ ✔️
    - ~~Use more sane defaults than 240 char line length~~ ✔️
    - ~~Maybe give project formating in the hands of black and be done with it?~~ ✔️
  - Cloudkeeper core currently has some testing but not nearly enough
  - Plugins have virtually no testing; just a test_args.py stub that tests each plugin's args for correct default values
- Move to Poetry and pyproject.toml
- ~~Implement delete() and update/delete_tag() Methods for all resources, not just the expensive ones~~ ✔️
- Make existing delete() methods smarter - e.g. EKS Nodegroup deletion could block until the Nodegroup is gone so the EKS Cluster does not have to wait until the next collection round for its own deletion - on the other hand this would increase the number of API calls
- Distribute parallel cleanup by cloud, account and region as to optimaly use API request limits
- Implement more Cloud Providers (esp. GCP and Azure)
- Versioning via setuptools_scm?
- Should we break plugins out into separate Git repos?
- Should we upload to PyPI?


## Contributing
If you would like to contribute new plugins or other code improvements fork the repo into your own Github account, create a feature branch and submit a PR.  
Code formating tests currently use `black --line-length 88 --target-version py38` and flake8 with `max-line-length=120`. Meaning code must wrap after 88 characters but strings are allowed to be up to 120 characters long. This will change once black stable starts to wrap strings.  
If you find a bug or have a question about something please create a Github issue.


## Similar Projects
[https://github.com/cloud-custodian/cloud-custodian](https://github.com/cloud-custodian/cloud-custodian)  
[https://github.com/duo-labs/cloudmapper](https://github.com/duo-labs/cloudmapper)  
[https://github.com/duo-labs/cloudtracker](https://github.com/cloudsploit/scans)  
[https://github.com/gruntwork-io/cloud-nuke](https://github.com/gruntwork-io/cloud-nuke)  
[https://github.com/janiko71/aws-inventory](https://github.com/janiko71/aws-inventory)  
[https://github.com/lyft/cartography](https://github.com/lyft/cartography)  
[https://github.com/mlabouardy/komiser](https://github.com/mlabouardy/komiser)  
[https://github.com/nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite)  
[https://github.com/RiotGames/cloud-inquisitor](https://github.com/RiotGames/cloud-inquisitor)  
[https://github.com/turnerlabs/antiope](https://github.com/turnerlabs/antiope)  
[https://github.com/cloudquery/cloudquery](https://github.com/cloudquery/cloudquery)  


## Attribution
[misc/cloudkeeper.png](misc/cloudkeeper.png) [robot maid](https://thenounproject.com/term/robot-maid/2838673) by VINZENCE STUDIO from [the Noun Project](https://thenounproject.com/)


## License
```
Copyright 2021 Some Engineering Inc.
Copyright 2019-2021 D2iQ, Inc.

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
