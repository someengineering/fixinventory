# `ckworker`
Cloudkeeper worker daemon


## Table of contents

* [Overview](#overview)
* [Usage](#usage)
    * [Example usage](#example-usage)
* [Details](#details)
    * [Tasks and jobs](#tasks-and-jobs)
        * [Tasks](#tasks)
        * [Jobs](#jobs)
* [Contact](#contact)
* [License](#license)


## Overview
`ckworker` does all the collection and cleanup work in Cloudkeeper. It is connected to [`ckcore`](../ckcore/) over a websocket connection and waits for instructions. By default it subscribes to the `collect` and `cleanup` tasks as well as `tag` jobs.

`ckworker` loads collector [`plugins`](../plugins/) like AWS, GCP, Slack, Onelogin, etc.
Only those plugins have knowledge about how to communicate with each cloud. How to collect resources and how to clean them up.


## Usage
`ckworker` uses the following commandline arguments:
```
  -h, --help            show this help message and exit
  --verbose, -v         Verbose logging
  --logfile LOGFILE     Logfile to log into
  --collector COLLECTOR [COLLECTOR ...]
                        Collectors to load (default: all)
  --cleanup             Enable cleanup of resources (default: False)
  --cleanup-pool-size CLEANUP_POOL_SIZE
                        Cleanup thread pool size (default: 10)
  --cleanup-dry-run     Cleanup dry run (default: False)
  --ckcore-uri CKCORE_URI
                        ckcore URI (default: http://localhost:8900)
  --ckcore-ws-uri CKCORE_WS_URI
                        ckcore Websocket URI (default: ws://localhost:8900)
  --ckcore-graph CKCORE_GRAPH
                        ckcore graph name (default: ck)
  --pool-size POOL_SIZE
                        Collector Thread/Process Pool Size (default: 5)
  --fork                Use forked process instead of threads (default: False)
  --timeout TIMEOUT     Collection Timeout in seconds (default: 10800)
  --debug-dump-json     Dump the generated json data (default: False)
  ```

ENV Prefix: `CKWORKER_`
Every CLI arg can also be specified using ENV variables.

For instance the boolean `--fork` would become `CKWORKER_FORK=true` or `--collector aws gcp` would become `CKWORKER_COLLECTOR="aws gcp"`.

*Important* Every plugin will add its own CLI args to those of `ckworker`. Check the individual plugin documentation for details or use `ckworker --help` to see the complete list.

### Usage examples
```
$ ckworker \
    --verbose \
    --fork \
    --collector aws \
    --aws-fork \
    --aws-account-pool-size 50 \
    --aws-access-key-id AKIAZGZEXAMPLE \
    --aws-secret-access-key vO51EW/8ILMGrSBV/Ia9FEXAMPLE \
    --aws-role Cloudkeeper \
    --aws-scrape-org
```

Let us unpack this command
- `verbose` turn on verbose logging
- `fork` makes `ckworker` fork each collector plugin instead of using threads
- `collector aws` loads the AWS collector plugin
- `aws-fork` tells the AWS collector plugin to also use forked processes instead of threads
- `aws-access-key-id/-secret-access-key` AWS credentials for API acces. Instead of using credentials directly you can also opt to inherit them from the environment e.g. using an `AWS_PROFILE` or when running on EC2 using an instance profile.
- `aws-role` the IAM role Cloudkeeper should assume when making API requests
- `aws-scrape-org` tells the AWS collector plugin to retrieve a list of all org accounts and then assume into each one of them.

The reason for using forked processes instead of threads is to work around performance limitations of Python's [GIL](https://en.wikipedia.org/wiki/Global_interpreter_lock). By forking we almost scale linearly with the number of CPU cores when collecting many accounts at once. The default is to use threads to conserve system resources.


## Details
### Tasks and jobs
Think of tasks and jobs like topics and queues in a messaging system.

#### Tasks
When the `collect` workflow within `ckcore` is triggered (bei either an event or a schedule or because the user manually triggered it), `ckcore` will broadcast a ***"start collecting all the cloud accounts you know about"*** message to all the subscribed workers.
Once all the workers finish collecting and sent their graph to the core, the workflow will proceed to the next step which would be `plan_cleanup`. This one tells anyone interested to start planing their cleanup based on the just collected graph data. Once everyone has planed their cleanup and flagged resources that should get cleaned up with the `desired.clean = true` flag, the workflow proceeds to the `cleanup` step which again notifies anyone subscribed to now perform cleanup.


#### Jobs
When a plugin or a user decides that a resource tag should be added, changed or removed, e.g. by running
```
match id = i-039e06bb2539e5484 | tag update owner lukas
```
`ckcore` will puth this tagging job onto a queue. This queue is then consumed by a `ckworker` that knows how to perform tagging for that particular resource and its particular cloud and account. In or example above where we are setting the tag `owner: lukas` for an AWS EC2 instance with ID `i-039e06bb2539e5484` the job would be given to a `ckworker` that knows how to update AWS EC2 instance tags in that resources account.


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
