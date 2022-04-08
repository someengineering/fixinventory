# `resotoworker`
Resoto worker daemon


## Table of contents

* [Overview](#overview)
* [Usage](#usage)
    * [Example usage](#example-usage)
* [Details](#details)
    * [Actions and Tasks](#actions-and-tasks)
        * [Actions](#actions)
        * [Tasks](#tasks)
* [Contact](#contact)
* [License](#license)


## Overview
`resotoworker` does all the collection and cleanup work in Resoto. It is connected to [`resotocore`](../resotocore/) over a websocket connection and waits for instructions. By default it subscribes to the `collect` and `cleanup` actions as well as `tag` tasks.

`resotoworker` loads collector [`plugins`](../plugins/) like AWS, GCP, Slack, Onelogin, etc.
Only those plugins have knowledge about how to communicate with each cloud. How to collect resources and how to clean them up.

There can be one or more instances of `resotoworker` in a Resoto deployment. A single `resotoworker` can collect many clouds or you could have multiple `resotoworker` collecting one cloud or even one account in one cloud each.

More information can be found below and in [the docs](https://resoto.com/docs/concepts/components/worker).


## Usage
`resotoworker` uses the following commandline arguments:
```
  --subscriber-id SUBSCRIBER_ID
                        Unique subscriber ID (default: resoto.worker)
  --psk PSK             Pre-shared key
  --verbose, -v         Verbose logging
  --quiet               Only log errors
  --resotocore-uri RESOTOCORE_URI
                        resotocore URI (default: https://localhost:8900)
  --override CONFIG_OVERRIDE [CONFIG_OVERRIDE ...]
                        Override config attribute(s)
  --ca-cert CA_CERT     Path to custom CA certificate file
  --cert CERT           Path to custom certificate file
  --cert-key CERT_KEY   Path to custom certificate key file
  --cert-key-pass CERT_KEY_PASS
                        Passphrase for certificate key file
  --no-verify-certs     Turn off certificate verification
```

ENV Prefix: `RESOTOWORKER_`
Every CLI arg can also be specified using ENV variables.

For instance the boolean `--fork` would become `RESOTOWORKER_FORK=true`.


## Details
Once `resotoworker` is started you do not have to interact with it at all. It will just sit there, wait for work and do its job. The following are details on how `resotoworker` works internally and how it integrates with `resotocore`.


### Actions and Tasks
Think of actions and tasks like topics and queues in a messaging system. Actions are broadcast to everyone subscribed for that action. A task is always given to exactly one worker that knows how to handle it.


#### Actions
When the `collect` workflow within `resotocore` is triggered (by either an event or a schedule or because the user manually triggered it), `resotocore` will broadcast a ***"start collecting all the cloud accounts you know about"*** message to all the subscribed workers.
Once all the workers finish collecting and sent their graph to the core, the workflow will proceed to the next step which would be `plan_cleanup`. This one tells anyone interested to start planing their cleanup based on the just collected graph data. Once everyone has planed their cleanup and flagged resources that should get cleaned up with the `desired.clean = true` flag, the workflow proceeds to the `cleanup` step which again notifies anyone subscribed to now perform cleanup of those flagged resources. Because the cleaner within `resotoworker` has knowledge of all dependencies in the graph, it will ensure that resources are cleaned up in the right order.


#### Tasks
When a plugin or a user decides that a resource tag should be added, changed or removed, e.g. by running
```
search id = i-039e06bb2539e5484 | tag update owner lukas
```
`resotocore` will put this tagging task onto a task queue. This task is then consumed by a `resotoworker` that knows how to perform tagging for that particular resource and its particular cloud and account. In our example above where we are setting the tag `owner: lukas` for an AWS EC2 instance with ID `i-039e06bb2539e5484` the task would be given to a `resotoworker` that knows how to update AWS EC2 instance tags in that resources account.


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
