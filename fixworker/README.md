# `fixworker`
Fix worker daemon


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
`fixworker` does all the collection and cleanup work in Fix. It is connected to [`fixcore`](../fixcore/) over a websocket connection and waits for instructions. By default it subscribes to the `collect` and `cleanup` actions as well as `tag` tasks.

`fixworker` loads collector [`plugins`](../plugins/) like AWS, GCP, Slack, Onelogin, etc.
Only those plugins have knowledge about how to communicate with each cloud. How to collect resources and how to clean them up.

There can be one or more instances of `fixworker` in a Fix deployment. A single `fixworker` can collect many clouds or you could have multiple `fixworker` collecting one cloud or even one account in one cloud each.

More information can be found below and in [the docs](https://inventory.fix.security/docs/concepts/components/worker).


## Usage
`fixworker` uses the following commandline arguments:
```
  --subscriber-id SUBSCRIBER_ID
                        Unique subscriber ID (default: fix.worker)
  --psk PSK             Pre-shared key
  --verbose, -v         Verbose logging
  --quiet               Only log errors
  --fixcore-uri FIXCORE_URI
                        fixcore URI (default: https://localhost:8900)
  --override CONFIG_OVERRIDE [CONFIG_OVERRIDE ...]
                        Override config attribute(s)
  --ca-cert CA_CERT     Path to custom CA certificate file
  --cert CERT           Path to custom certificate file
  --cert-key CERT_KEY   Path to custom certificate key file
  --cert-key-pass CERT_KEY_PASS
                        Passphrase for certificate key file
  --no-verify-certs     Turn off certificate verification
```

ENV Prefix: `FIXWORKER_`
Every CLI arg can also be specified using ENV variables.

For instance the boolean `--fork` would become `FIXWORKER_FORK=true`.


## Details
Once `fixworker` is started you do not have to interact with it at all. It will just sit there, wait for work and do its job. The following are details on how `fixworker` works internally and how it integrates with `fixcore`.


### Actions and Tasks
Think of actions and tasks like topics and queues in a messaging system. Actions are broadcast to everyone subscribed for that action. A task is always given to exactly one worker that knows how to handle it.


#### Actions
When the `collect` workflow within `fixcore` is triggered (by either an event or a schedule or because the user manually triggered it), `fixcore` will broadcast a ***"start collecting all the cloud accounts you know about"*** message to all the subscribed workers.
Once all the workers finish collecting and sent their graph to the core, the workflow will proceed to the next step which would be `plan_cleanup`. This one tells anyone interested to start planing their cleanup based on the just collected graph data. Once everyone has planed their cleanup and flagged resources that should get cleaned up with the `desired.clean = true` flag, the workflow proceeds to the `cleanup` step which again notifies anyone subscribed to now perform cleanup of those flagged resources. Because the cleaner within `fixworker` has knowledge of all dependencies in the graph, it will ensure that resources are cleaned up in the right order.


#### Tasks
When a plugin or a user decides that a resource tag should be added, changed or removed, e.g. by running
```
search id = i-039e06bb2539e5484 | tag update owner lukas
```
`fixcore` will put this tagging task onto a task queue. This task is then consumed by a `fixworker` that knows how to perform tagging for that particular resource and its particular cloud and account. In our example above where we are setting the tag `owner: lukas` for an AWS EC2 instance with ID `i-039e06bb2539e5484` the task would be given to a `fixworker` that knows how to update AWS EC2 instance tags in that resources account.


## Contact
If you have any questions feel free to [join our Discord](https://discord.gg/fixsecurity) or [open a GitHub issue](https://github.com/someengineering/fix/issues/new).


## License
See [LICENSE](../LICENSE) for details.
