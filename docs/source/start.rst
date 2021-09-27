.. highlight:: bash

Quick start
===========
In this quick start guide, we’re showing you three things, how to:

    #. install Cloudkeeper for AWS with docker
    #. use the Cloudkeeper CLI to run your first ``collect`` process
    #. query the results of the collect process 

The docker set-up takes 2-5 minutes. The duration of the first collect process depends on the size of your environment - usually 2-5 minutes. 

| Examples and data in this documentation are based on a small AWS `cloud9 <https://aws.amazon.com/cloud9/>`_ environment.
| To start exploring you need AWS credentials and a working docker environment with access to AWS APIs.
| We assume you are familiar with basic docker operations and how to operate a linux shell.

AWS Credentials
---------------
For this demo you need an `AWS IAM User <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html>`_ with `Access Key <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html>`_.

Run Cloudkeeper
---------------
Assuming `docker <https://www.docker.com/get-started>`_ is already present, run the latest Cloudkeeper release:

::

    $ docker run -t -v "${HOME}"/data/test:/data:rw \
    -e AWS_ACCESS_KEY_ID=YOURKEYID -e AWS_SECRET_ACCESS_KEY='YOURACCESSKEY' \
    -e CKWORKER_COLLECTOR=”aws example” \
    --name cloudkeeper ghcr.io/someengineering/cloudkeeper > cloudkeeper.log


Start the Cloudkeeper CLI
-------------------------
You interact with `ckcore <https://github.com/someengineering/cloudkeeper/tree/main/ckcore>`_ via `cksh <https://github.com/someengineering/cloudkeeper/tree/main/cksh>`_
::

    $ docker exec -it cloudkeeper cksh

Collect AWS Inventory
---------------------
::

    > start_task collect
    > tasks
    id: 501d6048-1e2e-11ec-ace0-330e870b1c75
    started_at: '2021-09-25T18:28:00Z'
    descriptor:
    id: collect
    name: collect


Depending on infrastructure size, the collect process usually takes anywhere between 2-5 minutes. Huge cloud accounts (>500+ instances) can take up to 15 minutes.


The ``collect`` task runs every full hour. Cloudkeeper persists data in $HOME/data/test/db (`ArangoDB <https://www.arangodb.com/learn/>`_) and $HOME/data/test/tsdb (`Prometheus <https://prometheus.io/docs/prometheus/latest/getting_started/>`_).

| *Hint:*
| You can observe the collect process in the logs

::

    $ grep ckcore cloudkeeper.log | grep 501d6048-1e2e-11ec-ace0-330e870b1c75
    [INFO] Task 501d6048-1e2e-11ec-ace0-330e870b1c75: begin step is: pre_collect [core.task.task_description]
    [INFO] Task 501d6048-1e2e-11ec-ace0-330e870b1c75: begin step is: collect [core.task.task_description]
    [INFO] Start new task: collect with id 501d6048-1e2e-11ec-ace0-330e870b1c75 [core.task.task_handler]
    [INFO] Incoming message: type=1 data={"kind": "action_done", "message_type": "collect", "data": {"task": "501d6048-1e2e-11ec-ace0-330e870b1c75", "step": "collect"}} extra= [core.web.api]
    [INFO] Task 501d6048-1e2e-11ec-ace0-330e870b1c75: begin step is: post_collect [core.task.task_description]
    [INFO] Task 501d6048-1e2e-11ec-ace0-330e870b1c75: begin step is: pre_metrics [core.task.task_description]
    [INFO] Task 501d6048-1e2e-11ec-ace0-330e870b1c75: begin step is: metrics [core.task.task_description]
    [INFO] Incoming message: type=1 data={"kind": "action_done", "message_type": "generate_metrics", "data": {"task": "501d6048-1e2e-11ec-ace0-330e870b1c75", "step": "metrics"}} extra= [core.web.api]
    [INFO] Task 501d6048-1e2e-11ec-ace0-330e870b1c75: begin step is: post_metrics [core.task.task_description]
    [INFO] Task 501d6048-1e2e-11ec-ace0-330e870b1c75: begin step is: task_end [core.task.task_description]

Almost done
-----------
Count the resources available in Cloudkeeper
::

    > match is(resource) | count
    matched: 278
    not_matched: 0

What is your number? Let us know in `Discord <https://discord.gg/3G3sX6y3bt>`_!

| Reach out to us if you have any questions, improvements, bugs!
| Contributions are very much appreciated.

| Discord:
| https://discord.gg/3G3sX6y3bt

| GitHub Issue:
| https://github.com/someengineering/cloudkeeper/issues/new 
