.. highlight:: bash
.. _quickstart:

Quick start
***********
In this quick start guide, we’re showing you three things, how to:

    #. install Cloudkeeper for AWS with docker
    #. use the Cloudkeeper CLI to run your first ``collect`` process
    #. query the results of the collect process 

The docker set-up takes 2-5 minutes. The duration of the first collect process depends on the size of your environment - usually 5-10 minutes. 

| Examples and data in this documentation are based on a small AWS `Cloud9 <https://aws.amazon.com/cloud9/>`_ environment.
| To start exploring you need AWS credentials and a working Docker environment with access to AWS APIs.
| We assume you are familiar with basic Docker operations and how to operate a Linux shell.

Install & Run Cloudkeeper
=========================

AWS Credentials
---------------
For this demo you need an `AWS IAM User <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html>`_ with `Access Key <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html>`_.

Run Cloudkeeper
---------------
Assuming `docker <https://www.docker.com/get-started>`_ is already present, run the latest Cloudkeeper release.
Replace ``YOURKEYID`` and ``YOURACCESSKEY`` to collect your AWS inventory.

::
    $ mkdir -p ~/data/test
    $ docker run -d -v "${HOME}/data/test":/data:rw \
    -e AWS_ACCESS_KEY_ID=YOURKEYID -e AWS_SECRET_ACCESS_KEY='YOURACCESSKEY' \
    -e CKWORKER_COLLECTOR=”aws example” \
    --name cloudkeeper ghcr.io/someengineering/cloudkeeper:2.0.0a5

Start the Cloudkeeper CLI
=========================
You interact with `ckcore <https://github.com/someengineering/cloudkeeper/tree/main/ckcore>`_ via `cksh <https://github.com/someengineering/cloudkeeper/tree/main/cksh>`_

::

    $ docker exec -it cloudkeeper cksh


| `ckcore <https://github.com/someengineering/cloudkeeper/tree/main/ckcore>`_ the platform maintaining the `MultiDiGraph <https://en.wikipedia.org/wiki/Multigraph#Directed_multigraph_(edges_with_own_identity)>`_.
| `cksh <https://github.com/someengineering/cloudkeeper/tree/main/cksh>`_ the Cloudkeeper shell to interact with the core.

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

    $ docker logs -f cloudkeeper | grep ckcore cloudkeeper.log | grep 501d6048-1e2e-11ec-ace0-330e870b1c75
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

You have this many ressources!
------------------------------
Count the resources available in Cloudkeeper
::

    > match is(resource) | count
    total matched: 280
    total unmatched: 0

What is your number? Let us know in `Discord <https://discord.gg/3G3sX6y3bt>`_!

.. highlight:: bash

Usage of the Cloudkeeper CLI
============================
In this section we show you how to use Cloudkeeper CLI(`cksh <https://github.com/someengineering/cloudkeeper/tree/main/cksh>`_) to discover your infrastructure by selecting, filtering and counting your resources.

How to access help
------------------------------------------------
| `cksh <https://github.com/someengineering/cloudkeeper/tree/main/cksh>`_ ``help`` command list all commands available.
| Guidance for a specific command is ``help <command>``

::

    > help
    ckcore CLI
    Valid placeholder string:
    @UTC@ -> 2021-09-25T19:11:19Z
    [...]
    Available Commands:
    add_job - Add job to the system.
    [...]
    Available Aliases:
    match (reported) - Matches a property in the reported section.
    [...]
    Note that you can pipe commands using the pipe character (|)
    and chain multiple commands using the semicolon (;).

This cksh output is shortened for readability.

List your resource types
------------------------
``kind`` lists all resource types currently available for exploration.
::

    > help kind
    > kind
    [...]
    - aws_account
    - aws_alb
    - aws_alb_quota
    - aws_alb_target_group
    - aws_cloudformation_stack
    - aws_ec2_instance
    - aws_ec2_instance_quota
    - aws_ec2_instance_type
    - aws_ec2_internet_gateway
    - aws_ec2_internet_gateway_quota
    - aws_ec2_network_acl
    - aws_ec2_network_interface
    - aws_ec2_route_table
    - aws_ec2_security_group
    - aws_ec2_subnet
    - aws_ec2_volume
    - aws_ec2_volume_type
    - aws_elb_quota
    - aws_iam_access_key
    - aws_iam_group
    - aws_iam_policy
    - aws_iam_role
    - aws_iam_server_certificate_quota
    - aws_iam_user
    - aws_region
    - aws_resource
    - aws_s3_bucket
    - aws_s3_bucket_quota
    - aws_vpc
    - aws_vpc_quota
    [...]
    - resource
    [...]


See full list of currently `supported AWS ressources <https://github.com/someengineering/cloudkeeper/blob/main/plugins/aws/cloudkeeper_plugin_aws/resources.py>`_.

We add new resources every week. Please star this `repo <http://github.com/someengineering/cloudkeeper>`_ to support us and stay up to date. If you’d like to request a specific resource, join our `Discord <https://discord.gg/3G3sX6y3bt>`_ channel and let us know!. 

Query your resource types
-------------------------
``match`` matches the collected values from your AWS Infrastructure
::

    > help match
    > match is(aws_ec2_instance) limit 1
    reported:
    kind: aws_ec2_instance
    id: i-03df836cdd46e2f94
    tags:
        aws:cloud9:environment: 7135ada88b05425aa8a6238dd30b58af
        email: neil@some.engineering
        Name: aws-cloud9-keepercore-documentation-7135ada88b05425aa8a6238dd30b58af
        aws:cloudformation:logical-id: Instance
        aws:cloud9:owner: AIDA42373V3XEXWC6AHSG
        aws:cloudformation:stack-name: aws-cloud9-keepercore-documentation-7135ada88b05425aa8a6238dd30b58af
        aws:cloudformation:stack-id: arn:aws:cloudformation:us-east-2:882323420974:stack/aws-cloud9-keepercore-documentation-7135ada88b05425aa8a6238dd30b58af/d068f250-0fc7-11ec-a7db-0a05d1ef2266
    name: aws-cloud9-keepercore-documentation-7135ada88b05425aa8a6238dd30b58af
    ctime: '2021-09-24T15:37:30Z'
    instance_cores: 2
    instance_memory: 8
    instance_type: m5.large
    instance_status: stopped
    metadata:
    ancestors:
        cloud:
        name: aws
        id: aws
        account:
        name: someengineering
        id: '882323420974'
        region:
        name: us-east-2
        id: us-east-2
    kinds:
    - resource
    - aws_ec2_instance
    - instance
    - aws_resource

Count and filter your resources
-------------------------------
``count`` will give you the number of incoming elements.
This provides information on the number of items you are interacting with.
::

    > help count
    > match is(aws_ec2_instance) | count
    total matched: 1
    total unmatched: 0

This will count all ``aws_ec2_instance`` that are older than 24h.
Both commands are identical, the 2nd one makes use of predefined placeholder strings.
::

    > match is(aws_ec2_instance) ctime < -1d | count
    > match is(aws_ec2_instance) ctime < "@YESTERDAY@" | count

| ``help`` provides all available placeholder strings in section ``Valid placeholder string``
| ``match`` automatically filters for the ``reported`` section of the response. With commands like ``query`` you need to explicitly select the reported section.  ``ctime`` is then selected via ``reported.ctime``.

| ``count`` has another handy feature: building a sum over a provided parameter results. 
| In this case: ``reported.instance_cores``.
| This will sum the number of instance_cores for all ``aws_ec2_instances`` that were created before yesterday, groups them by reported.instance_cores results and counts the occurences of them.

::

    > match is(aws_ec2_instance) ctime < "@YESTERDAY@" | count reported.instance_cores
    2: 1                         ← Number of occurences of reported.instance_cores = 2
    1: 1                         ← Number of occurences of reported.instance_cores = 1
    total matched: 2
    total unmatched: 0

As a small reminder: ``reported.instance_cores`` references to data from matched ``aws_ec2_instances``

::

    > match is(aws_ec2_instance)
    reported:
    kind: aws_ec2_instance
    [...]
    ctime: '2021-09-24T15:37:30Z'    ← reported.ctime < "@YESTERDAY@"
    instance_cores: 2                ← reported.instance_cores
    [...]
    kinds:
    - resource
    - aws_ec2_instance
    - instance
    - aws_resource
    ---
    reported:
    kind: aws_ec2_instance
    [...]
    ctime: '2021-09-11T15:37:30Z'    ← reported.ctime < "@YESTERDAY@"
    instance_cores: 1                ← reported.instance_cores
    [...]
    kinds:
    - resource
    - aws_ec2_instance
    - instance
    - aws_resource

Output is shortened for documentation purposes

You made it!
============
Congratulations, you have now finished our basic starters tutorial.
Thank you so much for exploring Cloudkeeper. This is just the beginning.

What now?
---------
All documentation is under heavy development, including this tutorial.
We extend and improve this documentation almost daily. Please star this `repo <http://github.com/someengineering/cloudkeeper>`_ to support us and stay up to date.

| Please explore Cloudkeeper, build your queries and discover your infrastructure.
| A good place to continue is joining our community to get the most out of Cloudkeeper and the experiences collected from many different SREs, companies and curious people.
| We would love to hear from you with your feedback, experiences and interesting queries and use cases.

How you get more assistance
---------------------------

| Reach out to us if you have any questions, improvements, bugs!
| Contributions are very much appreciated.

| Discord:
| https://discord.gg/3G3sX6y3bt

| GitHub Issue:
| https://github.com/someengineering/cloudkeeper/issues/new
