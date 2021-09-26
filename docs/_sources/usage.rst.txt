.. highlight:: bash

Usage
=====
Selecting, filtering and counting your resources
------------------------------------------------
In this section we show you how to use cloudkeeper CLI(`cksh <https://github.com/someengineering/cloudkeeper/tree/main/cksh>`_) to discover your infrastructure by selecting, filtering and counting your resources.

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

We add new resources every week. Please watch or star this repo to receive updates. If you’d like to request a specific resource, join our Discord channel and let us know!. 

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

``count`` will give you the number of incoming elements.
This provides information on the number of items you are interacting with.
::

    > help count
    > match is(aws_ec2_instance) | count
    matched: 1
    not_matched: 0

This will count all ``aws_ec2_instance`` that are older than 24h.
Both commands are identical, the 2nd one makes use of predefined placeholder strings.
::

    > match is(aws_ec2_instance) reported.ctime < -1d | count
    > match is(aws_ec2_instance) reported.ctime < "@YESTERDAY@" | count

| ``help`` provides all available placeholder strings in section ``Valid placeholder string``
| ``match`` automatically filters for the ``reported`` section of the response. ``reported.ctime`` can be shortened to ``ctime``.
| We will omit this starting with our next example.

| ``count`` has another handy feature: building a sum over a provided parameter.
| In this case: ``reported.instance_cores``.
| This will sum the number of instance_cores for all ``aws_ec2_instances`` that were created before yesterday.

::

    > match is(aws_ec2_instance) ctime < "@YESTERDAY@" | count reported.instance_cores
    matched: 3                   ← sum of 2+1 instance_cores, see output below
    not_matched: 0

As a small reminder: ``reported.instance_cores`` references to data from matched ``aws_ec2_instances``

::

    > reported is(aws_ec2_instance)
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

| Reach out to us if you have any questions, improvements, bugs!
| Contributions are very much appreciated.

| Discord:
| https://discord.gg/3G3sX6y3bt

| GitHub Issue:
| https://github.com/someengineering/cloudkeeper/issues/new 