.. _introduction:

.. raw:: html

   <div class="sparta">Cloudkeeper is an open-source tool doing <b>“housekeeping for clouds”</b> - find leaky resources, manage quota limits, detect drift and clean up.</div>


============
Introduction
============

.. code-block:: none
    :caption: Hello World in Cloudkeeper 🌍
    
    match is(resource) | count
    total matched: 459241
    total unmatched: 0

Welcome to the official Cloudkeeper documentation!

What is Cloudkeeper?
********************

The official `GitHub repository can be found here <https://github.com/someengineering/cloudkeeper>`_.

Cloudkeeper indexes resources, captures dependencies and maps out your infrastructure in an understandable graph. The graph contains metrics for each resource.

Developers and SREs can **search the graph with a query language**, and create **alerting and clean-up workflows**.

Metrics can be aggregated and exported to a time series database like Prometheus.

Is Cloudkeeper the tool I am looking for?
-----------------------------------------

If you ever

- had a standstill in your CI pipeline because a broken job leaked cloud resources which triggered a :ref:`quota limit <ql-kind-quota>`
- wanted to find all :ref:`expired certificate <ql-kind-certificate>`
- had to :ref:`change the tags <action_tags>` of thousands of EC2 instances at once
- needed to delete all :ref:`unused EBS volumes <ql-kind-volume>` that had no I/O in the past month
- wished for a god view that lets you explore all cloud usage across all clouds
- reported the cost of a project across different accounts or even across clouds
- cleaned up :ref:`orphaned load balancers <ql-kind-aws_alb>` that had no active backends
- wanted to automate any of the above

then you know the kind of situations Cloudkeeper was built for and you will love it.

Supported Clouds and Integrations
*********************************
Cloudkeeper collects data using simple plugins written in Python.

**The following plugins are supplied at the moment:**

- AWS
- Google Cloud
- VMWare Vsphere
- OneLogin
- Kubernetes
- Slack

The latter can also be used for notification of resource cleanups.

.. hint::
    If the cloud or service you are using is not listed, it is easy to write your own collector plugin.

    Here is an `example plugin <https://github.com/someengineering/cloudkeeper/blob/main/plugins/example_collector>`_.

Get in touch
************
If you need support, have feedback, questions, plugins and everything else you can think of, don't hesitate to join our Discord - We're looking forward to talk!

| Discord:
| https://discord.gg/someengineering

You found a bug, have ideas or a proposal? Head over to our GitHub issues:

| GitHub Issues:
| https://github.com/someengineering/cloudkeeper/issues/new 
