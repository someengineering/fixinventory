=============
Query library
=============

In this library we collect and describe common queries for Resoto.

If a query you need is missing, please jump to our :ref:`query_missing` section on how you can get help.

.. hint::
 All queries listed here are safe to use, as they will *NOT* modify your resources.

By kind
*******

.. _ql-kind-aws_alb:

aws_alb
=======

Orphaned Load Balancers that have no active backend
---------------------------------------------------

.. code-block:: bash

    query is(aws_alb) and age > 7d and backends==[] with(empty, <-- is(aws_alb_target_group) and target_type = instance and age > 7d with(empty, <-- is(aws_ec2_instance) and instance_status != terminated)) <-[0:1]- is(aws_alb_target_group) or is(aws_alb)

aws_iam_access_key
==================

Number of active access keys per user
-------------------------------------

.. code-block:: bash
    :caption: Ensure there is only one active access key available for any single IAM user

    query is(access_key) access_key_status = "Active" | aggregate user_name as user : sum(1) as number_of_keys

.. _ql-kind-certificate:

certificate
===========

Find expired ssl certificates currently in use
----------------------------------------------

.. code-block:: bash

    query is(certificate) and expires < @NOW@ <--

.. _ql-kind-quota:

quota
=====

Find current quota consumption to prevent service interruptions
---------------------------------------------------------------

.. code-block:: bash

    query is(quota) and usage > 0

.. _ql-kind-volume:

volume
======

Discover unused AWS volumes
---------------------------

.. code-block:: bash
    :caption: Find unused AWS volumes older than 30 days with no IO in the past 7 days

    query is(aws_ec2_volume) and age > 30d and last_access > 7d and last_update > 7d and volume_status = available

.. _query_missing:

Query missing?
**************

If you need support, have feedback, questions, queries and everything else you can think of, don't hesitate to join our Discord - We're looking forward to talk!

| Discord:
| https://discord.gg/someengineering

You found a bug, have ideas or a proposal? Head over to our GitHub issues:

| GitHub Issues:
| https://github.com/someengineering/resoto/issues/new
