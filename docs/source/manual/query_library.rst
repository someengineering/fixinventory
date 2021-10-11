=============
Query library
=============

In this library we collect and describe common queries for cloudkeeper.

By kind
*******

.. _ql-kind-aws_alb:

aws_alb
=======

Orphaned Load Balancers that have no active backend
---------------------------------------------------

.. code-block:: bash
    
    match is(aws_alb) and ctime < -7d and backends==[] with(empty, <-- is(aws_alb_target_group) and target_type = instance and ctime < -7d with(empty, <-- is(aws_ec2_instance) and instance_status != terminated)) <-[0:1]- is(aws_alb_target_group) or is(aws_alb)

.. _ql-kind-certificate:

certificate
===========

Find expired ssl certificates currently in use
----------------------------------------------

.. code-block:: bash
    
    match is(certificate) and expires < @NOW@ <--

.. _ql-kind-quota:

quota
=====

Find current quota consumption to prevent service interruptions
---------------------------------------------------------------

.. code-block:: bash
    
    match is(quota) and usage > 0

.. _ql-kind-volume:

volume
======

Discover unused volumes
--------------------------------------------------------------------

.. code-block:: bash
    :caption: Find unused volumes older than 30 days with no IO in the past 7 days
    
    match is(volume) and ctime < -30d and atime < -7d and mtime < -7d and volume_status = available

Query missing?
**************

| If we missed your super useful query, you have questions or found a bug: reach out to us!
| Contributions are very much appreciated.

| Discord:
| https://discord.gg/someengineering

| GitHub Issues:
| https://github.com/someengineering/cloudkeeper/issues/new
