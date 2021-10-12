.. _action:

======
Action
======

You can modify your discovered cloud resources by using Cloudkeepers powerful commands like ``tag`` or ``clean``.

To learn about your new superpowers and use them in the best way, it is important to understand how Cloudkeeper handles commands in the background.

.. warning::
    | Cloudkeeper will **NOT** delete resources marked for deletion by default!
    | Read more about this here: :ref:`delete_warning`

How Cloudkeeper maintains your resources
****************************************

| Cloudkeeper does the housekeeping for you. It automatically uses workflows in the background to achive this which are triggered by events or by a specific time.
| Therefor there typically is no need to trigger them manually in daily operations.

Workflows
=========

| Cloudkeeper has four workflows we will now explain.
| In our examples all workflows are triggered by the ``start_workflow`` command via :ref:`component-cksh`.

:ref:`workflow-collect_and_cleanup` has an additional, built in, trigger by time. It runs every full hour.

.. _workflow-collect:

collect
-------
.. code-block::
    :caption: Start collect workflow
    
        > start_workflow collect
        
This will trigger all :ref:`plugins` to this workflow.
As an additional step, this workflow will trigger :ref:`workflow-metrics` aswell, which will put :ref:`component-ckmetrics` into action.

.. _workflow-cleanup:

cleanup
-------

This workflow triggers all :ref:`plugins` to delete ressources they manage, that were previously marked as to be cleand.
To activate this feature, :ref:`setup-ckworker` needs to be started with the ``--cleanup`` parameter.
Otherwise it will NOT delete any ressources.
You can provide ``--cleanup-dry-run`` to :ref:`setup-ckworker` startup to print what it would do without actually doing it.

.. code-block::
    :caption: Start cleanup workflow
    
        > start_workflow cleanup
        
As an additional step, this workflow will trigger :ref:`workflow-metrics` aswell.

.. _workflow-metrics:

metrics
-------

.. code-block::
    :caption: Start metrics workflow
    
        > start_workflow metrics
        
This will put :ref:`component-ckmetrics` into action.

.. _workflow-collect_and_cleanup:

collect_and_cleanup
-------------------
This workflow combines :ref:`workflow-collect`, :ref:`workflow-cleanup` and :ref:`workflow-metrics` into one.

You can trigger this workflow also like the others via :ref:`component-cksh` command.

.. code-block::
    :caption: Start collect_and_cleanup workflow
    
        > start_workflow collect_and_cleanup

The :ref:`workflow-collect_and_cleanup` workflow is hardwired to run automatically every full hour.


.. _action_tags:

Working with tags
*****************

Tags are a very useful to organise your cloud infrastructure and provide additional information to your resources.
Cloudkeeper provides a powerful command to mass create, update or delete tags to keep everything clean and tidy.

.. code-block:: bash
    :caption: update tag ``owner`` of instance ``i-039e06bb2539e5484`` if present, create if new.

    match id = i-039e06bb2539e5484 | tag update owner lukas

.. code-block:: bash
    :caption: delete tag ``owner`` from instance ``i-039e06bb2539e5484``

    match id = i-039e06bb2539e5484 | tag delete owner

:ref:`component-ckcore` will put this tagging task onto a task queue. This task is then consumed by a :ref:`component-ckworker` that knows how to perform tagging for that particular resource and its particular cloud and account.

In our first example above we set the tag ``owner: lukas`` for the AWS EC2 instance with ID ``i-039e06bb2539e5484``.
This task is given to a :ref:`component-ckworker` that knows how to update AWS EC2 instance tags in that resources account.

.. _delete_warning:

Deleting resources
******************

.. warning::

    | **Cloudkeeper is designed to clean up resources**.
    | Act with caution when selecting and filtering resources for cleanup.
    
    If you run ``match is(aws_ec2_volume) | clean``, it marks **all** ``aws_ec2_volume`` resources in your cloud for deletion.

    | By default, :ref:`component-ckworker` will **NOT delete resources marked for deletion.**
    | Resources marked with ``| clean`` will stay this way without deleting them.

    | :ref:`component-ckworker` will only delete marked resources when started with the ``--cleanup`` command.
    | When started like that, marked resources will be cleaned every full hour via our :ref:`workflow-collect_and_cleanup` workflow.
    
    You can provide ``--cleanup-dry-run`` to :ref:`setup-ckworker` startup, to print **what it would delete without actually deleting it**.

    When doing a resource cleanup selection for the first time it is good practice to confirm the list of selected resources for plausibility using something like ``desired clean = true | count``.

    To quickly undo marking all ``aws_ec2_volumes`` for clean use ``match is(aws_ec2_volume) | set_desired clean=false``.
    
    To remove all clean marker on all ressources you can use ``desired clean=true  | set_desired clean=false``.


Deletion of ressources via Cloudkeeper is done in two phases.

#. :ref:`mark_resources_for_deletion`
#. :ref:`delete_the_actual_ressources`

.. _mark_resources_for_deletion:

Mark resources for deletion
===========================

| Marking ressources for deletion is very easy. Just pipe your matched ressources to the ``clean`` command.
| This will add a "desired.clean = true" to all matched ressources.

Optionally you can provide a reason for marking the matched ressources for the next cleanup run by just adding the reason to the ``clean`` command.

.. code-block:: bash
    :caption: Mark all unused EBS volume older than 30 days that had no IO in the past 7d

    match is(volume) and ctime < -30d and atime < -7d and mtime < -7d and volume_status = available | clean "older than 30d with more then 7d of not beeing used"

.. _delete_the_actual_ressources:

Delete the actual ressources
============================

Resources in Cloudkeeper will only be deleted if you started a :ref:`component-ckworker` with the ``--delete`` parameter.
If done so, there will be an automatic cleanup every full hour.
Otherwise the ``cleanup`` will only be simulated without actually being deleted.

Instant cleanup can be triggered via starting the corresponding workflow.
Please see :ref:`workflow-cleanup` or :ref:`workflow-collect_and_cleanup` on how to trigger it manually.

