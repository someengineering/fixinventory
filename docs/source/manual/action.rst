======
Action
======

Flavour Text, maybe gfx on clean(up), tag modification, magic on automatic running workflows and how to trigger them manually

Working with tags
*****************

Delete unwanted resources
*************************

How Cloudkeeper maintains your resources
****************************************

| Cloudkeeper does the housekeeping for you. It automatically uses workflows in the background to achive this which are triggered by events or time.
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
To activate this feature, :ref:`setup-ckworker` needs to be started started with the ``--cleanup`` parameter.
Otherwise it will default to a dry-run and NOT delete any ressources.

.. code-block::
    :caption: Start cleanup workflow
    
        > start_workflow cleanup
        
As an additional step, this workflow will trigger :ref:`workflow-metrics` aswell, which will put :ref:`component-ckmetrics` into action.

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
