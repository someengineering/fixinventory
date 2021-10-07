.. _ckworker-deepdive:

====================
ckworker - Deep Dive
====================

Once :ref:`component-ckworker` is started you do not have to interact with it at all. It will just sit there, wait for work and do its job.

The following are details on how :ref:`component-ckworker` works internally and how it integrates with :ref:`component-ckcore`.

Workflows
---------

Think of actions and tasks like topics and queues in a messaging system. Actions are broadcast to everyone subscribed for that action.

A task is always given to exactly one worker that knows how to handle it.

Workflows consists of a collection of event types.

Cloudkeeper currently has four workflows built in.

Each workflow step posts into the specific topic. As :ref:`component-ckworker` knows about all plugins for an event type it waits on every individual plugin to finish (or until timeout, which can be configured for each subscription).

When the ``collect`` workflow within :ref:`component-ckcore` is triggered (by either an event or a schedule or because the user manually triggered it), 
:ref:`component-ckcore` will broadcast a ***"start collecting all the cloud accounts you know about"*** message to all the subscribed workers.
Once all the workers finish collecting and sent their graph to the core, the workflow will proceed to the next step which would be ``plan_cleanup``.

This one tells anyone interested to start planing their cleanup based on the just collected graph data.
Once everyone has planed their cleanup and flagged resources that should get cleaned up with the ``desired.clean = true`` flag,
the workflow proceeds to the ``cleanup`` step which again notifies anyone subscribed to now perform cleanup of those flagged resources.

Because the cleaner within :ref:`component-ckworker` has knowledge of all dependencies in the graph,
it will ensure that resources are cleaned up in the right order.

collect
^^^^^^^
The ``collect`` workflow can be triggered via :ref:`component-cksh` command.

.. code-block::
    :caption: Start collect workflow
    
        > start_task collect
        
This will trigger all subscribers to the ``collect`` event type.
As an additional step, this workflow will call the ``metrics`` event type, which will put :ref:`component-ckmetrics` into action.

cleanup
^^^^^^^

This workflow deletes ressources, that were previously marked as to be cleand.
:ref:`setup-ckworker` needs to be started started with the ``--cleanup`` parameter.
Otherwise it will default to a dry-run and NOT delete any ressources.

The collect workflow can be triggered via :ref:`component-cksh` command.

.. code-block::
    :caption: Start cleanup workflow
    
        > start_task cleanup
        
This will trigger all subscribers to the ``cleanup`` event type.
As an additional step, this workflow will call the ``metrics`` event type, which will put :ref:`component-ckmetrics` into action.

metrics
^^^^^^^

The ``metrics`` workflow can be triggered via :ref:`component-cksh` command.

.. code-block::
    :caption: Start metrics workflow
    
        > start_task metrics
        
This will trigger all subscribers to the ``metrics`` event type. This will put :ref:`component-ckmetrics` into action.

collect_and_cleanup
^^^^^^^^^^^^^^^^^^^
The ``collect_and_cleanup`` workflow is hardwired to run automatically every full hour.
This will trigger all ``collect``, ``cleanup`` and ``metrics`` subscribers.

You can trigger this workflow also like the others via :ref:`component-cksh` command.

.. code-block::
    :caption: Start collect_and_cleanup workflow
    
        > start_task collect_and_cleanup

Tasks
-----

When a plugin or a user decides that a resource tag should be added, changed or removed, e.g. by running

.. code-block:: bash

    match id = i-039e06bb2539e5484 | tag update owner lukas

:ref:`component-ckcore` will put this tagging task onto a task queue. This task is then consumed by a :ref:`component-ckworker` that knows how to perform tagging for that particular resource and its particular cloud and account. In our example above where we are setting the tag ``owner: lukas`` for an AWS EC2 instance with ID ``i-039e06bb2539e5484`` the task would be given to a :ref:`component-ckworker` that knows how to update AWS EC2 instance tags in that resources account.
