.. _component-list:

==========
Components
==========

These are the moving parts of cloudkeeper.
We will now guide you through the setup and run procedure for each one.
:ref:`plugins` have no extra section, as they are integrated via :ref:`ckworker`

- :ref:`component-ckcore`: the platform maintaining the `MultiDiGraph <https://en.wikipedia.org/wiki/Multigraph#Directed_multigraph_(edges_with_own_identity)>`_.
- :ref:`component-cksh`: the Cloudkeeper shell to interact with the core.
- :ref:`component-ckmetrics` is a `Prometheus <https://prometheus.io/>`_ `exporter <https://prometheus.io/docs/instrumenting/exporters/>`_.
- :ref:`component-ckworker` provides workers that load `plugins <https://github.com/someengineering/cloudkeeper/tree/main/plugins>`_ to perform collect and cleanup operations.
- :ref:`plugins` are a collection of worker plugins like `AWS <plugins/aws/>`_

To give you a better understanding of how cloudkeepers components interact with each other and where prometheus and arangoDB come in, we have prepared this visualisation for you.

.. image:: img/component_graph.png
  :alt: Component connection

.. _component-ckcore:

ckcore
******

The Cloudkeeper graph platform :ref:`ckcore` is the persistence and query backend of Cloudkeeper. It maintains the graph
of resources and provides APIs to update and access them. Within :ref:`ckcore` there are workflows consisting of steps
that result in actions like ``collect``, ``cleanup`` or ``generate_metrics``. These actions are being received by components
like :ref:`ckworker` and :ref:`ckmetrics`.

You can find more information in the section about :ref:`ckcore_spotlight`.

.. toctree::
   :maxdepth: 1
   :hidden:

   ckcore_spotlight

.. _component-cksh:

cksh
****

:ref:`component-cksh` starts the Cloudkeeper shell. It is used to interact with :ref:`component-ckcore`.
It allows you to explore the graph, find resources of interest, mark them for cleanup, fix their tagging, aggregate over their metadata to create metrics and format the output for use in a 3rd party script or system.

.. _component-ckmetrics:

ckmetrics
*********

:ref:`component-ckmetrics` takes :ref:`component-ckcore` graph data and runs aggregation functions on it. Those aggregated metrics
are then exposed in a :ref:`prometheus` compatible format.

.. _component-ckworker:

ckworker
********

:ref:`component-ckworker` does all the collection and cleanup work in Cloudkeeper. It is connected to :ref:`component-ckcore` over a websocket connection and waits for instructions. By default it subscribes to the `collect` and `cleanup` actions as well as `tag` tasks.

:ref:`component-ckworker` loads collector :ref:`plugins` like AWS, GCP, Slack, Onelogin, etc.
Only those plugins have knowledge about how to communicate with each cloud. How to collect resources and how to clean them up.

There can be one or more instances of :ref:`component-ckworker` in a Cloudkeeper deployment. A single :ref:`component-ckworker` can collect many clouds or you could have multiple :ref:`component-ckworker` collecting one cloud or even one account in one cloud each.

You can find more information in the section about :ref:`ckworker-spotlight`.


.. toctree::
   :maxdepth: 1
   :hidden:

   ckworker_spotlight
