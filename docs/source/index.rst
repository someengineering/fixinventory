========================
Housekeeping for Clouds!
========================

Overview
********
Cloudkeeper is “housekeeping for clouds” - find leaky resources, manage quota limits, detect drift and clean up.

Cloudkeeper indexes resources, captures dependencies and maps out your infrastructure in a graph so that it’s understandable for a human. The graph contains metrics for each resource. Developers and SREs can search the graph with a query language, and create alerting and clean-up workflows. Metrics can be aggregated and exported to a time series database like Prometheus.

Cloudkeeper consists of multiple components described in the :ref:`component-list`.

Contents
********
.. toctree::
   :maxdepth: 1
   :caption: General
   :name: sec-general

   general/introduction
   
.. toctree::
   :maxdepth: 1
   :caption: Getting Started
   :name: sec-gettingstarted

   getting_started/quick_start
   getting_started/setup_individual_components

.. toctree::
   :maxdepth: 1
   :caption: Manual
   :name: sec-manual

   manual/query

.. toctree::
   :maxdepth: 1
   :caption: Deep Dives
   :name: sec-deepdive

   deep_dive/components/index
   deep_dive/model



