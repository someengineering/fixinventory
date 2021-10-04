Housekeeping for Clouds!
########################
Contents
********
.. toctree::
   :maxdepth: 1

   start
   setup
   component-list
   model
   query

Overview
********
Cloudkeeper is “housekeeping for clouds” - find leaky resources, manage quota limits, detect drift and clean up.

Cloudkeeper indexes resources, captures dependencies and maps out your infrastructure in a graph so that it’s understandable for a human. The graph contains metrics for each resource. Developers and SREs can search the graph with a query language, and create alerting and clean-up workflows. Metrics can be aggregated and exported to a time series database like Prometheus.

Cloudkeeper consists of multiple components described in the :ref:`component-list`.
