Setup individual components
###########################

In this setup guide we're showing you three things:
    #. how to prepare your python environment
    #. how to install each cloudkeeper component
    #. how to run & access each component

We assume that you know your way around installing and maintaining a python >= 3.9 environment aswell as installing ArangoDB >= 3.8.1 and Prometheus >= 2.30.1

The component set-up takes 20 minutes. The duration of the first collect process depends on the size of your environment - usually 5-10 minutes.

To start exploring you need AWS credentials with access to AWS APIs.
We assume you have done our :ref:`quickstart`.

Prepare your environment
************************

ArangoDB
========

Run
---

Our defaults run fine but things like ``GRAPHDB_ROOT_PASSWORD`` need to be changed for non-laptop-environments.

.. code-block:: bash
    :caption: Create data directory and run ArangoDB

    $ mkdir -p ${GRAPHDB_DATABASE_DIRECTORY:-/data/db}
    $ /usr/local/db/bin/arangod --database.directory "${GRAPHDB_DATABASE_DIRECTORY:-/data/db}" \
      --server.endpoint "${GRAPHDB_SERVER_ENDPOINT:-tcp://127.0.0.1:8529}" \
      --database.password "${GRAPHDB_ROOT_PASSWORD:-changeme}"

Prepare graph database for ``ckcore``
-------------------------------------

Now you need to prepare the graph database for ``ckcore``.

You will add an user for ``ckcore``, create a database and grant priveleges for the user to access the database.

Our defaults run fine but things like ``GRAPHDB_ROOT_PASSWORD`` or ``CKCORE_GRAPHDB_PASSWORD`` need to be changed for non-laptop-environments.

.. code-block:: bash
    :caption: Run ArangoSH to configure graph database

    $ arangosh --console.history false --server.password "${GRAPHDB_ROOT_PASSWORD:-changeme}"
    > const users = require('@arangodb/users');
    > users.save('${CKCORE_GRAPHDB_LOGIN:-cloudkeeper}', '${CKCORE_GRAPHDB_PASSWORD:-changeme}');
    > db._createDatabase('${CKCORE_GRAPHDB_DATABASE:-cloudkeeper}');
    > users.grantDatabase('${CKCORE_GRAPHDB_LOGIN:-cloudkeeper}', '${CKCORE_GRAPHDB_DATABASE:-cloudkeeper}', 'rw');

Prometheus
==========

Run
---

In this example we expect a configuration at ``/usr/local/tsdb/prometheus.yml`` with this configuration

.. code-block:: yaml
    :caption: /usr/local/tsdb/prometheus.yml configuration.

    global:
        scrape_interval: 120s 
        evaluation_interval: 120s

        alerting:
        alertmanagers:
            - static_configs:
                - targets:
                # - alertmanager:9093

        rule_files:
        # - "first_rules.yml"
        # - "second_rules.yml"

        scrape_configs:
        - job_name: "prometheus"
            static_configs:
            - targets: ["localhost:9090"]

        - job_name: "ckmetrics"
            static_configs:
            - targets: ["localhost:9955"]


.. code-block:: bash
    :caption: Create data directory and run Prometheus

    $ mkdir -p ${TSDB_DATABASE_DIRECTORY:-/data/tsdb}
    $ /usr/local/tsdb/prometheus --config.file=${TSDB_CONFIG_FILE:-/usr/local/tsdb/prometheus.yml} \
      --storage.tsdb.path=${TSDB_DATABASE_DIRECTORY:-/data/tsdb} \
      --storage.tsdb.retention.time=${TSDB_RETENTION_TIME:-730d} \
      --web.console.libraries=/usr/local/tsdb/console_libraries \
      --web.console.templates=/usr/local/tsdb/consoles \
      --web.enable-lifecycle \
      --web.enable-admin-api
