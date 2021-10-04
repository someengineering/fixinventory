Setup individual components
###########################

In this setup guide we're showing you three things:
    #. how to prepare your environment
    #. how to install each cloudkeeper component
    #. how to run & access each component

We assume that you know your way around installing and maintaining a python >= 3.9 environment as well as installing ArangoDB >= 3.8.1 and Prometheus >= 2.30.1

The component set-up takes 20 minutes. The duration of the first collect process depends on the size of your environment - usually 5-10 minutes.

To start exploring you need AWS credentials with access to AWS APIs.
We assume you have done our :ref:`quickstart`.

Prepare your environment
************************

.. _arangodb:

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

You will add an user for ``ckcore``, create a database and grant privileges for the user to access the database.

Our defaults run fine but things like ``GRAPHDB_ROOT_PASSWORD`` or ``CKCORE_GRAPHDB_PASSWORD`` need to be changed for non-laptop-environments.

.. code-block:: bash
    :caption: Run ArangoSH to configure graph database

    $ arangosh --console.history false --server.password "${GRAPHDB_ROOT_PASSWORD:-changeme}"
    > const users = require('@arangodb/users');
    > users.save('${CKCORE_GRAPHDB_LOGIN:-cloudkeeper}', '${CKCORE_GRAPHDB_PASSWORD:-changeme}');
    > db._createDatabase('${CKCORE_GRAPHDB_DATABASE:-cloudkeeper}');
    > users.grantDatabase('${CKCORE_GRAPHDB_LOGIN:-cloudkeeper}', '${CKCORE_GRAPHDB_DATABASE:-cloudkeeper}', 'rw');

.. _prometheus:

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

.. _component-list:

Cloudkeeper components
**********************

These are the moving parts of cloudkeeper.
We will now guide you through the setup and run procedure for each one.
:ref:`plugins` have no extra section, as they are integrated via :ref:`ckworker`

- :ref:`ckcore`: the platform maintaining the `MultiDiGraph <https://en.wikipedia.org/wiki/Multigraph#Directed_multigraph_(edges_with_own_identity)>`_.
- :ref:`cksh`: the Cloudkeeper shell to interact with the core.
- :ref:`ckworker` provides workers that load `plugins <https://github.com/someengineering/cloudkeeper/tree/main/plugins>`_ to perform collect and cleanup operations.
- :ref:`ckmetrics` is a `Prometheus <https://prometheus.io/>`_ `exporter <https://prometheus.io/docs/instrumenting/exporters/>`_.
- :ref:`plugins` are a collection of worker plugins like `AWS <plugins/aws/>`_

ToDo: Visualisation of the components and how they connect to each other

.. _ckcore:

ckcore
======

The Cloudkeeper graph platform :ref:`ckcore` is the persistence and query backend of Cloudkeeper. It maintains the graph
of resources and provides APIs to update and access them. Within :ref:`ckcore` there are workflows consisting of steps
that result in actions like ``collect``, ``cleanup`` or ``generate_metrics``. These actions are being received by components
like :ref:`ckworker` and :ref:`ckmetrics`.

:ref:`ckcore` also provides the CLI API that :ref:`cksh` calls.

Install ckcore
--------------

You install ckcore via python pip directly from our git repository.
Please make sure you have git installed.
First you need to install :ref:`cklib` as dependency to :ref:`ckcore`.

.. code-block:: bash
    :caption: Install cklib und ckcore

    $ pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cklib&subdirectory=cklib"
    $ pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=ckcore&subdirectory=ckcore"

Usage
-----
:ref:`ckcore` uses the following command line arguments:

.. code-block:: bash
    :caption: :ref:`ckcore` parameters

    -h, --help            show this help message and exit
    --log-level LOG_LEVEL
                        Log level (default: info)
    --graphdb-server GRAPHDB_SERVER
                        Graph database server (default: http://localhost:8529)
    --graphdb-database GRAPHDB_DATABASE
                        Graph database name (default: cloudkeeper)
    --graphdb-username GRAPHDB_USERNAME
                        Graph database login (default: cloudkeeper)
    --graphdb-password GRAPHDB_PASSWORD
                        Graph database password (default: "")
    --graphdb-type GRAPHDB_TYPE
                        Graph database type (default: arangodb)
    --graphdb-no-ssl-verify
                        If the connection should be verified (default: False)
    --graphdb-request-timeout GRAPHDB_REQUEST_TIMEOUT
                        Request timeout in seconds (default: 900)
    --psk PSK             Pre-shared key
    --host HOST [HOST ...]
                        TCP host(s) to bind on (default: 127.0.0.1)
    --port PORT           TCP port to bind on (default: 8900)
    --plantuml-server PLANTUML_SERVER
                        PlantUML server URI for UML image rendering (default: https://www.plantuml.com/plantuml)
    --jobs [JOBS ...]

ENV Prefix: ``CKCORE_``

Every CLI arg can also be specified using ENV variables.

For instance ``--graphdb-server http://foobar.tld:8529`` would become ``CKCORE_GRAPHDB_SERVER=http://foobar.tld:8529``.


Run ckcore
----------
Now you can start and connect :ref:`ckcore` to the previous setup :ref:`arangodb`.
Please match your parameter values with the ones used while preparing :ref:`arangodb`.

We add the ``--log-level debug`` on first start to get used to what is happening exactly.
You can skip this argument later to reduce log output volume when all components are set up.

Add --graphdb-server if :ref:`arangodb` is running on another instance.

.. code-block:: bash
    :caption: Run ckcore

    $ ckcore --log-level debug \
      --graphdb-server ${GRAPHDB_SERVER_ENDPOINT:-tcp://127.0.0.1:8529} \
      --graphdb-database ${CKCORE_GRAPHDB_DATABASE:-cloudkeeper} \
      --graphdb-username ${CKCORE_GRAPHDB_LOGIN:-cloudkeeper} \
      --graphdb-password ${CKCORE_GRAPHDB_PASSWORD:-changeme}

.. code-block:: console
    :caption: Successful launch log output

    20:25:11 [INFO] Starting up... [core.__main__]
    20:25:11 [DEBUG] Using selector: KqueueSelector [asyncio]
    20:25:11 [INFO] Create ArangoHTTPClient with timeout=900 and verify=True [core.db.arangodb_extensions]
    20:25:11 [INFO] No authentication requested. [core.web.auth]
    20:25:11 [DEBUG] Starting new HTTP connection (1): localhost:8529 [urllib3.connectionpool]
    20:25:11 [DEBUG] http://localhost:8529 "GET /_db/cloudkeeper/_api/collection HTTP/1.1" 200 1845 [urllib3.connectionpool]
    [...]
    20:25:11 [INFO] Found graph: ck [core.db.db_access]
    [...]
    20:25:11 [INFO] Initialization done. Starting API. [core.__main__]
    20:25:11 [INFO] Listener task_handler added to following queues: ['*'] [core.event_bus]
    20:25:11 [DEBUG] Looking for jobs to run [apscheduler.scheduler]
    20:25:11 [DEBUG] Next wakeup is due at 2021-10-04 19:00:00+00:00 (in 2088.660527 seconds) [apscheduler.scheduler]
    ======== Running on http://localhost:8900 ========
    (Press CTRL+C to quit)

.. _cksh:

cksh
======
:ref:`cksh` starts the Cloudkeeper shell. It is used to interact with :ref:`ckcore`.
It allows you to explore the graph, find resources of interest, mark them for cleanup, fix their tagging, aggregate over their metadata to create metrics and format the output for use in a 3rd party script or system.

Install cksh
--------------

You install cksh via python pip directly from our git repository.
Please make sure you have git installed.

If not already done in :ref:`ckcore` section, you need to install :ref:`cklib` as dependency to :ref:`cksh`.

.. code-block:: bash
    :caption: Install cklib und cksh

    $ pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cklib&subdirectory=cklib"
    $ pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cksh&subdirectory=cksh"

Usage
-----
:ref:`cksh` uses the following command line arguments:

.. code-block:: bash
    :caption: :ref:`cksh` parameters

    -h, --help            show this help message and exit
    --ckcore-uri CKCORE_URI
                        ckcore URI (default: http://localhost:8900)
    --ckcore-ws-uri CKCORE_WS_URI
                        ckcore Websocket URI (default: ws://localhost:8900)
    --ckcore-graph CKCORE_GRAPH
                        ckcore graph name (default: ck)
    --stdin               Read from STDIN instead of opening a shell
    --verbose, -v         Verbose logging
    --logfile LOGFILE     Logfile to log into

ENV Prefix: ``CKSH_``

Every CLI arg can also be specified using ENV variables.

For instance ``--ckcore-uri http://foobar.tld:8900`` would become ``CKSH_CKCORE_URI=http://foobar.tld:8900``.
