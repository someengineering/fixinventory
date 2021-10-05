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

To give you a better understanding of how cloudkeepers components interact with each other and where prometheus and arangod come in, we have prepared this Visualisation for you.
<insert Visualisation>.

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
First you need to install :ref:`cklib` as a dependency to :ref:`ckcore`.

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
Now you can start and connect :ref:`ckcore` to the previous setup of :ref:`arangodb`.
Please match your parameter values with the ones used while preparing :ref:`arangodb`.

We add the ``--log-level debug`` on first start to get used to what is happening exactly.
You can skip this argument later to reduce log output volume when all components are set up.

Add --graphdb-server if :ref:`arangodb` is running on another instance or port.

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

.. _ckworker:

ckworker
========

:ref:`ckworker` does all the collection and cleanup work in Cloudkeeper. It is connected to :ref:`ckcore` over a websocket connection and waits for instructions. By default it subscribes to the `collect` and `cleanup` actions as well as `tag` tasks.

:ref:`ckworker` loads collector :ref:`plugins` like AWS, GCP, Slack, Onelogin, etc.
Only those plugins have knowledge about how to communicate with each cloud. How to collect resources and how to clean them up.

There can be one or more instances of :ref:`ckworker` in a Cloudkeeper deployment. A single :ref:`ckworker` can collect many clouds or you could have multiple :ref:`ckworker` collecting one cloud or even one account in one cloud each.

Install ckworker
----------------

You install :ref:`ckworker` via python pip directly from our git repository.
Please make sure you have git installed.
First you need to install :ref:`cklib` as a dependency to :ref:`ckworker` as well.

.. code-block:: bash
    :caption: Install cklib und ckworker

    $ pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cklib&subdirectory=cklib"
    $ pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=ckworker&subdirectory=ckworker"


.. _plugins:

Install ckworker plugins
------------------------

As :ref:`ckworker` needs plugins to actually do something you need to install them, too.
A full list of available plugins can be found in your `repository <https://github.com/someengineering/cloudkeeper/tree/main/plugins>`_

.. code-block:: bash
    :caption: Install plugins

    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-aws&subdirectory=plugins/aws"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-backup&subdirectory=plugins/backup"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-ckcore&subdirectory=plugins/ckcore"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-cleanup_aws_alarms&subdirectory=plugins/cleanup_aws_alarms"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-cleanup_aws_loadbalancers&subdirectory=plugins/cleanup_aws_loadbalancers"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-cleanup_aws_vpcs&subdirectory=plugins/cleanup_aws_vpcs"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-cleanup_expired&subdirectory=plugins/cleanup_expired"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-cleanup_untagged&subdirectory=plugins/cleanup_untagged"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-cleanup_volumes&subdirectory=plugins/cleanup_volumes"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-cli_debug&subdirectory=plugins/cli_debug"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-cli_edgestats&subdirectory=plugins/cli_edgestats"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-cli_jq&subdirectory=plugins/cli_jq"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-example_cli&subdirectory=plugins/example_cli"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-example_collector&subdirectory=plugins/example_collector"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-example_persistent&subdirectory=plugins/example_persistent"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-gcp&subdirectory=plugins/gcp"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-github&subdirectory=plugins/github"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-k8s&subdirectory=plugins/k8s"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-logdump&subdirectory=plugins/logdump"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-metrics_age_range&subdirectory=plugins/metrics_age_range"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-onelogin&subdirectory=plugins/onelogin"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-onprem&subdirectory=plugins/onprem"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-protect_snowflakes&subdirectory=plugins/protect_snowflakes"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-remote&subdirectory=plugins/remote"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-remote_event_callback&subdirectory=plugins/remote_event_callback"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-report_cleanups&subdirectory=plugins/report_cleanups"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-slack&subdirectory=plugins/slack"
    pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cloudkeeper-plugin-vsphere&subdirectory=plugins/vsphere"

Usage
-----
:ref:`worker` uses the following command line arguments:

.. code-block:: bash
    :caption: :ref:`ckworker` parameters
    
    -h, --help            show this help message and exit
    --verbose, -v         Verbose logging
    --logfile LOGFILE     Logfile to log into
    --collector COLLECTOR [COLLECTOR ...]
                        Collectors to load (default: all)
    --cleanup             Enable cleanup of resources (default: False)
    --cleanup-pool-size CLEANUP_POOL_SIZE
                        Cleanup thread pool size (default: 10)
    --cleanup-dry-run     Cleanup dry run (default: False)
    --ckcore-uri CKCORE_URI
                        ckcore URI (default: http://localhost:8900)
    --ckcore-ws-uri CKCORE_WS_URI
                        ckcore Websocket URI (default: ws://localhost:8900)
    --ckcore-graph CKCORE_GRAPH
                        ckcore graph name (default: ck)
    --pool-size POOL_SIZE
                        Collector Thread/Process Pool Size (default: 5)
    --fork                Use forked process instead of threads (default: False)
    --timeout TIMEOUT     Collection Timeout in seconds (default: 10800)
    --debug-dump-json     Dump the generated json data (default: False)

ENV Prefix: ``CKWORKER_``  
Every CLI arg can also be specified using ENV variables.

For instance the boolean ``--fork`` would become ``CKWORKER_FORK=true`` or ``--collector aws gcp`` would become ``CKWORKER_COLLECTOR="aws gcp"``.

*Important*: Every plugin will add its own CLI args to those of :ref:`ckworker`. Check the individual plugin documentation for details or use ``ckworker --help`` to see the complete list.

Run ckworker
------------
Now you can connect :ref:`ckworker` to the previous setup :ref:`ckcore`.
Please match your parameter values to reflect your environment while running :ref:`ckcore`.

We add the ``--verbose`` on first start to get used to what is happening exactly.
You can skip this argument later to reduce log output volume when all components are set up.

Add ``--ckcore-uri`` and ``--ckcore-ws-uri`` if :ref:`ckcore` is running on another instance or port.

Add ``--ckcore-graph`` if you want to change the default name of the graph in the database to something other than 'ck'.
Keep in mind that you need to adjust ``--ckcore-graph`` for :ref:`cksh` and :ref:`ckmetrics`, too.

As we are using AWS in this example, please replace ``--aws-access-key-id`` and ``--aws-secret-access-key`` with values matching your environment.

.. code-block:: bash
    :caption: Run ckcore

    $ ckworker --verbose \
      --ckcore-uri ${CKCORE_URI:-http://127.0.0.1:8900} \
      --ckcore-ws-uri ${CKCORE_WS_URI:-ws://127.0.0.1:8900} \
      --ckcore-graph ${CKCORE_GRAPH:-ck}
      --fork \
      --collector aws \
      --aws-fork \
      --aws-account-pool-size 50 \
      --aws-access-key-id AKIAZGZEXAMPLE \
      --aws-secret-access-key vO51EW/8ILMGrSBV/Ia9FEXAMPLE \
      --aws-role Cloudkeeper \
      --aws-scrape-org

.. code-block:: console
    :caption: Successful launch log output

    2021-10-05 13:03:36,924 - INFO - 3189/MainThread - Cloudkeeper collectord initializing
    2021-10-05 13:03:36,924 - DEBUG - 3189/MainThread - Only loading plugins of type PluginType.COLLECTOR
    2021-10-05 13:03:36,925 - DEBUG - 3189/MainThread - Finding plugins
    2021-10-05 13:03:37,443 - DEBUG - 3189/MainThread - Found plugin <class 'cloudkeeper_plugin_aws.AWSPlugin'> (COLLECTOR)
    [...]
    2021-10-05 13:03:37,446 - INFO - 3189/workerd-events - Connecting to ckcore message bus
    2021-10-05 13:03:37,446 - DEBUG - 3189/workerd-events - workerd-events registering for collect actions ({'timeout': 10800, 'wait_for_completion': True})
    2021-10-05 13:03:37,446 - DEBUG - 3189/workerd-tasks - Registering <bound method CoreTasks.shutdown of <CoreTasks(workerd-tasks, started 6197522432)>> with event SHUTDOWN (blocking: False, one-shot: False)
    2021-10-05 13:03:37,448 - INFO - 3189/workerd-tasks - Connecting to ckcore task queue
    2021-10-05 13:03:37,448 - DEBUG - 3189/workerd-tasks - workerd-tasks connecting to ws://localhost:8900/work/queue?task=tag
    2021-10-05 13:03:37,454 - DEBUG - 3189/workerd-tasks - workerd-tasks connected to ckcore task queue
    2021-10-05 13:03:37,514 - DEBUG - 3189/workerd-events - workerd-events registering for cleanup actions ({'timeout': 10800, 'wait_for_completion': True})
    2021-10-05 13:03:37,533 - DEBUG - 3189/workerd-events - workerd-events connecting to ws://localhost:8900/subscriber/workerd-events/handle
    2021-10-05 13:03:37,536 - DEBUG - 3189/workerd-events - workerd-events connected to ckcore message bus

Let us unpack this command

- ``fork`` makes :ref:`ckworker` fork each collector plugin instead of using threads
- ``collector aws`` loads the AWS collector plugin
- ``aws-fork`` tells the AWS collector plugin to also use forked processes instead of threads
- ``aws-access-key-id/-secret-access-key`` AWS credentials for API access. Instead of using credentials directly you can also opt to inherit them from the `awscli <https://aws.amazon.com/cli/>`_ environment or when running on EC2 using an instance profile.
- ``aws-role`` the IAM role Cloudkeeper should assume when making API requests
- ``aws-scrape-org`` tells the AWS collector plugin to retrieve a list of all org accounts and then assume into each one of them.

The reason for using forked processes instead of threads is to work around performance limitations of Python's `GIL <https://en.wikipedia.org/wiki/Global_interpreter_lock>`_. By forking we almost scale linearly with the number of CPU cores when collecting many accounts at once. The default is to use threads to conserve system resources.

.. _ckmetrics:

ckmetrics
=========

:ref:`ckmetrics` takes :ref:`ckcore` graph data and runs aggregation functions on it. Those aggregated metrics
are then exposed in a :ref:`prometheus` compatible format. The default TCP port is ``9955`` but
can be changed using the ``--web-port`` argument.

Install ckmetrics
-----------------

You install ckmetrics via python pip directly from our git repository.
Please make sure you have git installed.

If not already done in the :ref:`ckcore` section, you need to install :ref:`cklib` as dependency to :ref:`ckmetrics` as well.

.. code-block:: bash
    :caption: Install cklib und ckmetrics

    $ pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=cklib&subdirectory=cklib"
    $ pip3 install "git+https://github.com/someengineering/cloudkeeper.git@main#egg=ckmetrics&subdirectory=ckmetrics"

Usage
-----

:ref:`ckmetrics` uses the following commandline arguments:

.. code-block:: bash
    :caption: :ref:`ckmetrics` parameters

    -h, --help            show this help message and exit
    --ckcore-uri CKCORE_URI
                        ckcore URI (default: http://localhost:8900)
    --ckcore-ws-uri CKCORE_WS_URI
                        ckcore Websocket URI (default: ws://localhost:8900)
    --ckcore-graph CKCORE_GRAPH
                        ckcore graph name (default: ck)
    --psk PSK             Pre-shared key
    --timeout TIMEOUT     Metrics generation timeout in seconds (default: 300)
    --verbose, -v         Verbose logging
    --web-port WEB_PORT   Web Port (default 9955)
    --web-host WEB_HOST   IP to bind to (default: ::)
    --web-path WEB_PATH   Web root in browser (default: /)

ENV Prefix: ``CKMETRICS_``  
Every CLI arg can also be specified using ENV variables.

For instance the boolean ``--verbose`` would become ``CKMETRICS_VERBOSE=true`` or ``--timeout 300`` would become ``CKMETRICS_TIMEOUT=300``.

Once started :ref:`ckmetrics` will register for ``generate_metrics`` core events. When such an event is received it will
generate Cloudkeeper metrics and provide them at the ``/metrics`` endpoint.

As mentioned in the :ref:`prometheus` setup your configuration needs to contain this configuration snippet.

.. code-block:: yaml
    :caption: :ref:`prometheus` configuration snippet

    scrape_configs:
    - job_name: "ckmetrics"
        static_configs:
        - targets: ["localhost:9955"]

Run ckmetrics
-------------
Now you can connect :ref:`ckmetrics` to the previous setup :ref:`ckcore` as well as let your prometheus connect to :ref:`ckmetrics`.
Please match your parameter values to reflect your environment while running :ref:`ckcore`.

We add the ``--verbose`` on first start to get used to what is happening exactly.
You can skip this argument later to reduce log output volume when all components are set up.

Add ``--ckcore-uri`` and ``--ckcore-ws-uri`` if :ref:`ckcore` is running on another instance or port.
Add ``--ckcore-graph`` if you defined another name of the graph for :ref:`ckworker`

.. code-block:: bash
    :caption: Run ckmetrics

    $ ckmetrics --verbose \
      --ckcore-uri ${CKCORE_URI:-http://127.0.0.1:8900} \
      --ckcore-ws-uri ${CKCORE_WS_URI:-ws://127.0.0.1:8900} \
      --ckcore-graph ${CKCORE_GRAPH:-ck}

.. code-block:: console
    :caption: Successful launch log output

    2021-10-05 13:20:43,798 - DEBUG - 6143/MainThread - generating metrics
    2021-10-05 13:20:43,798 - INFO - 6143/webserver - CherryPy ENGINE Bus STARTING
    2021-10-05 13:20:43,798 - DEBUG - 6143/ckmetrics - Registering <bound method CoreActions.shutdown of <CoreActions(ckmetrics, started 6189232128)>> with event SHUTDOWN (blocking: False, one-shot: False)
    2021-10-05 13:20:43,798 - INFO - 6143/ckmetrics - Connecting to ckcore message bus
    [...]
    2021-10-05 13:20:43,824 - DEBUG - 6143/ckmetrics - ckmetrics connected to ckcore message bus
    2021-10-05 13:20:44,904 - INFO - 6143/webserver - CherryPy ENGINE Serving on http://:::9955
    2021-10-05 13:20:44,905 - INFO - 6143/webserver - CherryPy ENGINE Bus STARTED

You can now access the metrics interface via `ckmetrics <http://localhost:9955/metrics>`_.

.. _cksh:

cksh
====
:ref:`cksh` starts the Cloudkeeper shell. It is used to interact with :ref:`ckcore`.
It allows you to explore the graph, find resources of interest, mark them for cleanup, fix their tagging, aggregate over their metadata to create metrics and format the output for use in a 3rd party script or system.

Install cksh
------------

You install cksh via python pip directly from our git repository.
Please make sure you have git installed.

If not already done in the :ref:`ckcore` section, you need to install :ref:`cklib` as a dependency to :ref:`cksh`.

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

Run cksh
----------
Now you can connect :ref:`cksh` to the previous setup :ref:`ckcore`.
Please match your parameter values to reflect your environment while running :ref:`ckcore`.

We add the ``--verbose`` on first start to get used to what is happening exactly.
You can skip this argument later to reduce log output volume when all components are set up.

Add ``--ckcore-uri`` and ``--ckcore-ws-uri`` if :ref:`ckcore` is running on another instance or port.
Add ``--ckcore-graph`` if you defined another name of the graph for :ref:`ckworker`

.. code-block:: bash
    :caption: Run cksh

    $ cksh --verbose \
      --ckcore-uri ${CKCORE_URI:-http://127.0.0.1:8900} \
      --ckcore-ws-uri ${CKCORE_WS_URI:-ws://127.0.0.1:8900} \
      --ckcore-graph ${CKCORE_GRAPH:-ck}

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

You made it!
************
Congratulations, you have now finished the setup of every cloudkeeper component.
Thank you so much for exploring Cloudkeeper. This is just the beginning.

What now?
=========
All documentation is under heavy development, including this tutorial.
We extend and improve this documentation almost daily. Please star this `repo <http://github.com/someengineering/cloudkeeper>`_ to support us and stay up to date.

| Please explore Cloudkeeper, build your queries and discover your infrastructure.
| A good place to continue is joining our community to get the most out of Cloudkeeper and the experiences collected from many different SREs, companies and curious people.
| We would love to hear from you with your feedback, experiences and interesting queries and use cases.

How you get more assistance
===========================

| Reach out to us if you have any questions, improvements, bugs!
| Contributions are very much appreciated.

| Discord:
| https://discord.gg/3G3sX6y3bt

| GitHub Issue:
| https://github.com/someengineering/cloudkeeper/issues/new 