===========================
Setup individual components
===========================

The :ref:`quickstart` guide used our Docker image. This tutorial will set up the individual components that make up a Cloudkeeper environment.

In this setup guide we're showing you three things:
    #. how to prepare your environment
    #. how to install each cloudkeeper component
    #. how to run & access each component

All the installation will take place in your home directory ``~/cloudkeeper/``. Choose a different ``INSTALL_PREFIX`` below if you prefer another location.


Prerequisites
*************

Python >= 3.9 is required for all Cloudkeeper components. ArangoDB >= 3.8.1 is used as the ``ckcore`` graph storage.
Optionally the Cloudkeeper Metrics Exporter ``ckmetrics`` can be installed and its metrics pulled by the Prometheus time series database.
This guide uses ``curl`` and ``git`` to download components.

The component set-up takes 20 minutes. The duration of the first collect process depends on the size of your environment - usually 5-10 minutes.

To start filling the Cloudkeeper graph with resource data you will need AWS credentials.
We assume you have done our :ref:`quickstart`.

Prepare your environment
************************

.. _configuration_environment:

Configuration
=============

Every Cloudkeeper component can be configured via environment variables instead of commandline arguments.
In this section we will prepare all configuration required.
Each component has its own prefix.

* :ref:`component-ckcore`: ``CKCORE_``
* :ref:`component-ckworker`: ``CKWORKER_``
* :ref:`component-ckmetrics`: ``CKMETRICS_``
* :ref:`component-cksh`: ``CKSH_``

Example for ``ckcore``
----------------------

ENV Prefix: ``CKCORE_``

Every CLI arg can also be specified using ENV variables.

For instance ``--graphdb-server http://foobar.tld:8529`` would become ``CKCORE_GRAPHDB_SERVER=http://foobar.tld:8529``.

.. code-block:: bash
    :caption: Prepare the environment

    INSTALL_PREFIX="$HOME/cloudkeeper"

    # Create a new Python 3.9 virtual environment
    mkdir -p "$INSTALL_PREFIX"
    cd "$INSTALL_PREFIX"
    python3.9 -m venv venv
    source venv/bin/activate


    # Download and extract ArangoDB
    ARANGODB_VERSION=3.8.1
    ARANGODB_LINUX_DOWNLOAD_URL="https://download.arangodb.com/arangodb38/Community/Linux/arangodb3-linux-${ARANGODB_VERSION}.tar.gz"
    ARANGODB_MACOS_DOWNLOAD_URL="https://download.arangodb.com/arangodb38/Community/MacOSX/arangodb3-macos-${ARANGODB_VERSION}.tar.gz"
    [ "$(uname -s)" = Linux ] && ARANGODB_DOWNLOAD_URL=$ARANGODB_LINUX_DOWNLOAD_URL || ARANGODB_DOWNLOAD_URL=$ARANGODB_MACOS_DOWNLOAD_URL
    GRAPHDB_DIRECTORY="$INSTALL_PREFIX/db"                #<-- directory to store ArangoDB
    GRAPHDB_DATABASE_DIRECTORY="$INSTALL_PREFIX/data/db"  #<-- directory to store ArangoDB data
    GRAPHDB_SERVER_ENDPOINT="tcp://127.0.0.1:8529"        #<-- IP:port for ArangoDB to listen on
    GRAPHDB_ROOT_PASSWORD="changeme"                      #<-- ArangoDB root password

    # Download and extract ArangoDB
    mkdir -p "$GRAPHDB_DIRECTORY"                         #<-- directory to store ArangoDB
    mkdir -p "$GRAPHDB_DATABASE_DIRECTORY"                #<-- create data directory for ArangoDB
    curl -L -o /tmp/arangodb.tar.gz "$ARANGODB_DOWNLOAD_URL"
    tar xzvf /tmp/arangodb.tar.gz --strip-components=1 -C "$GRAPHDB_DIRECTORY"
    rm -f /tmp/arangodb.tar.gz

    CKCORE_GRAPHDB_LOGIN="cloudkeeper"             #<-- user for ArangoDB database
    CKCORE_GRAPHDB_PASSWORD="changeme"             #<-- password for ArangoDB user
    CKCORE_GRAPHDB_DATABASE="cloudkeeper"          #<-- database name in ArangoDB


.. code-block:: bash
    :caption: Optional download and install :ref:`prometheus`

    PROMETHEUS_VERSION=2.30.3
    PROMETHEUS_LINUX_DOWNLOAD_URL="https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz"
    PROMETHEUS_MACOS_DOWNLOAD_URL="https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.darwin-amd64.tar.gz"
    [ "$(uname -s)" = Linux ] && PROMETHEUS_DOWNLOAD_URL=$PROMETHEUS_LINUX_DOWNLOAD_URL || PROMETHEUS_DOWNLOAD_URL=$PROMETHEUS_MACOS_DOWNLOAD_URL
    TSDB_DIRECTORY="$INSTALL_PREFIX/tsdb"                  #<-- directory to store Prometheus
    TSDB_DATABASE_DIRECTORY="$INSTALL_PREFIX/data/tsdb"    #<-- directory to store Prometheus data
    TSDB_CONFIG_FILE="$TSDB_DIRECTORY/prometheus.yml"      #<-- location of Prometheus configuration file
    TSDB_RETENTION_TIME="730d "                            #<-- retention time for Prometheus data

    # Download and extract Prometheus
    mkdir -p "$TSDB_DIRECTORY"                             #<-- directory to store Prometheus
    mkdir -p "$TSDB_DATABASE_DIRECTORY"                    #<-- create data directory for Prometheus
    curl -L -o /tmp/prometheus.tar.gz "$PROMETHEUS_DOWNLOAD_URL"
    tar xzvf /tmp/prometheus.tar.gz --strip-components=1 -C "$TSDB_DIRECTORY"
    rm -f /tmp/prometheus.tar.gz


.. _arangodb:

ArangoDB
========

Run
---
Open a new terminal window and enter the following to run the ArangoDB database process.

.. code-block:: bash
    :caption: run ArangoDB

    INSTALL_PREFIX="$HOME/cloudkeeper"
    GRAPHDB_DIRECTORY="$INSTALL_PREFIX/db"                #<-- directory to store ArangoDB
    GRAPHDB_DATABASE_DIRECTORY="$INSTALL_PREFIX/data/db"  #<-- directory to store ArangoDB data
    GRAPHDB_SERVER_ENDPOINT="tcp://127.0.0.1:8529"        #<-- IP:port for ArangoDB to listen on
    GRAPHDB_ROOT_PASSWORD="changeme"                      #<-- ArangoDB root password

    "$GRAPHDB_DIRECTORY/bin/arangod" \
      --database.directory "$GRAPHDB_DATABASE_DIRECTORY" \
      --server.endpoint "$GRAPHDB_SERVER_ENDPOINT" \
      --database.password "$GRAPHDB_ROOT_PASSWORD"

Prepare graph database for ``ckcore``
-------------------------------------

Back in our original terminal window enter the following to create the cloudkeeper database and user for ``ckcore``.

.. code-block:: bash
    :caption: Run ``arangosh`` to configure graph database

    cat <<EOF | "$GRAPHDB_DIRECTORY/bin/arangosh" --console.history false --server.password "$GRAPHDB_ROOT_PASSWORD"
    const users = require('@arangodb/users');
    users.save('$CKCORE_GRAPHDB_LOGIN', '$CKCORE_GRAPHDB_PASSWORD');
    db._createDatabase('$CKCORE_GRAPHDB_DATABASE');
    users.grantDatabase('$CKCORE_GRAPHDB_LOGIN', '$CKCORE_GRAPHDB_DATABASE', 'rw');
    EOF


Install Cloudkeeper components
******************************

.. _setup-ckcore:

ckcore
======

Install ckcore
--------------

You install :ref:`component-ckcore` via Python pip directly from our git repository.

Please make sure you have git installed.

First you need to install :ref:`cklib` as a dependency to :ref:`setup-ckcore`.

.. code-block:: bash
    :caption: Install cklib und ckcore

    pip install "git+https://github.com/someengineering/cloudkeeper.git@2.0.0a4#egg=cklib&subdirectory=cklib"
    pip install "git+https://github.com/someengineering/cloudkeeper.git@2.0.0a4#egg=ckcore&subdirectory=ckcore"

Usage
-----
You can access :ref:`setup-ckcore` help via ``$ ckcore --help``

Every CLI arg can also be specified using ENV variables, see :ref:`configuration_environment` for examples.

Run ckcore
----------
Now we connect :ref:`setup-ckcore` to the previously installed :ref:`arangodb`.
Please match your parameter values with the ones used while preparing :ref:`arangodb`.

Open a new terminal window and enter the following to run the ArangoDB database process.

.. code-block:: bash
    :caption: Run ckcore

    INSTALL_PREFIX="$HOME/cloudkeeper"
    CKCORE_GRAPHDB_LOGIN="cloudkeeper"             #<-- user for ArangoDB database
    CKCORE_GRAPHDB_PASSWORD="changeme"             #<-- password for ArangoDB user
    CKCORE_GRAPHDB_DATABASE="cloudkeeper"          #<-- database name in ArangoDB
    cd "$INSTALL_PREFIX"
    source venv/bin/activate

    ckcore \
      --graphdb-database "$CKCORE_GRAPHDB_DATABASE" \
      --graphdb-username "$CKCORE_GRAPHDB_LOGIN" \
      --graphdb-password "$CKCORE_GRAPHDB_PASSWORD"

.. code-block:: console
    :caption: Successful launch log output

    ...
    ...
    20:25:11 [INFO] Initialization done. Starting API. [core.__main__]
    20:25:11 [INFO] Listener task_handler added to following queues: ['*'] [core.event_bus]
    ======== Running on http://localhost:8900 ========
    (Press CTRL+C to quit)

Securing ckcore
---------------

To enforce authentication for connections to :ref:`setup-ckcore` provide ``--psk "some-secret-pre-shared-key"`` as parameter on startup.

.. _setup-cksh:

cksh
====

Install cksh
------------

Back to our original terminal.

We install :ref:`component-cksh` via python pip directly from our git repository.

.. code-block:: bash
    :caption: Install cksh

    pip install "git+https://github.com/someengineering/cloudkeeper.git@2.0.0a4#egg=cksh&subdirectory=cksh"

Usage
-----

You can access :ref:`setup-cksh` help via ``$ cksh --help``

Every CLI arg can also be specified using ENV variables, see :ref:`configuration_environment` for examples.

Run cksh
----------
Now you can connect :ref:`setup-cksh` to the previous setup :ref:`setup-ckcore`.
Please match your parameter values to reflect your environment while running :ref:`setup-ckcore`.

We add the ``--verbose`` on first start to get used to what is happening exactly.
You can skip this argument later to reduce log output volume when all components are set up.

Add ``--ckcore-uri`` and ``--ckcore-ws-uri`` if :ref:`setup-ckcore` is running on another instance or port.
Add ``--ckcore-graph`` if you defined another name of the graph for :ref:`setup-ckworker`

.. code-block:: bash
    :caption: Run cksh

    cksh

.. code-block:: bash
    :caption: Verify cksh connection to ckcore

    > help
    2021-10-06 15:09:40,705 - DEBUG - 59675/MainThread - Setting columns 213, rows 115
    2021-10-06 15:09:40,705 - DEBUG - 59675/MainThread - Sending command "help" to http://localhost:8900/cli/execute?graph=ck
    ckcore CLI
    Valid placeholder string:
        @UTC@ -> 2021-10-06T13:09:40Z
        @NOW@ -> 2021-10-06T13:09:40Z
        @TODAY@ -> 2021-10-06
    [...]

.. _setup-ckworker:

ckworker
========

Install ckworker
----------------

You install :ref:`component-ckworker` via python pip directly from our git repository.
Please make sure you have git installed.
First you need to install :ref:`cklib` as a dependency to :ref:`setup-ckworker` as well.

.. code-block:: bash
    :caption: Install ckworker

    pip install "git+https://github.com/someengineering/cloudkeeper.git@2.0.0a4#egg=ckworker&subdirectory=ckworker"


.. _plugins:

ckworker plugins
----------------

:ref:`setup-ckworker` requires collector plugins to actually do something.
A full list of available plugins can be found in the cloudkeeper `repository <https://github.com/someengineering/cloudkeeper/tree/main/plugins>`_

.. code-block:: bash
    :caption: Install plugins

    pip install "git+https://github.com/someengineering/cloudkeeper.git@2.0.0a4#egg=cloudkeeper-plugin-aws&subdirectory=plugins/aws"
    pip install "git+https://github.com/someengineering/cloudkeeper.git@2.0.0a4#egg=cloudkeeper-plugin-example_collector&subdirectory=plugins/example_collector"
    pip install "git+https://github.com/someengineering/cloudkeeper.git@2.0.0a4#egg=cloudkeeper-plugin-gcp&subdirectory=plugins/gcp"
    pip install "git+https://github.com/someengineering/cloudkeeper.git@2.0.0a4#egg=cloudkeeper-plugin-github&subdirectory=plugins/github"
    pip install "git+https://github.com/someengineering/cloudkeeper.git@2.0.0a4#egg=cloudkeeper-plugin-k8s&subdirectory=plugins/k8s"
    pip install "git+https://github.com/someengineering/cloudkeeper.git@2.0.0a4#egg=cloudkeeper-plugin-onelogin&subdirectory=plugins/onelogin"
    pip install "git+https://github.com/someengineering/cloudkeeper.git@2.0.0a4#egg=cloudkeeper-plugin-onprem&subdirectory=plugins/onprem"
    pip install "git+https://github.com/someengineering/cloudkeeper.git@2.0.0a4#egg=cloudkeeper-plugin-slack&subdirectory=plugins/slack"
    pip install "git+https://github.com/someengineering/cloudkeeper.git@2.0.0a4#egg=cloudkeeper-plugin-vsphere&subdirectory=plugins/vsphere"

Usage
-----
You can access :ref:`setup-ckworker` help via ``$ ckworker --help``

Every CLI arg can also be specified using ENV variables, see :ref:`configuration_environment` for examples.

*Important*: Every plugin will add its own CLI args to those of :ref:`setup-ckworker`. Check the individual plugin documentation for details or use ``ckworker --help`` to see the complete list.

Run ckworker
------------
Now you can connect :ref:`setup-ckworker` to the previous setup :ref:`setup-ckcore`.
Please match your parameter values to reflect your environment while running :ref:`setup-ckcore`.

We add the ``--verbose`` on first start to get used to what is happening exactly.
You can skip this argument later to reduce log output volume when all components are set up.

Add ``--ckcore-uri`` and ``--ckcore-ws-uri`` if :ref:`setup-ckcore` is running on another instance or port.

Add ``--ckcore-graph`` if you want to change the default name of the graph in the database to something other than 'ck'.
Keep in mind that you need to adjust ``--ckcore-graph`` for :ref:`setup-cksh` and :ref:`setup-ckmetrics`, too.

As we are using AWS in this example, please replace ``--aws-access-key-id`` and ``--aws-secret-access-key`` with values matching your environment.

.. code-block:: bash
    :caption: Run ckworker

    ckworker \
      --verbose \
      --collector aws \
      --aws-access-key-id AKIAZGZEXAMPLE \
      --aws-secret-access-key vO51EW/8ILMGrSBV/Ia9FEXAMPLE

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



.. _setup-ckmetrics:

ckmetrics
=========

Install ckmetrics
-----------------

You install :ref:`component-ckmetrics` via python pip directly from our git repository.
Please make sure you have git installed.

If not already done in the :ref:`setup-ckcore` section, you need to install :ref:`cklib` as dependency to :ref:`setup-ckmetrics` as well.

.. code-block:: bash
    :caption: Install ckmetrics

    pip install "git+https://github.com/someengineering/cloudkeeper.git@2.0.0a4#egg=ckmetrics&subdirectory=ckmetrics"

Usage
-----

You can access :ref:`setup-ckmetrics` help via ``$ ckmetrics --help``

Every CLI arg can also be specified using ENV variables, see :ref:`configuration_environment` for examples.

Once started :ref:`setup-ckmetrics` will register for ``generate_metrics`` core events. When such an event is received it will
generate Cloudkeeper metrics and provide them at the ``/metrics`` endpoint.

For prometheus, setup your configuration needs to contain this configuration snippet.

Adjust the ``targets`` to match your ckmetrics configuration

.. code-block:: yaml
    :caption: :ref:`prometheus` configuration snippet

    scrape_configs:
    - job_name: "ckmetrics"
        static_configs:
        - targets: ["localhost:9955"]

Run ckmetrics
-------------
Now you can connect :ref:`setup-ckmetrics` to the previous setup :ref:`setup-ckcore` as well as let your prometheus connect to :ref:`setup-ckmetrics`.
Please match your parameter values to reflect your environment while running :ref:`setup-ckcore`.

We add the ``--verbose`` flag to show what is happening in more detail.
You can skip this argument later to reduce log output volume when all components are set up.

Add ``--ckcore-uri`` and ``--ckcore-ws-uri`` if :ref:`setup-ckcore` is running on another instance or port.
Add ``--ckcore-graph`` if you defined another name of the graph for :ref:`setup-ckworker`

.. code-block:: bash
    :caption: Run ckmetrics

    $ ckmetrics --verbose

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

.. _prometheus:

(Optional) Run Prometheus
*************************

If you do not have prometheus already, here is how you configure and run it to make use of :ref:`ckmetrics` exporter data. 

Run
===

In this example we expect a configuration at your location defined in ``TSDB_CONFIG_FILE``

.. code-block:: yaml
    :caption: ``TSDB_CONFIG_FILE`` configuration.

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

    "$TSDB_DIRECTORY/prometheus" --config.file="$TSDB_CONFIG_FILE" \
      --storage.tsdb.path="$TSDB_DATABASE_DIRECTORY" \
      --storage.tsdb.retention.time="$TSDB_RETENTION_TIME" \
      --web.console.libraries=/usr/local/tsdb/console_libraries \
      --web.console.templates=/usr/local/tsdb/consoles \
      --web.enable-lifecycle \
      --web.enable-admin-api


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
