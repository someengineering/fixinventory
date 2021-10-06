.. _component-list:

Cloudkeeper components
######################

These are the moving parts of cloudkeeper.
We will now guide you through the setup and run procedure for each one.
:ref:`plugins` have no extra section, as they are integrated via :ref:`ckworker`

- :ref:`component-ckcore`: the platform maintaining the `MultiDiGraph <https://en.wikipedia.org/wiki/Multigraph#Directed_multigraph_(edges_with_own_identity)>`_.
- :ref:`component-cksh`: the Cloudkeeper shell to interact with the core.
- :ref:`component-ckmetrics` is a `Prometheus <https://prometheus.io/>`_ `exporter <https://prometheus.io/docs/instrumenting/exporters/>`_.
- :ref:`component-ckworker` provides workers that load `plugins <https://github.com/someengineering/cloudkeeper/tree/main/plugins>`_ to perform collect and cleanup operations.
- :ref:`plugins` are a collection of worker plugins like `AWS <plugins/aws/>`_

To give you a better understanding of how cloudkeepers components interact with each other and where prometheus and arangoDB come in, we have prepared this visualisation for you.

.. image:: _static/images/query_documentation2x_10.png
  :alt: Component connection

.. _component-ckcore:

ckcore
******

The Cloudkeeper graph platform :ref:`ckcore` is the persistence and query backend of Cloudkeeper. It maintains the graph
of resources and provides APIs to update and access them. Within :ref:`ckcore` there are workflows consisting of steps
that result in actions like ``collect``, ``cleanup`` or ``generate_metrics``. These actions are being received by components
like :ref:`ckworker` and :ref:`ckmetrics`.

:ref:`ckcore` provides the CLI API :ref:`cksh` calls which we will now use as an example.

ckcore - CLI API
================

The API of :ref:`component-ckcore` is exposed via http and websocket.
You can access it via http://<cloudkeeper-address>:8900/

:ref:`component-ckcore` has two API endpoints to connect to for CLI purposes:
* http://<cloudkeeper-address>:8900/cli/evaluate
* http://<cloudkeeper-address>:8900/cli/execute
  
``cli/evaluate`` functinality is used internally on every ``cli/execute`` before the command execution.

Here is a simulation of sending a :ref:`component-cksh` query to the CLI API.
We will evaluate the query before executing it for demonstration. Also we introduce this query with a typo to show the response if not successful.

Evaluate
--------

.. code-block:: bash
    :caption: Evaluate, correct: ``match is("resource") limit 1``

    $ echo 'graph=ck match is("resource") limit 1' | http :8900/cli/evaluate
    HTTP/1.1 200 OK
    Content-Length: 47
    Content-Type: application/json; charset=utf-8
    Date: Wed, 06 Oct 2021 15:13:08 GMT
    Server: Python/3.9 aiohttp/3.7.4.post0

    [
        {
            "execute_query": "is(\"resource\") limit 1"
        }
    ]

.. code-block:: bash
    :caption: Evaluate, typo: ``match is("resource") limit1``

    $ echo 'graph=ck match is("resource") limit1' | http :8900/cli/evaluate
    HTTP/1.1 400 Bad Request
    Content-Length: 151
    Content-Type: text/plain; charset=utf-8
    Date: Wed, 06 Oct 2021 15:13:33 GMT
    Server: Python/3.9 aiohttp/3.7.4.post0

    Error: ParseError
    Message: expected one of '!=', '!~', '<', '<=', '=', '==', '=~', '>', '>=', '[A-Za-z][A-Za-z0-9_]*', '`', 'in', 'not in', '~' at 0:21

Execute
-------

.. code-block:: bash
    :caption: Execute, correct: ``match is("resource") limit 1``

    $ echo 'graph=ck match is("resource") limit 1' | http :8900/cli/execute
    HTTP/1.1 200 OK
    Content-Type: application/json
    Date: Wed, 06 Oct 2021 15:08:10 GMT
    Server: Python/3.9 aiohttp/3.7.4.post0
    Transfer-Encoding: chunked

    [
        {
            "id": "06ee67f7c54124c019b80a7f53fa59b231b374fe61f94b91e0c26729440d095c",
            "kinds": [
                "base_cloud",
                "cloud",
                "resource"
            ],
            "metadata": {
                "python_type": "cloudkeeper.baseresources.Cloud"
            },
            "reported": {
                "ctime": "2021-09-25T23:49:38Z",
                "id": "gcp",
                "kind": "cloud",
                "name": "gcp",
                "tags": {}
            },
            "revision": "_d_7eKMa---",
            "type": "node"
        }
    ]

.. code-block:: bash
    :caption: Execute, typo: ``match is("resource") limit1``

    $ echo 'graph=ck match is("resource") limit1' | http :8900/cli/execute
    HTTP/1.1 400 Bad Request
    Content-Length: 151
    Content-Type: text/plain; charset=utf-8
    Date: Wed, 06 Oct 2021 15:26:54 GMT
    Server: Python/3.9 aiohttp/3.7.4.post0

    Error: ParseError
    Message: expected one of '!=', '!~', '<', '<=', '=', '==', '=~', '>', '>=', '[A-Za-z][A-Za-z0-9_]*', '`', 'in', 'not in', '~' at 0:21

More API Endpoints
==================

:ref:`component-ckcore` is the central HUB for everything Cloudkeeper does.
You can discover :ref:`component-ckcore` APIs directly via WebBrowser (exposed at http://<cloudkeeper-address>:8900/) or in our `repository <https://github.com/someengineering/cloudkeeper/blob/main/ckcore/core/static/api-doc.yaml>`_

There will be examples of typical API Calls in the in depth descriptions of every :ref:`Cloudkeeper component <component-list>`.


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
