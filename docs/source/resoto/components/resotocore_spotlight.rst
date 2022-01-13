.. _resotocore_spotlight:

==============
Spotlight: API
==============

The API of :ref:`component-resotocore` is exposed via http and websocket.
You can access it via http://<resoto-address>:8900/api-doc

| :ref:`component-resotocore` has two API endpoints to connect to for CLI purposes:
| ``http://<resoto-address>:8900/cli/evaluate``
| ``http://<resoto-address>:8900/cli/execute``
  
``cli/evaluate`` functinality is used internally on every ``cli/execute`` before the command execution.

Here is a simulation of sending a :ref:`component-resotoshell` query to the CLI API.
We will evaluate the query before executing it for demonstration. Also we introduce this query with a typo to show the response if not successful.

Evaluate
--------

.. code-block:: bash
    :caption: Evaluate, correct: ``match is("resource") limit 1``

    $ echo 'graph=resoto match is("resource") limit 1' | http :8900/cli/evaluate
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

    $ echo 'graph=resoto match is("resource") limit1' | http :8900/cli/evaluate
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

    $ echo 'graph=resoto match is("resource") limit 1' | http :8900/cli/execute
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
                "python_type": "resoto.baseresources.Cloud"
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

    $ echo 'graph=resoto match is("resource") limit1' | http :8900/cli/execute
    HTTP/1.1 400 Bad Request
    Content-Length: 151
    Content-Type: text/plain; charset=utf-8
    Date: Wed, 06 Oct 2021 15:26:54 GMT
    Server: Python/3.9 aiohttp/3.7.4.post0

    Error: ParseError
    Message: expected one of '!=', '!~', '<', '<=', '=', '==', '=~', '>', '>=', '[A-Za-z][A-Za-z0-9_]*', '`', 'in', 'not in', '~' at 0:21

More API Endpoints
==================

:ref:`component-resotocore` is the central HUB for everything Resoto does.
You can discover :ref:`component-resotocore` APIs directly via WebBrowser (exposed at ``http://<resoto-address>:8900/``) or in our `repository <https://github.com/someengineering/resoto/blob/main/resotocore/core/static/api-doc.yaml>`_

There will be examples of typical API Calls in the in depth descriptions of every :ref:`resoto component <component-list>`.
