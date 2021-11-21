NOTE: VERY ROUGH DRAFT!!!!!!!!!!

===========================
Setup In Kubernetes Using Helm
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

To start filling the Cloudkeeper graph with resource data you will need AWS credentials with proper permissions.

You can look up specific permission configurations in your :ref:`access-permissions` section.

We assume you have done our :ref:`quickstart`.

Prepare your environment
************************

Prepare arangodb database.
If you don't have arangodb, you can use the operator to install it.
see more info here:
https://www.arangodb.com/docs/stable/tutorials-kubernetes.html

but the gist of it is:

.. code-block:: bash
    :caption: Prepare the environment

    kubectl apply -f https://raw.githubusercontent.com/arangodb/kube-arangodb/1.2.4/manifests/arango-crd.yaml
    kubectl apply -f https://raw.githubusercontent.com/arangodb/kube-arangodb/1.2.4/manifests/arango-deployment.yaml
    kubectl apply -f <<EOF
    apiVersion: "database.arangodb.com/v1alpha"
    kind: "ArangoDeployment"
    metadata:
    name: "single-server"
    spec:
    mode: Single
    EOF


Setup a db and passowrd:

.. code-block:: bash
    :caption: Prepare the environment

    CKCORE_GRAPHDB_LOGIN=ckcore
    CKCORE_GRAPHDB_DATABASE=cloudkeeper
    CKCORE_GRAPHDB_PASSWORD=$(head -c 1500 /dev/urandom | tr -dc 'a-zA-Z0-9' | cut -c -32)
    POD=$(kubectl get pods --selector=arango_deployment=single-server -o name|head -1)
    kubectl exec -i $(POD) -- arangosh  --console.history false --server.password "$GRAPHDB_ROOT_PASSWORD" <<EOF
        const users = require('@arangodb/users');
        users.save('$CKCORE_GRAPHDB_LOGIN', '$CKCORE_GRAPHDB_PASSWORD');
        db._createDatabase('$CKCORE_GRAPHDB_DATABASE');
        users.grantDatabase('$CKCORE_GRAPHDB_LOGIN', '$CKCORE_GRAPHDB_DATABASE', 'rw');
    EOF

Create the secret with the credentials

.. code-block:: bash
    :caption: Prepare the environment

    kubectl create secret generic cloudkeeper-graphdb-credentials --from-literal=password=$CKCORE_GRAPHDB_PASSWORD


.. _configuration_environment:

Configuration
=============
Prepare your Helm values file:


.. code-block:: bash
    :caption: Prepare the environment

    cat > cloudkeeper-values.yaml <<EOF
    ckcore:
        graphdb:
            server: http://single-server:123
            login: $CKCORE_GRAPHDB_LOGIN
            passwordSecret:
                name: cloudkeeper-graphdb-credentials
                key: password
    # add your stuff here:
    ckworker:
        extraArgs:
            - --fork
    EOF


install!

.. code-block:: bash
    :caption: Prepare the environment

    helm install cloudkeeper -f cloudkeeper-values.yaml --namespace=ck-system



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
