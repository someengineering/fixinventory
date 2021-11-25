NOTE: VERY ROUGH DRAFT!!!!!!!!!!

===========================
Setup In Kubernetes Using Helm
===========================

The :ref:`quickstart` guide used our Docker image. This tutorial will set up the individual components that make up a Cloudkeeper environment.

In this setup guide we're showing you three things:
    #. how to prepare your environment
    #. how to prepare your helm values file
    #. how to install each cloudkeeper in kubernetes using helm

All the installation will take place in your home directory ``~/cloudkeeper/``. Choose a different ``INSTALL_PREFIX`` below if you prefer another location.


Prerequisites
*************
You will need:

Helm (version 3 and above)
A Kubernetes cluster (kind or minikube should work as well)

To start filling the Cloudkeeper graph with resource data you will need AWS credentials with proper permissions.

You can look up specific permission configurations in your :ref:`access-permissions` section.

We assume you have done our :ref:`quickstart`.

Prepare your environment
************************

Prepare arangodb database.
If you don't have arangodb, you can use the operator to install it.
see more info here:
https://www.arangodb.com/docs/stable/tutorials-kubernetes.html

You can use these commands to install the DB, but do note that this is not production-ready setup:

.. code-block:: bash
    :caption: Prepare the environment

    helm repo add arangodb https://arangodb.github.io/kube-arangodb
    helm repo update
    helm install kube-arangodb-crd arangodb/kube-arangodb-crd
    helm install kube-arangodb arangodb/kube-arangodb

    kubectl apply -f - <<EOF
    apiVersion: "database.arangodb.com/v1alpha"
    kind: "ArangoDeployment"
    metadata:
        name: "single-server"
    spec:
        mode: Single
        tls:
            caSecretName: None
    EOF

Note: This readme was tested with version 1.2.4 of the operator.

Setup a db and passowrd:

.. code-block:: bash
    :caption: Prepare the environment

    CKCORE_GRAPHDB_LOGIN=cloudkeeper
    CKCORE_GRAPHDB_DATABASE=cloudkeeper
    CKCORE_GRAPHDB_PASSWORD=$(head -c 1500 /dev/urandom | tr -dc 'a-zA-Z0-9' | cut -c -32)
    POD=$(kubectl get pods --selector=arango_deployment=single-server -o jsonpath="{.items[0].metadata.name}")
    kubectl exec -i ${POD} -- arangosh --console.history false --server.password "" <<EOF
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
*************
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
        collector: example
    EOF

Get the helm chart. For now, to get the helm chart you will need to clone Cloudkeeper locally:

.. code-block:: bash
    :caption: Clone Cloudkeeper

    git clone https://github.com/someengineering/cloudkeeper

Installation
************

Install Cloudkeeper:

.. code-block:: bash
    :caption: Prepare the environment

    helm install ./cloudkeeper/kubernetes/chart cloudkeeper -f cloudkeeper-values.yaml



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
