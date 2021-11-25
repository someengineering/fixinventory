==============================
Setup In Kubernetes Using Helm
==============================

The :ref:`quickstart` guide used our Docker image. This tutorial will set up the individual components that make up a Cloudkeeper environment.

In this setup guide we're showing you three things:
    #. how to prepare your environment
    #. how to prepare your helm values file
    #. how to install each cloudkeeper in kubernetes using helm

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

Wait until the the ArangoDB deployment is ready. You can check the conditions in the status to see that it is ready:

.. code-block:: bash
    :caption: Check status

    kubectl get arangodeployment single-server -o yaml

Setup a db and password:

.. code-block:: bash
    :caption: Create db and credentials

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
     :caption: Upload db credentials as a secret

    kubectl create secret generic cloudkeeper-graphdb-credentials --from-literal=password=$CKCORE_GRAPHDB_PASSWORD


.. _configuration_environment:

Configuration
*************
Prepare your Helm values file:


.. code-block:: bash
    :caption: Prepare the helm values file

    cat > cloudkeeper-values.yaml <<EOF
    ckcore:
        graphdb:
            server: http://single-server:8529
            login: $CKCORE_GRAPHDB_LOGIN
            database: $CKCORE_GRAPHDB_DATABASE
            passwordSecret:
                name: cloudkeeper-graphdb-credentials
                key: password
    # add your stuff here:
    ckworker:
        extraArgs:
            - --fork
        collector: example
    EOF

Optional - Configure Cloud Credentials
======================================

You can use helm values ckworker.extraArgs, ckworker.extraEnv, ckworker.volumes and ckworker.volumeMounts to injecti credentials and their configuration to ckworker.
For example, for AWS and GCE, you would do the following:

.. code-block:: bash
    :caption: Create credentials

    kubectl -n cloudkeeper create secret generic cloudkeeper-auth --from-file=GOOGLE_APPLICATION_CREDENTIALS=<PATH TO SERVICE ACCOUNT JSON CREDS> --from-literal=AWS_ACCESS_KEY_ID=<YOUR ACCESS KEY ID> --from-literal=AWS_SECRET_ACCESS_KEY=<YOUR ACCESS KEY>

Then you can use these values for ckwroker:

.. code-block:: yaml
    :caption: values with ckworker credentials

    ckcore:
        graphdb:
            server: http://single-server:8529
            login: cloudkeeper
            passwordSecret:
                name: cloudkeeper-graphdb-credentials
                key: password
    ckworker:
      collector: aws gcp
      volumeMounts:
          - mountPath: /etc/tokens/
            name: auth-secret
      volumes:
        - name: auth-secret
          secret:
            secretName: cloudkeeper-auth
            items:
              - key: GOOGLE_APPLICATION_CREDENTIALS
                path: gcp-service-account.json
      extraEnv:
          - name: AWS_ACCESS_KEY_ID
            valueFrom:
              secretKeyRef:
                name: cloudkeeper-auth
                key: AWS_ACCESS_KEY_ID
          - name: AWS_SECRET_ACCESS_KEY
            valueFrom:
              secretKeyRef:
                name: cloudkeeper-auth
                key: AWS_SECRET_ACCESS_KEY
      extraArgs:
          - --fork
          - --gcp-service-account
          - /etc/tokens/gcp-service-account.json
          - "--aws-fork"
          - "--gcp-fork"
          - "--aws-account-pool-size"
          - "4"
          - "--gcp-project-pool-size"
          - "4"

Installation
************

Get the helm chart. For now, to get the helm chart you will need to clone Cloudkeeper locally:

.. code-block:: bash
    :caption: Clone Cloudkeeper

    git clone https://github.com/someengineering/cloudkeeper

Install Cloudkeeper:

.. code-block:: bash
    :caption: Install Cloudkeeper

    helm install cloudkeeper ./cloudkeeper/kubernetes/chart --set image.tag=2.0.0a8 -f cloudkeeper-values.yaml



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
