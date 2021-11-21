#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

kind create cluster
kubectl create ns cloudkeeper

# deploy db operator.
helm install --namespace cloudkeeper arango-crd https://github.com/arangodb/kube-arangodb/releases/download/1.2.4/kube-arangodb-crd-1.2.4.tgz
helm install --namespace cloudkeeper arango https://github.com/arangodb/kube-arangodb/releases/download/1.2.4/kube-arangodb-1.2.4.tgz --set operator.replicaCount=1

# wait for operator to be ready.
kubectl --namespace cloudkeeper rollout status deploy/arango-arango-operator
# deploy a db.
kubectl --namespace cloudkeeper apply -f - <<EOF
apiVersion: "database.arangodb.com/v1alpha"
kind: "ArangoDeployment"
metadata:
  name: "single-server"
spec:
  mode: Single
  tls:
    caSecretName: None
EOF

# create secret for dashboard. not really needed for test, but nice to have.
kubectl --namespace cloudkeeper create secret generic arangodb-operator-dashboard --from-literal=username=a --from-literal=password=a

# wait for the db deployment is ready.
kubectl --namespace cloudkeeper wait --for=condition=ready arangodeployment/single-server --timeout=240s

# the the db's pod.
ARANGO_DB_POD=$(kubectl --namespace cloudkeeper get pod -larango_deployment=single-server -o name)

# wait until the db is ready to accept clients.
timeout 1m $SHELL -c "until kubectl --namespace cloudkeeper exec $ARANGO_DB_POD -- /lifecycle/tools/arangodb_operator lifecycle probe --endpoint=/_api/version --auth; do sleep 1; done"

# create a db and user for us.
kubectl --namespace cloudkeeper exec -i $ARANGO_DB_POD -- arangosh --console.history false --server.password "" <<EOF
const users = require('@arangodb/users');
print("creating user");
users.save('ck', 'ck');
print("creating db");
db._createDatabase('cloudkeeper');
print("granting user db access");
users.grantDatabase('ck', 'cloudkeeper', 'rw');
print("all done:", users.all());
EOF

# put the db password in a secret.
kubectl --namespace cloudkeeper create secret generic arango-user --from-literal=password=ck

# install cloud keeper with the example collector

DIR="$(dirname "$(realpath "$0")")"
helm upgrade -i --namespace cloudkeeper cloudkeeper "$DIR/cloudkeeper" --set image.tag=2.0.0a8 -f - <<EOF
ckcore:
  graphdb:
    server: http://single-server:8529
    login: ck
    database: cloudkeeper
    passwordSecret:
      name: arango-user
      key: password
ckworker:
  collector: example
  extraArgs:
    - --fork
EOF
# wait for it to be ready
kubectl --namespace cloudkeeper rollout status deploy/cloudkeeper-ckcore
kubectl --namespace cloudkeeper rollout status deploy/cloudkeeper-ckworker
kubectl --namespace cloudkeeper rollout status deploy/cloudkeeper-ckmetrics
# see an example query!
kubectl --namespace cloudkeeper exec -i deploy/cloudkeeper-ckcore -- cksh --stdin <<EOF
kind
query is(resource) | count reported.kind
EOF