.. _graph_node_spotlight:

=====================
Spotlight: Graph Node
=====================

A graph node is a json document with a well defined structure and these top level properties:

::

    {
      "id": "xxx",
      "kinds": [ ... ],
      "reported": { ... },
      "desired": { ... },
      "metadata": { ... }
    }

- ``id`` : This is a synthetic unique identifier of this node that is created by Resoto.
  It is used to maintain the node as well as all edges from and to this node.
- ``kinds``: This array contains all kinds of this node. It is derived from the kind of
  this node and includes the current kind as well as all parent kinds.
  See :ref:`model` for an explanation of kind.
- ``reported`` : This section is a json document and shows the reported properties from the
  collector. The data that is collected is specific to the cloud and the resource type.
  The reported data is of a specific ``kind`` indicated by the same property. The complete
  structure of the reported section is described in the model :ref:`model`.
- ``desired`` : This section is a json document and shows desired changes of this node.
  Desired changes are reflected by humans and tools via the API or command line.
  The desired section is not described via a ``kind`` model and allows arbitrary data.
- ``metadata`` : This section is a json document and shows metadata of this resource.
  The metadata section is intended to keep data attached to this resource, but not
  originating from the resource or the provider itself.
  metadata is created by humans and/or tools via the API or command line.
  The metadata section is not described via a ``kind`` model and allows arbitrary data.

Example node data showing data from an `AWS EC2 Instance <https://aws.amazon.com/ec2>`_
We use this example in the following sections to show query capabilities.

::

    {
      "id": "c0a43527846739d88c9",
      "kinds": [
        "aws_ec2_instance",
        "instance",
        "resource",
        "aws_resource"
      ],
      "reported": {
        "kind": "aws_ec2_instance",
        "id": "i-0994caaa55576a33d",
        "tags": {
          "expiration": "never",
          "name": "sunset",
          "owner": "nick"
        },
        "name": "sunset",
        "ctime": "2019-12-20T10:14:19Z",
        "instance_cores": 2,
        "instance_memory": 8,
        "instance_type": "m5a.large",
        "instance_status": "running"
      },
      "desired": {
        "clean": true
      },
      "metadata": {
        "ancestors": {
          "cloud": {
            "name": "aws",
            "id": "aws"
          },
          "account": {
            "name": "eng-production",
            "id": "139234212332"
          },
          "region": {
            "name": "us-east-1",
            "id": "us-east-1"
          }
        }
      }
    }
