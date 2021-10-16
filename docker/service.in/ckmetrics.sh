#!/bin/bash
source /usr/local/cloudkeeper-venv-python3/bin/activate
exec /sbin/setuser cloudkeeper ckmetrics @CLOUDKEEPER_ARGSDISPATCHER@
