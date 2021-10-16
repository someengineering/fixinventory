#!/bin/bash
source /usr/local/cloudkeeper-venv-python3/bin/activate
exec /sbin/setuser cloudkeeper ckworker @CLOUDKEEPER_ARGSDISPATCHER@
