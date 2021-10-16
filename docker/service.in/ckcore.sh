#!/bin/bash
source /usr/local/cloudkeeper-venv-pypy3/bin/activate
exec /sbin/setuser cloudkeeper ckcore @CLOUDKEEPER_ARGSDISPATCHER@
