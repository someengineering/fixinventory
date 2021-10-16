#!/bin/bash
. /usr/local/etc/cloudkeeper/defaults
if [ "$START_GRAPHDB" = true ]; then
    sv start graphdb || exit 1
    sleep 7
fi
source /usr/local/cloudkeeper-venv-pypy3/bin/activate
exec /sbin/setuser cloudkeeper ckcore @CLOUDKEEPER_ARGSDISPATCHER@
