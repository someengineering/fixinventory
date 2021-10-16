#!/bin/bash
. /usr/local/etc/cloudkeeper/defaults
if [ "$START_CKCORE" = true ]; then
    sv start ckcore || exit 1
fi
source /usr/local/cloudkeeper-venv-python3/bin/activate
exec /sbin/setuser cloudkeeper ckworker @CLOUDKEEPER_ARGSDISPATCHER@
