#!/bin/bash
. /usr/local/etc/cloudkeeper/defaults
if [ "$START_RESOTOCORE" = true ]; then
    sv start resotocore || exit 1
fi
source /usr/local/cloudkeeper-venv-python3/bin/activate
exec /sbin/setuser cloudkeeper resotoworker @CLOUDKEEPER_ARGSDISPATCHER@
