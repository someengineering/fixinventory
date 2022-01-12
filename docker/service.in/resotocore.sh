#!/bin/bash
. /usr/local/etc/resoto/defaults
if [ "$START_GRAPHDB" = true ]; then
    sv start graphdb || exit 1
    sleep 7
fi
source /usr/local/resoto-venv-pypy3/bin/activate
exec /sbin/setuser resoto resotocore --ui-path /usr/local/resoto/ui/ --start-collect-on-subscriber-connect @RESOTO_ARGSDISPATCHER@
