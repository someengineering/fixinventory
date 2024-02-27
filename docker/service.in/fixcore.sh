#!/bin/bash
. /usr/local/etc/fix/defaults
if [ "$START_GRAPHDB" = true ]; then
    sv start graphdb || exit 1
    sleep 7
fi
source /usr/local/fix-venv-pypy3/bin/activate
exec /sbin/setuser fix fixcore --override fixcore.runtime.start_collect_on_subscriber_connect=true fixcore.api.web_hosts=0.0.0.0 @FIX_ARGSDISPATCHER@
