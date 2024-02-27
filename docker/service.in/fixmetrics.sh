#!/bin/bash
. /usr/local/etc/fix/defaults
if [ "$START_FIXCORE" = true ]; then
    sv start fixcore || exit 1
fi
source /usr/local/fix-venv-python3/bin/activate
exec /sbin/setuser fix fixmetrics @FIX_ARGSDISPATCHER@
