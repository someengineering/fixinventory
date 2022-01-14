#!/bin/bash
. /usr/local/etc/resoto/defaults
if [ "$START_RESOTOCORE" = true ]; then
    sv start resotocore || exit 1
fi
source /usr/local/resoto-venv-python3/bin/activate
exec /sbin/setuser resoto resotometrics @RESOTO_ARGSDISPATCHER@
