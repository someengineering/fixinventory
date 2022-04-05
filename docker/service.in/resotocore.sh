#!/bin/bash
. /usr/local/etc/resoto/defaults
if [ "$START_GRAPHDB" = true ]; then
    sv start graphdb || exit 1
    sleep 7
fi
source /usr/local/resoto-venv-pypy3/bin/activate
exec /sbin/setuser resoto resotocore --override resotocore.api.ui_path=/usr/local/resoto/ui/ resotocore.runtime.start_collect_on_subscriber_connect=true resotocore.api.web_hosts=0.0.0.0 @RESOTO_ARGSDISPATCHER@
