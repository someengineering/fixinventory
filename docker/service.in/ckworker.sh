#!/bin/bash
exec /sbin/setuser cloudkeeper /usr/local/bin/ckworker @CLOUDKEEPER_ARGSDISPATCHER@
