#!/bin/bash
exec /sbin/setuser cloudkeeper /usr/local/tsdb/prometheus --config.file=@TSDB_CONFIG_FILE@ --storage.tsdb.path=@TSDB_DATABASE_DIRECTORY@ --storage.tsdb.retention.time=@TSDB_RETENTION_TIME@ --web.console.libraries=/usr/local/tsdb/console_libraries --web.console.templates=/usr/local/tsdb/consoles --web.enable-lifecycle --web.enable-admin-api
