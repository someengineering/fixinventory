#!/bin/bash

/sbin/setuser resoto /usr/local/sbin/bootstrap-graphdb
sv down graphdb-bootstrap
