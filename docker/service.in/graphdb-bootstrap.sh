#!/bin/bash

/sbin/setuser cloudkeeper /usr/local/sbin/bootstrap-graphdb
sv down graphdb-bootstrap
