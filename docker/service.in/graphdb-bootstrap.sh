#!/bin/bash

/sbin/setuser fix /usr/local/sbin/bootstrap-graphdb
sv down graphdb-bootstrap
