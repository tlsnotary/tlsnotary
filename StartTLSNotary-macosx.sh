#!/bin/sh
ulimit -n 1024 #raise the ridiculously low limit of 256 open files
python2.7 src/auditee/tlsnotary-auditee.py
