#!/bin/sh
ulimit -n 1024 #raise the ridiculously low limit of 256 open files
python2.7 data/auditee/tlsnotary-auditee.py
