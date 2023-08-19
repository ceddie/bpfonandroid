#!/bin/bash

PID=$(pidof $1)
LC_CTYPE=C.UTF-8 gdb -p $PID
