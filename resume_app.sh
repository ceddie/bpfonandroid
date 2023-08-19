#!/bin/bash

PID=$(pidof $1)
kill -SIGCONT $PID
