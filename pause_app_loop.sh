#/bin/bash

while [ TRUE ]; do
  PID=$(pidof $1)
  if [[ -n "$PID" ]]; then
    kill -SIGSTOP $PID
    exit
  fi
  sleep 0.01;
done
