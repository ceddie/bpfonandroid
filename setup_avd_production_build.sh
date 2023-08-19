#!/bin/sh

# run this in adb shell

mkdir -p /data/eadb/debian/mnt/sdcard
mount --bind /mnt/sdcard /data/eadb/debian/mnt/sdcard

mkdir -p /data/eadb/debian/mnt/data
mount --bind /data/misc/profiles/ref /data/eadb/debian/mnt/data

mkdir -p /data/eadb/debian/data/local/tmp/
mount --bind /data/local/tmp /data/eadb/debian/data/local/tmp/

mkdir -p /data/eadb/debian/bpfonandroid/output
mkdir -p /data/eadb/debian/bpfonandroid/cache