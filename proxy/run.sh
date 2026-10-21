#!/bin/sh
# Start nginx with its access log (stdout) and error log (stderr) passed
# through mask.awk, so no authorisation code or other one-time login value
# reaches `docker compose logs proxy`. nginx stays PID 1, so `nginx -s
# reload` and docker stop work as before; the filters end when it exits.
set -eu
for s in out err; do
  rm -f "/tmp/nginx-$s"
  mkfifo "/tmp/nginx-$s"
done
awk -f /etc/nginx/mask.awk </tmp/nginx-out &
awk -f /etc/nginx/mask.awk </tmp/nginx-err >&2 &
exec nginx -g 'daemon off;' >/tmp/nginx-out 2>/tmp/nginx-err
