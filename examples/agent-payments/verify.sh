#!/bin/sh
# Runs the whole example from a clean start, checks every step's outcome and
# removes everything afterwards. Exit 0 only when every check passed.
set -u
cd "$(dirname "$0")"
status=0
node demo.mjs --teardown || status=$?
# demo.mjs tears down itself; make sure nothing is left if it was interrupted.
docker compose -f docker-compose.yml down -v --remove-orphans >/dev/null 2>&1 || true
rm -rf runtime
if [ "$status" -eq 0 ]; then echo "verify: all checks passed"; else echo "verify: FAILED (exit $status)" >&2; fi
exit "$status"
