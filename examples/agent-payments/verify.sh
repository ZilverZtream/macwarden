#!/bin/sh
# Runs the whole example from a clean start, checks every step's outcome and
# removes everything afterwards. Exit 0 only when every check passed.
set -u
cd "$(dirname "$0")"
status=0
node demo.mjs --teardown || status=$?
# demo.mjs tears down itself; make sure nothing is left if it was interrupted. A failed
# cleanup fails the verification: containers, volumes or credential files may be left.
if ! docker compose -f docker-compose.yml down -v --remove-orphans >/dev/null 2>&1; then
  echo "verify: cleanup failed: docker compose down -v --remove-orphans did not succeed" >&2
  [ "$status" -ne 0 ] || status=1
fi
if ! rm -rf runtime; then
  echo "verify: cleanup failed: could not remove runtime/" >&2
  [ "$status" -ne 0 ] || status=1
fi
if [ "$status" -eq 0 ]; then echo "verify: all checks passed"; else echo "verify: FAILED (exit $status)" >&2; fi
exit "$status"
