#!/bin/sh
# Alert command for `macwarden watch --alert-command` (POSIX).
#
# watch runs it once per canary alert, without a shell, without arguments and with a
# minimal environment, and writes the alert as one JSON line to its stdin. The event
# carries the method, the root key ID, the credential ID and the label: never
# credential bytes. watch stops it after 10 s (SIGTERM) and 12 s (SIGKILL).
#
# This example appends the event to runtime/alerts.jsonl next to this script. In
# production, forward it to whatever pages a person (a webhook, a mail relay, syslog).
set -eu
umask 077
dir="$(dirname "$0")/runtime"
[ -d "$dir" ] || exit 1
cat >> "$dir/alerts.jsonl"
