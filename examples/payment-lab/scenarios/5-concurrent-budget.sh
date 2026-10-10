#!/bin/sh
# Scenario 5: two concurrent payouts race for one budget; reservations hold while unresolved.
set -eu
cd "$(dirname "$0")/.."
node lab/check-node.mjs
exec node --disable-warning=ExperimentalWarning scenarios/5-concurrent-budget.ts "$@"
