#!/bin/sh
# Scenario 4: a payment settles over several HTLC attempts; the books match LND's principal and fees.
set -eu
cd "$(dirname "$0")/.."
node lab/check-node.mjs
exec node --disable-warning=ExperimentalWarning scenarios/4-multi-attempt.ts "$@"
