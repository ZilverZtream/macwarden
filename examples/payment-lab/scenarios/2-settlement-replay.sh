#!/bin/sh
# Scenario 2: a settlement is delivered again after a listener restart; the order is fulfilled and posted once.
set -eu
cd "$(dirname "$0")/.."
node lab/check-node.mjs
exec node --disable-warning=ExperimentalWarning scenarios/2-settlement-replay.ts "$@"
