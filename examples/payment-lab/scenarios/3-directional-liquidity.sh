#!/bin/sh
# Scenario 3: a refund fails for lack of outbound balance despite on-chain funds; diagnosis, fix, retry.
set -eu
cd "$(dirname "$0")/.."
node lab/check-node.mjs
exec node --disable-warning=ExperimentalWarning scenarios/3-directional-liquidity.ts "$@"
