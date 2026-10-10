#!/bin/sh
# Scenario 1: the connection is cut while the HTLC is held; recovery through TrackPaymentV2. Option: --cut kill|drop
set -eu
cd "$(dirname "$0")/.."
node lab/check-node.mjs
exec node --disable-warning=ExperimentalWarning scenarios/1-dropped-connection.ts "$@"
