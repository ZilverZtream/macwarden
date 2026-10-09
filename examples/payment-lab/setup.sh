#!/bin/sh
# Builds the regtest payment lab: bitcoind and three LND nodes, funded wallets, channels and one macwarden-baked credential per role.
set -eu
cd "$(dirname "$0")"
node lab/check-node.mjs
exec node --disable-warning=ExperimentalWarning lab/setup.ts "$@"
