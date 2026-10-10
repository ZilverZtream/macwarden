# Builds the regtest payment lab: bitcoind and three LND nodes, funded wallets, channels and one macwarden-baked credential per role.
$ErrorActionPreference = 'Stop'
$lab = Join-Path $PSScriptRoot '.'
& node (Join-Path $lab 'lab/check-node.mjs')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& node --disable-warning=ExperimentalWarning (Join-Path $lab 'lab/setup.ts') @args
exit $LASTEXITCODE
