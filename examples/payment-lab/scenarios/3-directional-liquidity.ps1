# Scenario 3: a refund fails for lack of outbound balance despite on-chain funds; diagnosis, fix, retry.
$ErrorActionPreference = 'Stop'
$lab = Join-Path $PSScriptRoot '..'
& node (Join-Path $lab 'lab/check-node.mjs')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& node --disable-warning=ExperimentalWarning (Join-Path $lab 'scenarios/3-directional-liquidity.ts') @args
exit $LASTEXITCODE
