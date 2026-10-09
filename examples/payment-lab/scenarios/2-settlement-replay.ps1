# Scenario 2: a settlement is delivered again after a listener restart; the order is fulfilled and posted once.
$ErrorActionPreference = 'Stop'
$lab = Join-Path $PSScriptRoot '..'
& node (Join-Path $lab 'lab/check-node.mjs')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& node --disable-warning=ExperimentalWarning (Join-Path $lab 'scenarios/2-settlement-replay.ts') @args
exit $LASTEXITCODE
