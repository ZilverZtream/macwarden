# Scenario 5: two concurrent payouts race for one budget; reservations hold while unresolved.
$ErrorActionPreference = 'Stop'
$lab = Join-Path $PSScriptRoot '..'
& node (Join-Path $lab 'lab/check-node.mjs')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& node --disable-warning=ExperimentalWarning (Join-Path $lab 'scenarios/5-concurrent-budget.ts') @args
exit $LASTEXITCODE
