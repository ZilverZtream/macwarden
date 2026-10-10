# Scenario 4: a payment settles over several HTLC attempts; the books match LND's principal and fees.
$ErrorActionPreference = 'Stop'
$lab = Join-Path $PSScriptRoot '..'
& node (Join-Path $lab 'lab/check-node.mjs')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& node --disable-warning=ExperimentalWarning (Join-Path $lab 'scenarios/4-multi-attempt.ts') @args
exit $LASTEXITCODE
