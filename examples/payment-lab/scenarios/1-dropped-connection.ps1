# Scenario 1: the connection is cut while the HTLC is held; recovery through TrackPaymentV2. Option: --cut kill|drop
$ErrorActionPreference = 'Stop'
$lab = Join-Path $PSScriptRoot '..'
& node (Join-Path $lab 'lab/check-node.mjs')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& node --disable-warning=ExperimentalWarning (Join-Path $lab 'scenarios/1-dropped-connection.ts') @args
exit $LASTEXITCODE
