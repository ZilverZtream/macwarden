# Starts the regtest stack and runs the safe agent payments story.
# The stack stays up afterwards; .\teardown.ps1 removes it.
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
node demo.mjs @args
exit $LASTEXITCODE
