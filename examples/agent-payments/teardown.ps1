# Removes the example's containers, volumes and runtime\ directory.
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
node demo.mjs down
exit $LASTEXITCODE
