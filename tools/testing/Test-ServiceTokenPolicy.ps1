param([Parameter(Mandatory=$true)][string]$ExecutablePath)
$ErrorActionPreference='Stop'
& $ExecutablePath token-policy
exit $LASTEXITCODE
