param([string]$BuildRoot=(Join-Path $env:USERPROFILE 'Downloads\ASCENT_Native_UBIFS_Helper_Build_20261106-r4'))
$ErrorActionPreference='Stop'
$RepoRoot=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Tests=Join-Path $BuildRoot 'regression-input'
if(Test-Path $Tests){throw 'Preserve existing regression input; select a new BuildRoot.'}
New-Item -ItemType Directory -Path $Tests|Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'test_helper.py') -Destination $Tests
Copy-Item -LiteralPath (Join-Path $RepoRoot 'artifacts\native-windows-builder-2026-11-06\helper\fixture') -Destination $Tests -Recurse
$python=Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'
& $python -I (Join-Path $Tests 'test_helper.py') (Join-Path $BuildRoot 'ascent-mkfs.ubifs.exe') (Join-Path $Tests 'fixture') (Join-Path $BuildRoot 'regression-results')
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
Copy-Item -LiteralPath (Join-Path $BuildRoot 'regression-results\results.json') -Destination (Join-Path $RepoRoot 'artifacts\native-windows-builder-2026-11-06\helper\windows-r4-regression-results.json')
