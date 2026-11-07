param([string]$BuildRoot=(Join-Path $env:USERPROFILE 'Downloads\ASCENT_Native_UBIFS_Helper_Build_20261106-r4'))
$ErrorActionPreference='Stop'
$RepoRoot=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$TestRoot=Join-Path $BuildRoot ('Unicode space '+[char]0x0394)
if(Test-Path $TestRoot){throw 'Test directory already exists; preserve prior test and choose a new BuildRoot.'}
New-Item -ItemType Directory -Path $TestRoot|Out-Null
Copy-Item -LiteralPath (Join-Path $RepoRoot 'artifacts\native-windows-builder-2026-11-06\helper\fixture\payload') -Destination $TestRoot -Recurse
Copy-Item -LiteralPath (Join-Path $RepoRoot 'artifacts\native-windows-builder-2026-11-06\helper\fixture\inventory.json') -Destination $TestRoot
$geometry=Get-Content -Raw (Join-Path $RepoRoot 'artifacts\native-windows-builder-2026-11-06\helper\fixture\geometry.json')|ConvertFrom-Json
$helper=Join-Path $BuildRoot 'ascent-mkfs.ubifs.exe'
$compileArgs=@('--ascent-inventory',(Join-Path $TestRoot 'inventory.json'),'-r',(Join-Path $TestRoot 'payload'),'-o',(Join-Path $TestRoot 'output.ubifs'))+$geometry
& $helper @compileArgs
if($LASTEXITCODE -ne 0){throw "Helper exit $LASTEXITCODE"}
Copy-Item -LiteralPath (Join-Path $TestRoot 'output.ubifs') -Destination (Join-Path $RepoRoot 'artifacts\native-windows-builder-2026-11-06\helper\fixture\windows-output-r4.ubifs')
@{helper=(Get-FileHash -Algorithm SHA256 $helper).Hash;output=(Get-FileHash -Algorithm SHA256 (Join-Path $TestRoot 'output.ubifs')).Hash;native=$true;path='Unicode space U+0394';exit=0}|ConvertTo-Json|Set-Content -Encoding UTF8 (Join-Path $RepoRoot 'artifacts\native-windows-builder-2026-11-06\helper\fixture\windows-result-r4.json')
