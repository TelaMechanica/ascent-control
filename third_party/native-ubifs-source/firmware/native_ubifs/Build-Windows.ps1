param([string]$BuildRoot=(Join-Path $env:USERPROFILE 'Downloads\ASCENT_Native_UBIFS_Helper_Build_20261106-r4'), [string]$Python=(Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'), [switch]$NoArtifactCopy)
$ErrorActionPreference='Stop'
$RepoRoot=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
New-Item -ItemType Directory -Force -Path $BuildRoot|Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $BuildRoot 'temp')|Out-Null
$env:TEMP=Join-Path $BuildRoot 'temp'
$env:TMP=$env:TEMP
$Generated=Join-Path $BuildRoot 'generated'
& $Python -I (Join-Path $PSScriptRoot 'build.py') $Generated --prepare-only
if($LASTEXITCODE -ne 0){throw 'Native source preparation failed.'}
$Generated=Join-Path $Generated 'src'
$Source=Join-Path $BuildRoot 'src'
if(-not(Test-Path $Source)){Copy-Item -LiteralPath $Generated -Destination $Source -Recurse}
$Adapter=Join-Path $BuildRoot 'adapter'
New-Item -ItemType Directory -Force -Path $Adapter|Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'portable.h') -Destination $Adapter -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'compat') -Destination $Adapter -Recurse -Force
Get-ChildItem -LiteralPath $Source -Recurse -File|Where-Object{$_.Extension -in '.c','.h'}|ForEach-Object{
 $text=[IO.File]::ReadAllText($_.FullName)
 if($text.Contains('struct stat')){[IO.File]::WriteAllText($_.FullName,$text.Replace('struct stat','struct _stat64'),(New-Object Text.UTF8Encoding($false)))}
}
$gcc='C:\msys64\ucrt64\bin\gcc.exe'
$env:PATH='C:\msys64\ucrt64\bin;'+$env:PATH
$Sub=Join-Path $Source 'ubifs-utils\mkfs.ubifs'
$Sources=@('mkfs.ubifs.c','lpt.c','compr.c','crc16.c','devtable.c','hashtable\hashtable.c','hashtable\hashtable_itr.c')|ForEach-Object{Join-Path $Sub $_}
$Sources+=Join-Path $Source 'lib\libcrc32.c'
$compileArgs=@('-std=gnu11','-O2','-ffunction-sections','-fdata-sections','-D_GNU_SOURCE','-D_FILE_OFFSET_BITS=64','-DWITH_ZLIB','-include','adapter/portable.h','-Iadapter/compat','-Isrc/include','-Isrc/ubifs-utils/mkfs.ubifs')
$Sources=$Sources|ForEach-Object{$_.Substring($BuildRoot.Length+1).Replace('\','/')}
Set-Location -LiteralPath $BuildRoot
$ForwardRoot=$BuildRoot.Replace('\','/')
$compileArgs+=@("-ffile-prefix-map=$BuildRoot=ascent-native-ubifs","-fmacro-prefix-map=$BuildRoot=ascent-native-ubifs","-ffile-prefix-map=$ForwardRoot=ascent-native-ubifs","-fmacro-prefix-map=$ForwardRoot=ascent-native-ubifs")
$compileArgs+=$Sources
$compileArgs+=@('-static','-Wl,--gc-sections,--strip-all,--no-insert-timestamp','-municode','C:\msys64\ucrt64\lib\libz.a','-lbcrypt','-lm','-o',(Join-Path $BuildRoot 'ascent-mkfs.ubifs.exe'))
$Run=1
while(Test-Path (Join-Path $BuildRoot "build-$Run.log")){$Run++}
$compileArgs|ConvertTo-Json|Set-Content -Encoding UTF8 (Join-Path $BuildRoot "command-$Run.json")
$ErrorActionPreference='Continue'
& $gcc @compileArgs 2>&1|Out-File -Encoding UTF8 (Join-Path $BuildRoot "build-$Run.log")
$code=$LASTEXITCODE
$ErrorActionPreference='Stop'
Get-Content (Join-Path $BuildRoot "build-$Run.log")
if($code -ne 0){exit $code}
& (Join-Path $BuildRoot 'ascent-mkfs.ubifs.exe') --ascent-capabilities
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
if(-not $NoArtifactCopy){
 $Destination=Join-Path $RepoRoot 'artifacts\native-windows-builder-2026-11-06\helper\ascent-mkfs.ubifs-r4.exe'
 if(Test-Path $Destination){
  if((Get-FileHash $Destination).Hash -ne (Get-FileHash (Join-Path $BuildRoot 'ascent-mkfs.ubifs.exe')).Hash){throw 'Different artifact exists; preserve it and use -NoArtifactCopy or a versioned destination.'}
 }else{New-Item -ItemType Directory -Force -Path (Split-Path $Destination)|Out-Null;Copy-Item -LiteralPath (Join-Path $BuildRoot 'ascent-mkfs.ubifs.exe') -Destination $Destination}
}
