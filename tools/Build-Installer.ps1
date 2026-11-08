[CmdletBinding()]
param(
  [string]$OutputDir,
  [string]$WorkDir,
  [string]$NativeArchive,
  [string]$CameraArchive,
  [string]$DependencyCache,
  [int]$BuildRevision=2
)
$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
$payloadSpec=Get-Content -LiteralPath (Join-Path $repo 'release\public-payload.json') -Raw|ConvertFrom-Json
foreach($required in @('python.exe','pythonw.exe','python312.zip','python312._pth')){
 if(-not $payloadSpec.dependencies.pyembed.PSObject.Properties[$required]){throw ('Embedded Python pin is missing: '+$required)}
}
if(-not $payloadSpec.dependencies.gstreamer.PSObject.Properties['bin/gstreamer-1.0-0.dll']){throw 'Pinned media runtime inventory is missing'}
$version=$payloadSpec.version
if($BuildRevision -lt 1 -or $BuildRevision -gt 65535){throw 'BuildRevision must be between 1 and 65535'}
if(-not $OutputDir){$OutputDir=Join-Path $repo 'artifacts\release'}
if(-not $WorkDir){$WorkDir=Join-Path $env:TEMP ('ascent-public-'+[guid]::NewGuid().ToString('N'))}
if(Test-Path -LiteralPath $WorkDir){throw 'Select a fresh work directory; previous build evidence is preserved'}
New-Item -ItemType Directory -Path $WorkDir|Out-Null
# File enumeration expands Windows 8.3 aliases. Use that same canonical root
# before deriving relative inventory paths or compiler path mappings.
$WorkDir=(Get-Item -LiteralPath $WorkDir).FullName
$source=Join-Path $WorkDir 'source'
New-Item -ItemType Directory -Path $source|Out-Null
foreach($entry in $payloadSpec.source_files.PSObject.Properties){
 $from=Join-Path $repo $entry.Name
 if(-not(Test-Path -LiteralPath $from) -or (Get-FileHash -LiteralPath $from -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value){throw ('Source inventory mismatch: '+$entry.Name)}
 $to=Join-Path $source $entry.Name
 New-Item -ItemType Directory -Force -Path (Split-Path -Parent $to)|Out-Null
 Copy-Item -LiteralPath $from -Destination $to
}
Copy-Item -LiteralPath (Join-Path $repo 'release\public-payload.json') -Destination (Join-Path $source 'release\public-payload.json')

# Reuse only explicitly pinned dependency files; never copy an installed AC tree.
foreach($name in @('pyembed','gstreamer')){
 $destination=Join-Path $source $name
 if($DependencyCache){
  foreach($entry in $payloadSpec.dependencies.$name.PSObject.Properties){
   $metadata=Join-Path (Join-Path $source 'release\gstreamer-metadata') $entry.Name
   $from=if($name -eq 'gstreamer' -and (Test-Path -LiteralPath $metadata)){$metadata}else{Join-Path (Join-Path $DependencyCache $name) $entry.Name}
   if(-not(Test-Path -LiteralPath $from) -or (Get-FileHash -LiteralPath $from -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value){throw ('Dependency cache mismatch: '+$name+'/'+$entry.Name)}
   $to=Join-Path $destination $entry.Name
   New-Item -ItemType Directory -Force -Path (Split-Path -Parent $to)|Out-Null
   Copy-Item -LiteralPath $from -Destination $to
  }
 }else{
  $script=if($name -eq 'pyembed'){'Stage-PythonRuntime.ps1'}else{'Stage-GStreamer.ps1'}
  & (Join-Path $source ('tools\'+$script)) -Destination $destination
  if($LASTEXITCODE -ne 0){throw ('Dependency staging failed: '+$name)}
 }
}
# Generated media metadata contains staging timestamps and serializer formatting.
# Ship reviewed, deterministic notices and source metadata; DLL/plugin hashes are
# independently checked below against the exact pinned dependency inventory.
$metadataRoot=Join-Path $source 'release\gstreamer-metadata'
foreach($file in Get-ChildItem -LiteralPath $metadataRoot -Recurse -File){
 $relative=$file.FullName.Substring($metadataRoot.Length+1)
 $destination=Join-Path (Join-Path $source 'gstreamer') $relative
 New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination)|Out-Null
 Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
}
$python=Join-Path $source 'pyembed\python.exe'
$staging=@('-I',(Join-Path $source 'tools\stage_public_inputs.py'),'--root',$source)
if($NativeArchive){$staging+=@('--native-archive',(Resolve-Path -LiteralPath $NativeArchive).ProviderPath)}
if($CameraArchive){$staging+=@('--camera-archive',(Resolve-Path -LiteralPath $CameraArchive).ProviderPath)}
& $python @staging
if($LASTEXITCODE -ne 0){throw 'Public runtime input staging failed'}
& $python -I (Join-Path $source 'tools\verify_public_build.py') --root $source --phase source
if($LASTEXITCODE -ne 0){throw 'Public source/package boundary verification failed'}

$env:MSBUILDDISABLENODEREUSE='1'
$env:DOTNET_CLI_USE_MSBUILD_SERVER='0'
$env:TEMP=Join-Path $WorkDir 'temp';$env:TMP=$env:TEMP
New-Item -ItemType Directory -Path $env:TEMP|Out-Null
$publish=Join-Path $WorkDir 'publish'
$project=Join-Path $source 'src\Ascent.Desktop\Ascent.Desktop.csproj'
$fileVersion=$version+'.'+$BuildRevision
Push-Location $source
try{
 & dotnet tool restore
 if($LASTEXITCODE -ne 0){throw 'Pinned WiX tool restore failed'}
 & dotnet publish $project -c Release -r win-x64 --self-contained true -o $publish "-p:AscentFileVersion=$fileVersion" "-p:BaseOutputPath=$WorkDir\bin\" "-p:BaseIntermediateOutputPath=$WorkDir\obj\" "-p:DirectoryBuildTargetsPath=$source\tools\PreservedBuildOutputs.targets" "-p:PathMap=$WorkDir=/ascent-build" -p:NuGetAudit=false -p:UseSharedCompilation=false -p:ContinuousIntegrationBuild=true -m:1
 if($LASTEXITCODE -ne 0){throw 'Public desktop publish failed'}
 & (Join-Path $publish 'pyembed\python.exe') -I (Join-Path $source 'tools\verify_public_build.py') --root $publish --reference $source --phase publish
 if($LASTEXITCODE -ne 0){throw 'Published public payload verification failed'}
 & (Join-Path $source 'tools\Test-GStreamerPayload.ps1') -StageDir (Join-Path $publish 'gstreamer')
 if($LASTEXITCODE -ne 0){throw 'Published media runtime validation failed'}
 if((Get-Item -LiteralPath (Join-Path $publish 'AscentControl.dll')).VersionInfo.FileVersion -ne $fileVersion){throw 'Desktop file version differs from MSI/backend version'}
 $msi=Join-Path $WorkDir ('AscentControl-'+$version+'-x64.msi')
 & dotnet tool run wix build (Join-Path $source 'installer\AscentControl.wxs') -arch x64 -d "PublishDir=$publish" -d "ProductVersion=$version" -o $msi
 if($LASTEXITCODE -ne 0){throw 'Public MSI authoring failed'}
}finally{Pop-Location}

# Administrative extraction validates contents without installing the application.
$extract=Join-Path $WorkDir 'extracted'
$log=Join-Path $WorkDir 'administrative-extraction.log'
$process=Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/a',('"'+$msi+'"'),'/qn',('TARGETDIR="'+$extract+'"'),'/L*v',('"'+$log+'"')) -Wait -PassThru
if($process.ExitCode -ne 0){throw 'Public MSI administrative extraction failed'}
$executables=@(Get-ChildItem -LiteralPath $extract -Recurse -File -Filter 'AscentControl.exe')
if($executables.Count -ne 1){throw 'Expected exactly one extracted desktop executable'}
$payload=$executables[0].DirectoryName;$count=0
foreach($file in Get-ChildItem -LiteralPath $publish -Recurse -File){
 $relative=$file.FullName.Substring($publish.Length+1);$other=Join-Path $payload $relative
 if(-not(Test-Path -LiteralPath $other) -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $other -Algorithm SHA256).Hash){throw ('Extracted payload mismatch: '+$relative)}
 $count++
}
& (Join-Path $payload 'pyembed\python.exe') -I (Join-Path $source 'tools\verify_public_build.py') --root $payload --reference $source --phase publish
if($LASTEXITCODE -ne 0){throw 'Extracted public payload verification failed'}
New-Item -ItemType Directory -Force -Path $OutputDir|Out-Null
$final=Join-Path $OutputDir (Split-Path -Leaf $msi)
if(Test-Path -LiteralPath $final){throw 'Preserve the existing MSI; select another output directory'}
Copy-Item -LiteralPath $msi -Destination $final
$record=[ordered]@{version=$version;file_version=$fileVersion;msi=$final;bytes=(Get-Item -LiteralPath $final).Length;sha256=(Get-FileHash -LiteralPath $final -Algorithm SHA256).Hash.ToLowerInvariant();verified_payload_files=$count;extracted_payload=$payload;work=$WorkDir;installed=$false;hardware_executed=$false;signed=$false}
$record|ConvertTo-Json|Set-Content -Encoding UTF8 (Join-Path $OutputDir 'public-msi-build-result.json')
Write-Host ($record|ConvertTo-Json -Compress)
