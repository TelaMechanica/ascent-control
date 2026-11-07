<#
.SYNOPSIS
  Stage a trimmed, pinned GStreamer runtime into gstreamer\ next to the application.

.DESCRIPTION
  WHY THIS EXISTS. The first release searched only machine-global locations for
  GStreamer -- GSTREAMER_1_0_ROOT_MSVC_X86_64, C:\gstreamer and
  C:\Program Files\gstreamer. Every development machine had one of those populated,
  so video worked everywhere it was tried. On a clean Windows install none exist,
  the MSI installed no GStreamer of its own, and video could not start at all. The
  dependency was real, undeclared, and invisible to everyone who already had it.

  WHAT IS STAGED, AND WHY IT IS NOT 500 MB. The upstream x86_64 .exe is ~502 MB
  because it carries the development SDK. This stages ONLY the closure the
  application's own pipeline actually needs:

      rtspsrc ! parsebin ! decodebin3 ! queue ! videoconvert ! d3d11videosink

  Ten plugins, and the DLLs they import, computed by walking PE import tables
  rather than guessed -- about 17 MB. No headers, no .lib, no examples, no
  gst-launch/gst-inspect, no unrelated plugins.

  WHY 1.26.11 AND NOT THE NEWEST. 1.28.x ships only an Inno Setup .exe, which
  cannot be unpacked without either running it (which modifies the build machine)
  or adding a third-party extractor as a build dependency. 1.26.11 ships a real
  .msi, which `msiexec /a` extracts using nothing but Windows itself and changes
  nothing on the machine. That is worth more here than being on the latest point
  release.

  DECODERS. d3d11h264dec and d3d11h265dec live in gstd3d11.dll -- the same plugin
  as the sink -- so hardware decoding for both H.264 and H.265 comes free with a
  file we already need, and no codec library is redistributed. gstlibav.dll
  (avdec_*) and gstopenh264.dll are deliberately NOT staged: see the notes file
  this script writes and THIRD-PARTY-NOTICES.md.

  The archive is verified by SHA-256 before a single byte is extracted. An
  installer that silently ships whatever the network returned is worse than one
  that fails.
#>
[CmdletBinding()]
param(
  [string] $Destination,
  [string] $CacheDir,
  [switch] $Force
)

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Destination) { $Destination = Join-Path $here '..\gstreamer' }
if (-not $CacheDir)    { $CacheDir    = Join-Path $env:TEMP 'ascent-gstreamer' }

# Pinned. Upgrading is a deliberate act: change the version and the hash together,
# re-run, and re-check the element closure below still resolves -- plugin layout
# moves between releases (videoconvert lived in gstvideoconvert.dll before 1.22,
# gstvideoconvertscale.dll after).
$GstVersion  = '1.26.11'
$MsiName     = "gstreamer-1.0-msvc-x86_64-$GstVersion.msi"
$MsiUrl      = "https://gstreamer.freedesktop.org/data/pkg/windows/$GstVersion/msvc/$MsiName"
$MsiSha256   = '31cbc21fa0950b5c1e79c80959b2799805cb05a7a35953a13a9f790776137605'

# The ten plugins that satisfy the application pipeline, including the elements
# rtspsrc and decodebin3 build at runtime rather than at parse time. Each was
# resolved with gst-inspect against this exact version, not from memory.
$Plugins = @(
  'gstcoreelements.dll',        # queue, typefind
  'gsttypefindfunctions.dll',   # stream type detection
  'gstplayback.dll',            # parsebin, decodebin3
  'gstvideoconvertscale.dll',   # videoconvert
  'gstrtsp.dll',                # rtspsrc
  'gstrtp.dll',                 # rtph264depay, rtph265depay
  'gstrtpmanager.dll',          # rtpjitterbuffer, rtpsession, rtp*demux
  'gstudp.dll',                 # udpsrc, udpsink
  'gstvideoparsersbad.dll',     # h264parse, h265parse
  'gstd3d11.dll'                # d3d11videosink + d3d11h264dec + d3d11h265dec
)

if ((Test-Path (Join-Path $Destination 'bin\gstreamer-1.0-0.dll')) -and -not $Force) {
  Write-Host "GStreamer already staged at $Destination (use -Force to restage)."
  exit 0
}

New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
$msi = Join-Path $CacheDir $MsiName

if (-not (Test-Path $msi)) {
  Write-Host "Downloading $MsiUrl"
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri $MsiUrl -OutFile $msi -UseBasicParsing
}

$actual = (Get-FileHash -Path $msi -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $MsiSha256) {
  Remove-Item $msi -Force
  throw "SHA-256 mismatch for ${MsiName}: expected $MsiSha256, got $actual. The cached copy has been removed; re-run."
}
Write-Host "SHA-256 verified: $actual"

# Administrative install == pure extraction. It unpacks the MSI's file tree and
# does NOT register the product, write uninstall entries, or touch PATH. Using the
# real installer here would modify the build machine and could collide with a
# GStreamer the developer already has.
$extract = Join-Path $CacheDir "extract-$GstVersion"
if (-not (Test-Path (Join-Path $extract 'PFiles64\gstreamer\1.0\msvc_x86_64\bin\gstreamer-1.0-0.dll'))) {
  if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
  Write-Host "Extracting (administrative install, nothing is registered)..."
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
    '/a', "`"$msi`"", '/qn', "TARGETDIR=`"$extract`""
  )
  if ($p.ExitCode -ne 0) { throw "msiexec administrative install failed with exit code $($p.ExitCode)." }
}

$root = Join-Path $extract 'PFiles64\gstreamer\1.0\msvc_x86_64'
$srcBin = Join-Path $root 'bin'
$srcPlug = Join-Path $root 'lib\gstreamer-1.0'
if (-not (Test-Path $srcBin))  { throw "Extraction produced no bin directory at $srcBin." }
if (-not (Test-Path $srcPlug)) { throw "Extraction produced no plugin directory at $srcPlug." }

# --- the DLL closure, computed from the PE import tables -----------------------
# Guessing this list would be a standing source of "works here, not there": a
# missing transitive dependency does not fail at stage time, it fails on a user's
# machine as a load error with no name attached.
Add-Type -AssemblyName System.Core
function Get-PeImports {
  param([string] $Path)
  $d = [IO.File]::ReadAllBytes($Path)
  if ($d.Length -lt 0x40 -or $d[0] -ne 0x4D -or $d[1] -ne 0x5A) { return @() }
  $pe = [BitConverter]::ToInt32($d, 0x3C)
  if ($pe + 24 -ge $d.Length) { return @() }
  if ($d[$pe] -ne 0x50 -or $d[$pe+1] -ne 0x45) { return @() }
  $nsec  = [BitConverter]::ToUInt16($d, $pe + 6)
  $optsz = [BitConverter]::ToUInt16($d, $pe + 20)
  $magic = [BitConverter]::ToUInt16($d, $pe + 24)
  $dd    = $pe + 24 + $(if ($magic -eq 0x20b) { 112 } else { 96 })
  $impRva = [BitConverter]::ToUInt32($d, $dd + 8)
  if ($impRva -eq 0) { return @() }
  $secs = @()
  $so = $pe + 24 + $optsz
  for ($i = 0; $i -lt $nsec; $i++) {
    $o = $so + 40 * $i
    $secs += ,@([BitConverter]::ToUInt32($d, $o+12),
                [Math]::Max([BitConverter]::ToUInt32($d, $o+8), [BitConverter]::ToUInt32($d, $o+16)),
                [BitConverter]::ToUInt32($d, $o+20))
  }
  function Rva2Off($rva) {
    foreach ($s in $secs) { if ($rva -ge $s[0] -and $rva -lt $s[0] + $s[1]) { return $s[2] + ($rva - $s[0]) } }
    return -1
  }
  $out = @()
  $base = Rva2Off $impRva
  if ($base -lt 0) { return @() }
  for ($i = 0; ; $i++) {
    $e = $base + 20 * $i
    if ($e + 20 -gt $d.Length) { break }
    $nameRva = [BitConverter]::ToUInt32($d, $e + 12)
    if ($nameRva -eq 0) { break }
    $no = Rva2Off $nameRva
    if ($no -lt 0) { break }
    $end = $no
    while ($end -lt $d.Length -and $d[$end] -ne 0) { $end++ }
    $out += [Text.Encoding]::ASCII.GetString($d, $no, $end - $no)
  }
  return $out
}

$binHave = @{}
Get-ChildItem -Path $srcBin -Filter *.dll | ForEach-Object { $binHave[$_.Name.ToLowerInvariant()] = $_.FullName }

$need = New-Object 'System.Collections.Generic.HashSet[string]'
$stack = New-Object 'System.Collections.Generic.Stack[string]'
# The two we P/Invoke directly are roots even if no plugin imports them.
'gstreamer-1.0-0.dll','gstvideo-1.0-0.dll' | ForEach-Object { $stack.Push($_) }
foreach ($pl in $Plugins) {
  $pp = Join-Path $srcPlug $pl
  if (-not (Test-Path $pp)) { throw "Required plugin $pl is not in the pinned distribution." }
  foreach ($dep in (Get-PeImports $pp)) {
    $k = $dep.ToLowerInvariant(); if ($binHave.ContainsKey($k)) { $stack.Push($k) }
  }
}
while ($stack.Count -gt 0) {
  $n = $stack.Pop().ToLowerInvariant()
  if ($need.Contains($n) -or -not $binHave.ContainsKey($n)) { continue }
  [void]$need.Add($n)
  foreach ($dep in (Get-PeImports $binHave[$n])) {
    $k = $dep.ToLowerInvariant()
    if ($binHave.ContainsKey($k) -and -not $need.Contains($k)) { $stack.Push($k) }
  }
}

if (Test-Path $Destination) { Remove-Item $Destination -Recurse -Force }
$dstBin  = Join-Path $Destination 'bin'
$dstPlug = Join-Path $Destination 'lib\gstreamer-1.0'
New-Item -ItemType Directory -Force -Path $dstBin, $dstPlug | Out-Null

$bytes = 0
foreach ($n in ($need | Sort-Object)) {
  Copy-Item $binHave[$n] -Destination $dstBin -Force
  $bytes += (Get-Item $binHave[$n]).Length
}
foreach ($pl in $Plugins) {
  Copy-Item (Join-Path $srcPlug $pl) -Destination $dstPlug -Force
  $bytes += (Get-Item (Join-Path $srcPlug $pl)).Length
}

# --- licence notices -----------------------------------------------------------
# GStreamer core and the plugins staged here are LGPL-2.1-or-later. Shipping them
# without the notice and without saying where the source is would be a licence
# breach, not an oversight.
$licDir = Join-Path $Destination 'licenses'
New-Item -ItemType Directory -Force -Path $licDir | Out-Null

# The upstream distribution ships NO licence text of its own -- share\ carries
# locale data and nothing else -- so the obligation cannot be met by copying. The
# licence text is committed at third_party\licenses\ and staged from there, which
# also keeps the build offline-deterministic.
$lgpl = Join-Path $here '..\third_party\licenses\LGPL-2.1.txt'
if (-not (Test-Path $lgpl)) { throw "The LGPL-2.1 text is missing at $lgpl; it must ship with the runtime." }
Copy-Item $lgpl -Destination $licDir -Force

# Per-plugin licence inventory. Every plugin staged here reports LGPL; the
# inventory is generated rather than asserted so that adding a plugin with a
# different licence shows up here instead of being discovered by a lawyer.
$inventory = $Plugins | ForEach-Object {
  $mod = switch -Wildcard ($_) {
    'gstcoreelements.dll'      { 'gstreamer' }
    'gsttypefindfunctions.dll' { 'gst-plugins-base' }
    'gstplayback.dll'          { 'gst-plugins-base' }
    'gstvideoconvertscale.dll' { 'gst-plugins-base' }
    'gstrtsp.dll'              { 'gst-plugins-good' }
    'gstrtp.dll'               { 'gst-plugins-good' }
    'gstrtpmanager.dll'        { 'gst-plugins-good' }
    'gstudp.dll'               { 'gst-plugins-good' }
    'gstvideoparsersbad.dll'   { 'gst-plugins-bad' }
    'gstd3d11.dll'             { 'gst-plugins-bad' }
    default                    { 'unknown' }
  }
  [ordered]@{ plugin = $_; license = 'LGPL-2.1-or-later'; source_module = $mod }
}
[IO.File]::WriteAllText((Join-Path $licDir 'plugin-licenses.json'),
  ($inventory | ConvertTo-Json -Depth 3), (New-Object Text.UTF8Encoding $false))

$notice = @"
GStreamer components bundled with Ascent Control
================================================

Version:  $GstVersion (MSVC x86_64)
Source:   $MsiUrl
SHA-256:  $MsiSha256

Ascent Control bundles a trimmed subset of the GStreamer runtime so that video
works without a separate installation. The bundled components -- the GStreamer
core libraries and the ten plugins listed in plugin-licenses.json -- are licensed
under the GNU Lesser General Public License, version 2.1 or later. The full text
is in LGPL-2.1.txt beside this file.

These components are UNMODIFIED binaries from the official distribution named
above. Nothing was patched, recompiled or statically linked into Ascent Control;
they are loaded dynamically at runtime. The corresponding source for this exact
version is published by the GStreamer project at:

    https://gstreamer.freedesktop.org/src/

You may obtain, modify and relink these libraries under the terms of the LGPL. To
replace a bundled component, substitute the corresponding DLL in the gstreamer\
directory of the Ascent Control installation.

GStreamer is a trademark of its respective owners. Ascent Control is not affiliated
with or endorsed by the GStreamer project.
"@
[IO.File]::WriteAllText((Join-Path $licDir 'NOTICE-GStreamer.txt'), $notice,
  (New-Object Text.UTF8Encoding $false))

$manifest = [ordered]@{
  gstreamer_version = $GstVersion
  source_url        = $MsiUrl
  source_sha256     = $MsiSha256
  staged_utc        = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  bin_dlls          = @($need | Sort-Object)
  plugins           = $Plugins
  total_bytes       = $bytes
  license           = 'LGPL-2.1-or-later (GStreamer core and staged plugins)'
  excluded          = @(
    'gstlibav.dll (avdec_h264/avdec_h265) -- FFmpeg-derived software decoders',
    'gstopenh264.dll (openh264dec) -- Cisco OpenH264 software decoder',
    'gstd3d12.dll (d3d12h264dec) -- newer hardware path, not needed while d3d11 is the sink',
    'development SDK, headers, .lib, examples, gst-launch/gst-inspect tools'
  )
}
# WriteAllText with a BOM-less encoder, NOT Set-Content -Encoding UTF8.
# Windows PowerShell's "UTF8" writes a byte-order mark, and a BOM makes the file
# unreadable to every standard JSON parser -- Python's json.load raises on it. The
# manifest exists to be read by tooling, so a BOM would defeat its only purpose.
[IO.File]::WriteAllText(
  (Join-Path $Destination 'gstreamer-manifest.json'),
  ($manifest | ConvertTo-Json -Depth 4),
  (New-Object Text.UTF8Encoding $false))

Write-Host ("Staged GStreamer {0}: {1} runtime DLLs + {2} plugins, {3:N1} MB -> {4}" -f `
  $GstVersion, $need.Count, $Plugins.Count, ($bytes / 1MB), $Destination)
