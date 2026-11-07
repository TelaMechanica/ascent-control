<#
.SYNOPSIS
  Prove the STAGED GStreamer payload works on its own, with no machine-global help.

.DESCRIPTION
  This is the test the original packaging never had. Every development machine here
  has GStreamer installed globally, so a test that merely asks "can video start?"
  passes on the exact machines where the defect is invisible and fails only on the
  clean ones -- which is the wrong way round.

  So this does three things that a naive check does not:

   1. It STRIPS the environment first. GST_* variables are cleared and every
      directory containing gstreamer-1.0-0.dll is removed from PATH for this
      process, so a global install cannot quietly satisfy the test.

   2. It PINS THE VERSION. The loaded runtime must report exactly the staged
      version. This is the discriminator that catches an accidental global
      satisfaction even if the path stripping were imperfect -- a machine-global
      copy is a different build and will report a different version.

   3. It CREATES EVERY REQUIRED ELEMENT, not just a representative one. A missing
      plugin only shows up as the element it provides, and the decoders are chosen
      dynamically so they never appear in the pipeline string at all.

  It does NOT claim live video works. It proves the components are present and
  loadable. Live video is a separate claim requiring a VRX.
#>
[CmdletBinding()]
param(
  [string] $StageDir,
  [string] $ExpectVersion = '1.26.11'
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $StageDir) { $StageDir = Join-Path $here '..\gstreamer' }
# .ProviderPath, NOT .Path. Over a UNC invocation (building from a WSL checkout)
# .Path returns a PowerShell provider-qualified path --
# "Microsoft.PowerShell.Core\FileSystem::\\wsl.localhost\..." -- which Test-Path
# happily accepts but Win32 cannot use. SetDllDirectory and LoadLibraryExW then fail
# with ERROR_MOD_NOT_FOUND, which reads exactly like a missing dependency and is not
# one. .ProviderPath is the native filesystem path.
$StageDir = (Resolve-Path $StageDir).ProviderPath
$bin  = Join-Path $StageDir 'bin'
$plug = Join-Path $StageDir 'lib\gstreamer-1.0'

$fail = 0
function Check([string] $name, [bool] $ok, [string] $detail = '') {
  if ($ok) { Write-Host "  ok   $name" }
  else { $script:fail++; Write-Host "  FAIL $name$(if($detail){"  -- $detail"})" }
}

Write-Host "GStreamer payload test"
Check 'staged bin directory exists' (Test-Path $bin) $bin
Check 'staged plugin directory exists' (Test-Path $plug) $plug
if ($fail) { Write-Host "`n$fail failed"; exit 1 }

# --- 1. strip the environment --------------------------------------------------
foreach ($v in @('GST_PLUGIN_PATH','GST_PLUGIN_PATH_1_0','GST_PLUGIN_SYSTEM_PATH',
                 'GST_PLUGIN_SYSTEM_PATH_1_0','GST_REGISTRY','GST_REGISTRY_1_0',
                 'GSTREAMER_1_0_ROOT_MSVC_X86_64','GST_PLUGIN_SCANNER')) {
  Set-Item -Path "env:$v" -Value $null -ErrorAction SilentlyContinue
  Remove-Item -Path "env:$v" -ErrorAction SilentlyContinue
}
$kept = @(); $dropped = @()
foreach ($d in ($env:PATH -split ';')) {
  if (-not $d) { continue }
  $probe = Join-Path $d 'gstreamer-1.0-0.dll'
  if ((Test-Path $probe -ErrorAction SilentlyContinue) -and
      ((Resolve-Path $d -ErrorAction SilentlyContinue).ProviderPath -ne $bin)) { $dropped += $d }
  else { $kept += $d }
}
$env:PATH = ($kept -join ';')
Write-Host "  (removed $($dropped.Count) global GStreamer director$(if($dropped.Count -eq 1){'y'}else{'ies'}) from PATH)"

# --- 2. point at the staged payload, process scope only ------------------------
$env:GST_PLUGIN_SYSTEM_PATH_1_0 = $plug
$env:GST_PLUGIN_PATH_1_0        = $plug
$reg = Join-Path $env:TEMP ("ascent-gst-payload-test-{0}.bin" -f ([guid]::NewGuid().ToString('N')))
$env:GST_REGISTRY_1_0 = $reg

Add-Type -Namespace AscentGst -Name N -MemberDefinition @'
[DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern bool SetDllDirectory(string lpPathName);
[DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern System.IntPtr LoadLibraryExW(string path, System.IntPtr reserved, uint flags);
[DllImport("gstreamer-1.0-0.dll", CallingConvention=CallingConvention.Cdecl)]
public static extern void gst_init(IntPtr argc, IntPtr argv);
[DllImport("gstreamer-1.0-0.dll", CallingConvention=CallingConvention.Cdecl)]
public static extern IntPtr gst_version_string();
[DllImport("gstreamer-1.0-0.dll", CallingConvention=CallingConvention.Cdecl, CharSet=CharSet.Ansi)]
public static extern IntPtr gst_element_factory_find(string name);
[DllImport("gstreamer-1.0-0.dll", CallingConvention=CallingConvention.Cdecl)]
public static extern void gst_object_unref(IntPtr o);
'@

Check 'the staged bin directory can be made searchable' ([AscentGst.N]::SetDllDirectory($bin))

# This mirrors GstInterop.Initialise exactly, and must keep doing so -- the test is
# only worth anything if it exercises the mechanism that actually ships.
#
# SetDllDirectory alone is not enough. A by-name P/Invoke finds the core DLL but then
# fails to resolve glib/gobject/intl beside it (ERROR_MOD_NOT_FOUND, 0x8007007E), which
# is what this test caught. Loading the core by ABSOLUTE path with
# LOAD_WITH_ALTERED_SEARCH_PATH (0x8) resolves dependencies from the bundle's own
# directory; the by-name P/Invokes below then bind to the already-loaded module.
$LOAD_WITH_ALTERED_SEARCH_PATH = 0x8
$core = Join-Path $bin 'gstreamer-1.0-0.dll'
$h = [AscentGst.N]::LoadLibraryExW($core, [IntPtr]::Zero, $LOAD_WITH_ALTERED_SEARCH_PATH)
if ($h -eq [IntPtr]::Zero) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Check 'the staged core library loads with its own dependencies' $false "Windows error $err"
    Write-Host "`n$fail failed"; exit 1
}
Check 'the staged core library loads with its own dependencies' $true

try { [AscentGst.N]::gst_init([IntPtr]::Zero, [IntPtr]::Zero); Check 'the staged runtime loads and initialises' $true }
catch { Check 'the staged runtime loads and initialises' $false $_.Exception.Message; Write-Host "`n$fail failed"; exit 1 }

$ver = [Runtime.InteropServices.Marshal]::PtrToStringAnsi([AscentGst.N]::gst_version_string())
Write-Host "  runtime reports: $ver"
Check "the loaded runtime is the PINNED version ($ExpectVersion), not a machine-global one" `
      ($ver -match [regex]::Escape($ExpectVersion)) $ver

# --- 3. every element the real pipeline needs ----------------------------------
$required = @('queue','typefind','parsebin','decodebin3','videoconvert',
              'rtspsrc','rtpjitterbuffer','udpsrc',
              'rtph264depay','rtph265depay','h264parse','h265parse',
              'd3d11videosink')
$missing = @()
foreach ($e in $required) {
  $f = [AscentGst.N]::gst_element_factory_find($e)
  if ($f -eq [IntPtr]::Zero) { $missing += $e } else { [AscentGst.N]::gst_object_unref($f) }
}
Check 'every element the application pipeline needs can be created' ($missing.Count -eq 0) ($missing -join ', ')

# Decoders are reported separately: they are hardware-backed, so on a machine with
# no video-capable GPU they can be absent while the install is perfectly intact.
$decMissing = @()
foreach ($e in @('d3d11h264dec','d3d11h265dec')) {
  $f = [AscentGst.N]::gst_element_factory_find($e)
  if ($f -eq [IntPtr]::Zero) { $decMissing += $e } else { [AscentGst.N]::gst_object_unref($f) }
}
if ($decMissing.Count) { Write-Host "  note: hardware decoders absent on this machine: $($decMissing -join ', ')" }
else { Write-Host "  ok   hardware decoders present: d3d11h264dec, d3d11h265dec" }

Check 'the plugin cache was written outside Program Files' `
  ((Test-Path $reg) -and ($reg -notlike '*Program Files*')) $reg
Remove-Item $reg -Force -ErrorAction SilentlyContinue

Write-Host ""
if ($fail) { Write-Host "$fail failed"; exit 1 }
Write-Host "all checks passed"; exit 0
