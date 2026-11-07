<#
.SYNOPSIS
  Stage the embeddable CPython distribution into pyembed\ next to the application.

.DESCRIPTION
  BackendHost.LocatePythonExecutable() prefers pyembed\pythonw.exe over anything on
  PATH, and it does that for a reason recorded there: this bench's PATH carries five
  interpreters and an ESP-IDF toolchain Python shadows every real install. Shipping
  our own removes the question entirely and removes "install Python first" from the
  user's path.

  The Ascent Control backend is pure standard library -- serial is ctypes/Win32
  (caddx_legacy_serial.py), not pyserial -- so the embeddable distribution needs no
  pip, no site-packages and no build step. sqlite3 (map packages), ctypes (serial),
  socket/ssl (Ground UDP, tile fetch) are all present as .pyd in the distribution.

  The archive is verified by SHA-256 before a single byte is extracted. An installer
  that silently ships whatever the network returned is worse than one that fails.
#>
[CmdletBinding()]
param(
  [string] $Destination,
  [string] $CacheDir,
  [switch] $Force
)

$ErrorActionPreference = 'Stop'

# $PSScriptRoot is not reliably populated inside a param() default on Windows
# PowerShell 5.1, so both paths are resolved here.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Destination) { $Destination = Join-Path $here '..\pyembed' }
if (-not $CacheDir)    { $CacheDir    = Join-Path $env:TEMP 'ascent-pyembed' }

# Pinned. Upgrading the interpreter is a deliberate act: change all three together
# and re-run, never just the version.
$PythonVersion = '3.12.7'
$ArchiveName   = "python-$PythonVersion-embed-amd64.zip"
$ArchiveUrl    = "https://www.python.org/ftp/python/$PythonVersion/$ArchiveName"
$ArchiveSha256 = '0d57bb6cb078b74d23dbfe91f77d6780d45bed328911609f1f7ee2ba1606bf44'

if ((Test-Path (Join-Path $Destination 'pythonw.exe')) -and -not $Force) {
  Write-Host "pyembed already staged at $Destination (use -Force to restage)."
  exit 0
}

New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
$archive = Join-Path $CacheDir $ArchiveName

if (-not (Test-Path $archive)) {
  Write-Host "Downloading $ArchiveUrl"
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri $ArchiveUrl -OutFile $archive -UseBasicParsing
}

$actual = (Get-FileHash -Path $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $ArchiveSha256) {
  Remove-Item $archive -Force
  throw "SHA-256 mismatch for ${ArchiveName}: expected $ArchiveSha256, got $actual. The cached copy has been removed; re-run."
}
Write-Host "SHA-256 verified: $actual"

if (Test-Path $Destination) { Remove-Item $Destination -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Destination | Out-Null
Expand-Archive -Path $archive -DestinationPath $Destination -Force

# Replace the stock ._pth rather than appending to it.
#
# The stock file lists "python312.zip" and "." -- the executable's own directory.
# Our backend lives one level up in runtime\, and whether CPython still inserts the
# script's directory as sys.path[0] when a ._pth is present is exactly the kind of
# interpreter-internal behaviour an installer must not depend on. Naming the path
# explicitly makes the search path deterministic and readable.
#
# Paths in a ._pth are relative to the directory holding it, so ..\runtime resolves
# to the sibling of pyembed -- which is where the csproj stages the backend.
$pth = Join-Path $Destination 'python312._pth'
@'
python312.zip
.
..\runtime

# site is deliberately NOT imported: there are no third-party packages to find, and
# leaving it off keeps a user-level site-packages directory on the build or target
# machine from reaching this interpreter.
'@ | Set-Content -Path $pth -Encoding ASCII

if (-not (Test-Path (Join-Path $Destination 'pythonw.exe'))) {
  throw "Staging produced no pythonw.exe in $Destination."
}
Write-Host "Staged CPython $PythonVersion to $Destination"

# Report success explicitly, and only here.
#
# A PowerShell script does not set $LASTEXITCODE by falling off its end -- it leaves
# whatever the last native process set. Build-Installer.ps1 tests $LASTEXITCODE after
# invoking this script, so without this line a clean build could consume a stale
# nonzero code from some earlier native command and abort AFTER staging had in fact
# succeeded. The early-return path above already exits 0; this is the same statement
# for the fresh-download path, which previously had none.
#
# Position matters. This sits after the download, the SHA-256 verification, the
# extraction, the ._pth rewrite and the pythonw.exe check -- every one of which
# throws on failure and therefore never reaches this line. It cannot turn a failed
# stage into a successful one.
exit 0
