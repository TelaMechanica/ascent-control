[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CoreRecord,
    [Parameter(Mandatory)][string]$PlusRecord,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceCommit
)
$ErrorActionPreference = 'Stop'
$installer = New-Object -ComObject WindowsInstaller.Installer

function Get-MsiProperty($Database, [string]$Name) {
    $query = 'SELECT `Value` FROM `Property` WHERE `Property` = ''' + $Name + ''''
    $view = $Database.OpenView($query)
    try {
        [void]$view.Execute()
        $row = $view.Fetch()
        if ($null -eq $row) { throw "Required MSI property missing: $Name" }
        return $row.StringData(1)
    } finally {
        [void]$view.Close()
    }
}

function Assert-NetRunnerDownloadBoundary($Database, [string]$ProductName) {
    $receiverFiles = @(
        'ascent_wifi_channels', 'wpa_cli', 'wpa_supplicant',
        '8188fu.ko', 'hostapd', 'hostapd_cli', 'busybox'
    )
    $view = $Database.OpenView('SELECT `FileName` FROM `File`')
    try {
        [void]$view.Execute()
        while ($row = $view.Fetch()) {
            # MSI can encode a short name followed by the installed long name.
            $name = ($row.StringData(1) -split '\|')[-1]
            if ($name -in $receiverFiles) {
                throw "$ProductName includes NetRunner receiver file '$name'. Ship it in the widget download."
            }
        }
    } finally {
        [void]$view.Close()
    }
}

# Read the edition stamp that is actually inside the MSI payload. The whole AC/AC+
# split is one bit -- the ascent_edition.txt the installer writes at the install
# root -- so a pair contract that never inspects that bit cannot tell an AC MSI
# from an AC+ MSI, and two mis-stamped builds would pass every other check. An
# administrative extraction lays out the payload without installing; the stamp is
# at the extracted root beside the app.
function Get-MsiEditionStamp([string]$MsiPath, [string]$ProductName) {
    $extract = Join-Path ([IO.Path]::GetTempPath()) ('pair-verify-' + [guid]::NewGuid().ToString('N'))
    $log = "$extract.log"
    $proc = Start-Process -FilePath 'msiexec.exe' -Wait -PassThru -ArgumentList @(
        '/a', ('"' + $MsiPath + '"'), '/qn', ('TARGETDIR="' + $extract + '"'), '/L*v', ('"' + $log + '"'))
    if ($proc.ExitCode -ne 0) { throw "$ProductName administrative extraction failed (exit $($proc.ExitCode))." }
    # The stamp is the install-root marker the backend reads from ROOT.parent, so it
    # must sit BESIDE the application, not merely somewhere in the payload. Anchor on
    # the one application executable and require the stamp as its sibling.
    $exe = @(Get-ChildItem -LiteralPath $extract -Recurse -File -Filter 'AscentControl.exe')
    if ($exe.Count -ne 1) {
        throw "$ProductName MSI must contain exactly one AscentControl.exe (found $($exe.Count))."
    }
    $stamp = Join-Path $exe[0].DirectoryName 'ascent_edition.txt'
    if (-not (Test-Path -LiteralPath $stamp -PathType Leaf)) {
        throw "$ProductName MSI has no ascent_edition.txt at the install root beside AscentControl.exe."
    }
    $all = @(Get-ChildItem -LiteralPath $extract -Recurse -File -Filter 'ascent_edition.txt')
    if ($all.Count -ne 1) {
        throw "$ProductName MSI must carry exactly one ascent_edition.txt (found $($all.Count))."
    }
    return ([IO.File]::ReadAllText($stamp)).Trim().ToLowerInvariant()
}

function Verify-Edition([string]$RecordPath, [string]$ProductName, [string]$FilePrefix, [string]$ExpectedEdition) {
    $record = Get-Content -LiteralPath $RecordPath -Raw | ConvertFrom-Json
    if ($record.source_commit -cne $SourceCommit) {
        throw "$ProductName was not built from the selected shared commit."
    }
    if ($record.edition -cne $ExpectedEdition) {
        throw "$ProductName build record edition '$($record.edition)' is not the expected '$ExpectedEdition'."
    }
    if ($record.installed -ne $false -or $record.hardware_executed -ne $false -or
        $record.verified_payload_files -lt 1) {
        throw "$ProductName lacks a successful offline package verification record."
    }
    $asset = Get-Item -LiteralPath $record.msi
    if ($asset.Name -cne ($FilePrefix + '-' + $record.version + '-x64.msi') -or
        $asset.Length -ne $record.bytes) {
        throw "$ProductName release asset name or size differs from its build record."
    }
    $sha = (Get-FileHash -LiteralPath $asset.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sha -cne $record.sha256) { throw "$ProductName MSI differs from its build record." }
    $db = $installer.OpenDatabase($asset.FullName, 0)
    if ((Get-MsiProperty $db 'ProductName') -cne $ProductName -or
        (Get-MsiProperty $db 'ProductVersion') -cne $record.version) {
        throw "$ProductName MSI database identity differs from its build record."
    }
    $upgradeCode = Get-MsiProperty $db 'UpgradeCode'
    if ($upgradeCode -ne '{353ECEAF-B574-563B-9587-39464C4F0131}') {
        throw "$FilePrefix does not upgrade the Ascent Control Windows product."
    }
    Assert-NetRunnerDownloadBoundary $db $FilePrefix
    # The stamp in the payload is the load-bearing bit: it must match both the
    # build record and the edition this slot is supposed to be.
    $stamp = Get-MsiEditionStamp $asset.FullName $FilePrefix
    if ($stamp -cne $ExpectedEdition) {
        throw "$ProductName MSI edition stamp '$stamp' is not the expected '$ExpectedEdition'."
    }
    return [ordered]@{name=$asset.Name; bytes=$asset.Length; sha256=$sha; version=$record.version; edition=$stamp; product_code=(Get-MsiProperty $db 'ProductCode'); upgrade_code=$upgradeCode}
}

$core = Verify-Edition $CoreRecord 'Ascent Control' 'AscentControl' 'ac'
$plus = Verify-Edition $PlusRecord 'Ascent Control' 'AscentControlPlus' 'acplus'
if ($core.version -cne $plus.version) { throw 'The paired installers must have the same product version.' }
if ($core.product_code -eq $plus.product_code) { throw 'Edition packages must have distinct MSI product codes.' }
if ($core.sha256 -ceq $plus.sha256) { throw 'Both editions point to the same installer bytes.' }
if ($core.edition -ceq $plus.edition) { throw 'The paired installers must carry distinct edition stamps (ac / acplus).' }
[ordered]@{source_commit=$SourceCommit; assets=@($core, $plus)} | ConvertTo-Json -Depth 4
