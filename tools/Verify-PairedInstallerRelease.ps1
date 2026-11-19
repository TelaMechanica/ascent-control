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

function Verify-Edition([string]$RecordPath, [string]$ProductName, [string]$FilePrefix) {
    $record = Get-Content -LiteralPath $RecordPath -Raw | ConvertFrom-Json
    if ($record.source_commit -cne $SourceCommit) {
        throw "$ProductName was not built from the selected shared commit."
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
    return [ordered]@{name=$asset.Name; bytes=$asset.Length; sha256=$sha; version=$record.version}
}

$core = Verify-Edition $CoreRecord 'Ascent Control' 'AscentControl'
$plus = Verify-Edition $PlusRecord 'Ascent Control+' 'AscentControlPlus'
if ($core.sha256 -ceq $plus.sha256) { throw 'Both editions point to the same installer bytes.' }
[ordered]@{source_commit=$SourceCommit; assets=@($core, $plus)} | ConvertTo-Json -Depth 4
