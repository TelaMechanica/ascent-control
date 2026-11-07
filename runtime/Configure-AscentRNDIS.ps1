param(
    [Parameter(Mandatory=$true)][int]$InterfaceIndex,
    [string]$HostAddress = "192.168.3.103",
    [int]$PrefixLength = 24,
    # Undo a configuration THIS script performed. Never touches anything else.
    [switch]$Rollback
)
$ErrorActionPreference = "Stop"

# Ascent USB VID block 0x1D6B-0x1D84, from decompiled vendor VIDConst.
# See docs/PROTOCOL_SPEC.md section 10. Keep in sync with VID_PNP_RE in caddx_read_bundle.py.
# 0x1A86 (the GM-series gimbal bridge) is deliberately NOT recognized here.
# Recognition is not eligibility: QUALIFY still gates every operation.
$AscentVidRe = 'VID_1D(6[B-F]|7[0-9A-F]|8[0-4])'

# OWNERSHIP MARKER.
#
# Rollback must remove ONLY an address this application added. An operator may have
# configured 192.168.3.103 themselves, or another tool may have; deleting that would be
# destroying someone else's configuration to clean up after ourselves. So the add is
# recorded, and rollback refuses anything it cannot prove it created.
#
# It also records whether DHCP was disabled by us, so that is restored too -- otherwise a
# rolled-back adapter is left in a state it was never in before we touched it.
$MarkerDir = Join-Path $env:ProgramData 'AscentControl'
$Marker    = Join-Path $MarkerDir 'rndis_owned.json'

function Read-Marker {
    if (Test-Path -LiteralPath $Marker) {
        try { return (Get-Content -LiteralPath $Marker -Raw | ConvertFrom-Json) } catch { return $null }
    }
    return $null
}

$adapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex -ErrorAction Stop
if ($adapter.PnPDeviceID -notmatch $AscentVidRe -and $adapter.InterfaceDescription -notmatch '(?i)RNDIS|Remote NDIS|USB Ethernet') {
    throw "Interface $InterfaceIndex is not an identified Ascent/RNDIS adapter."
}

if ($Rollback) {
    $m = Read-Marker
    if (-not $m) { Write-Output "Nothing to roll back: no ownership record."; exit 0 }
    if ([int]$m.InterfaceIndex -ne $InterfaceIndex) {
        Write-Output "Nothing to roll back on interface $InterfaceIndex (record is for $($m.InterfaceIndex))."
        exit 0
    }
    $addr = Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -eq $m.HostAddress }
    if ($addr) {
        Remove-NetIPAddress -InterfaceIndex $InterfaceIndex -IPAddress $m.HostAddress -Confirm:$false -ErrorAction Stop
        Write-Output "Removed $($m.HostAddress) from $($adapter.Name)"
    } else {
        Write-Output "Address $($m.HostAddress) already absent."
    }
    if ($m.DhcpWasEnabled) {
        Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -Dhcp Enabled -ErrorAction SilentlyContinue
        Write-Output "Restored DHCP on $($adapter.Name)"
    }
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    exit 0
}

$existing = @(Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
$ascentExisting = $existing | Where-Object {
    $_.PrefixLength -eq 24 -and $_.IPAddress -like '192.168.3.*' -and $_.IPAddress -ne '192.168.3.102'
} | Select-Object -First 1
if ($ascentExisting) {
    Write-Output "Ascent RNDIS already configured: $($adapter.Name) $($ascentExisting.IPAddress)/24"
    exit 0
}

# Capture the prior state BEFORE changing anything, so rollback can restore it.
$iface = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
$dhcpWasEnabled = ($iface -and $iface.Dhcp -eq 'Enabled')

# Dedicated Ascent USB/RNDIS interfaces are configured with an additional static
# host address. We intentionally do not set a gateway or DNS server and we do not
# touch the VRX itself.
Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -Dhcp Disabled -ErrorAction Stop
try {
    New-NetIPAddress -InterfaceIndex $InterfaceIndex -IPAddress $HostAddress -PrefixLength $PrefixLength -AddressFamily IPv4 -ErrorAction Stop | Out-Null
} catch {
    # Leave the adapter as we found it rather than half-configured.
    if ($dhcpWasEnabled) {
        Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -Dhcp Enabled -ErrorAction SilentlyContinue
    }
    throw
}

New-Item -ItemType Directory -Force -Path $MarkerDir | Out-Null
@{
    InterfaceIndex = $InterfaceIndex
    HostAddress    = $HostAddress
    PrefixLength   = $PrefixLength
    DhcpWasEnabled = $dhcpWasEnabled
    ConfiguredUtc  = (Get-Date).ToUniversalTime().ToString('o')
} | ConvertTo-Json | Set-Content -LiteralPath $Marker -Encoding UTF8

Write-Output "Configured $($adapter.Name) as $HostAddress/$PrefixLength"
