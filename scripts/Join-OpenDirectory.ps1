#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Joins a Windows device to an OpenDirectory domain and reports hardware for automatic driver matching.

.DESCRIPTION
    1. Collects hardware inventory (manufacturer, model, OS, PnP device IDs)
    2. Registers the computer with OpenDirectory via the Samba AD DC API
    3. Posts hardware report to device-service for automatic driver matching
    4. Joins the Windows domain using the returned machine credentials
    5. Prints driver recommendations returned by the server

.PARAMETER ApiBase
    Base URL of the OpenDirectory API gateway.  Example: https://opendirectory.corp.example.com

.PARAMETER Realm
    Kerberos realm / AD domain in UPPERCASE.  Example: CORP.EXAMPLE.COM

.PARAMETER AdminUser
    Domain admin username for the join operation.  Example: Administrator

.PARAMETER AdminPassword
    Domain admin password (SecureString).  Prompted if omitted.

.PARAMETER OuDn
    Optional OU distinguished name where the computer account will be placed.
    Example: OU=Workstations,DC=corp,DC=example,DC=com

.EXAMPLE
    .\Join-OpenDirectory.ps1 -ApiBase https://od.corp.local -Realm CORP.LOCAL -AdminUser Administrator
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ApiBase,

    [Parameter(Mandatory)]
    [string]$Realm,

    [Parameter(Mandatory)]
    [string]$AdminUser,

    [SecureString]$AdminPassword,

    [string]$OuDn
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Helper: Invoke-OdApi ──────────────────────────────────────────────────────

function Invoke-OdApi {
    param(
        [string]$Method,
        [string]$Path,
        [hashtable]$Body
    )
    $uri = ($ApiBase.TrimEnd('/')) + $Path
    $params = @{
        Method      = $Method
        Uri         = $uri
        ContentType = 'application/json'
        UseBasicParsing = $true
    }
    if ($Body) { $params['Body'] = ($Body | ConvertTo-Json -Depth 10) }
    try {
        $resp = Invoke-WebRequest @params
        return ($resp.Content | ConvertFrom-Json)
    } catch {
        # Windows PowerShell 5.1 compatible (no ?. / ?? operators)
        $statusCode = 0
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        throw "API $Method $Path failed ($statusCode): $($_.Exception.Message)"
    }
}

# Safe property getter: Set-StrictMode -Version Latest throws on access to a
# property that is absent from a PSCustomObject (e.g. an optional field the
# API omitted from its JSON response), so every access to a dynamically
# parsed API response must be guarded.
function Get-OdProp {
    param(
        $InputObject,
        [string]$Name,
        $Default = $null
    )
    if ($InputObject -and ($InputObject.PSObject.Properties.Name -contains $Name)) {
        return $InputObject.$Name
    }
    return $Default
}

# ─── Step 1: Collect hardware inventory ───────────────────────────────────────

Write-Host "`n[1/5] Collecting hardware inventory..." -ForegroundColor Cyan

$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$os = Get-CimInstance -ClassName Win32_OperatingSystem

$manufacturer = $cs.Manufacturer
$model        = $cs.Model
$hostname     = $env:COMPUTERNAME
$osCaption    = $os.Caption        # e.g. "Microsoft Windows 11 Pro"
$osBuild      = $os.BuildNumber

Write-Host "  Manufacturer : $manufacturer"
Write-Host "  Model        : $model"
Write-Host "  Hostname     : $hostname"
Write-Host "  OS           : $osCaption (Build $osBuild)"

# Collect PnP hardware IDs for finer driver matching
$pnpDevices = @(
    Get-CimInstance -ClassName Win32_PnPEntity |
        Where-Object { $_.Status -eq 'OK' -and $_.DeviceID -ne $null } |
        Select-Object -First 50 @{
            Name       = 'class'
            Expression = { $_.PNPClass }
        }, @{
            Name       = 'deviceId'
            Expression = { $_.DeviceID }
        }, @{
            Name       = 'description'
            Expression = { $_.Description }
        }
)

Write-Host "  PnP devices  : $($pnpDevices.Count) found"

# ─── Step 2: Prompt for password if not provided ───────────────────────────────

if (-not $AdminPassword) {
    $AdminPassword = Read-Host "Domain admin password for $AdminUser" -AsSecureString
}

# ─── Step 3: Register computer with OpenDirectory / Samba AD DC ───────────────

Write-Host "`n[2/5] Registering computer with OpenDirectory domain..." -ForegroundColor Cyan

$joinBody = @{
    computerName    = $hostname
    requestingUser  = $AdminUser
    operatingSystem = $osCaption
    osVersion       = $osBuild
    manufacturer    = $manufacturer
    model           = $model
}
if ($OuDn) { $joinBody['ouDn'] = $OuDn }

try {
    $joinResult = Invoke-OdApi -Method POST -Path '/api/samba/computers/join' -Body $joinBody
} catch {
    Write-Error "Domain join registration failed: $_"
    exit 1
}

$machinePassword = Get-OdProp $joinResult 'machinePassword'
$dcIp            = Get-OdProp $joinResult 'dcIpAddress'
$netbiosDomain   = Get-OdProp $joinResult 'netbiosDomain'
$computerDn      = Get-OdProp $joinResult 'computerDn'

Write-Host "  Computer DN  : $computerDn"
Write-Host "  DC IP        : $dcIp"
Write-Host "  NetBIOS      : $netbiosDomain"

# ─── Step 4: Post hardware report for driver matching ─────────────────────────

Write-Host "`n[3/5] Submitting hardware report for driver matching..." -ForegroundColor Cyan

$hwBody = @{
    hostname     = $hostname
    manufacturer = $manufacturer
    model        = $model
    os           = 'windows'
    osVersion    = $osCaption
    hardwareIds  = @($pnpDevices)
}

try {
    $hwResult = Invoke-OdApi -Method POST -Path '/api/devices/report-hardware' -Body $hwBody
    Write-Host "  Driver recommendations: $(Get-OdProp $hwResult 'count' 0) found"
} catch {
    Write-Warning "Hardware report failed (non-fatal): $_"
    $hwResult = $null
}

# ─── Step 5: Join Windows domain ──────────────────────────────────────────────

Write-Host "`n[4/5] Joining Windows domain $Realm..." -ForegroundColor Cyan

$domainCred = New-Object System.Management.Automation.PSCredential(
    "$netbiosDomain\$AdminUser",
    $AdminPassword
)

$addParams = @{
    DomainName = $Realm
    Credential = $domainCred
    Force      = $true
}
if ($OuDn) { $addParams['OUPath'] = $OuDn }
if ($dcIp)  { $addParams['Server'] = $dcIp }

try {
    Add-Computer @addParams
    Write-Host "  Successfully joined domain $Realm" -ForegroundColor Green
} catch {
    Write-Warning "Windows domain join failed: $_"
    Write-Host "  You can join manually: Add-Computer -DomainName $Realm -Server $dcIp -Credential $netbiosDomain\$AdminUser"
}

# ─── Step 6: Show driver recommendations ──────────────────────────────────────

Write-Host "`n[5/5] Driver recommendations for this device:" -ForegroundColor Cyan

$recommendations = @()
if ($hwResult -and ($hwResult.PSObject.Properties.Name -contains 'recommendations')) {
    $recommendations = @($hwResult.recommendations)
}

if ($recommendations.Count -gt 0) {
    $recommendations | Select-Object -First 10 | ForEach-Object {
        $rec         = $_
        $matchScore  = Get-OdProp $rec 'matchScore'
        $deviceType  = Get-OdProp $rec 'deviceType'
        $recName     = Get-OdProp $rec 'name'
        $recVersion  = Get-OdProp $rec 'version'
        $recOs       = Get-OdProp $rec 'os' @()
        $recFormat   = Get-OdProp $rec 'format'
        $downloadUrl = Get-OdProp $rec 'downloadUrl'

        $score = if ($matchScore) { " [score: $matchScore]" } else { '' }
        $dtype = if ($deviceType) { $deviceType.ToString().ToUpper().PadRight(10) } else { 'OTHER     ' }
        Write-Host "  [$dtype] $recName v$recVersion$score"
        Write-Host "             OS: $($recOs -join ', ')  |  Format: $recFormat"
        if ($downloadUrl) {
            Write-Host "             URL: $downloadUrl"
        }
        Write-Host ""
    }
    Write-Host "  Full list available at: $ApiBase/api/devices/$hostname/driver-recommendations" -ForegroundColor DarkGray
} else {
    Write-Host "  No driver recommendations available (hardware report may still be processing)."
    Write-Host "  Check later: $ApiBase/api/devices/$hostname/driver-recommendations"
}

# ─── Done ──────────────────────────────────────────────────────────────────────

Write-Host "`nDone! A restart is required to complete domain membership." -ForegroundColor Green
Write-Host "After restart, log in with: $netbiosDomain\$AdminUser"

$restart = Read-Host "`nRestart now? [y/N]"
if ($restart -eq 'y' -or $restart -eq 'Y') {
    Restart-Computer -Force
}
