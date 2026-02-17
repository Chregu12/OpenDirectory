# OpenDirectory Windows Client Installer
# Installs and configures all required agents for OpenDirectory MDM

param(
    [string]$ServerUrl = "https://mdm.opendirectory.local",
    [string]$EnrollmentToken = "",
    [switch]$Silent = $false
)

Write-Host "OpenDirectory Windows Client Installer" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Create OpenDirectory directory
$OD_DIR = "C:\Program Files\OpenDirectory"
if (!(Test-Path $OD_DIR)) {
    New-Item -ItemType Directory -Path $OD_DIR -Force
}

# Simple device monitoring via PowerShell
Write-Host "Setting up device monitoring..." -ForegroundColor Yellow

# Install OpenDirectory PowerShell module
Write-Host "Installing OpenDirectory PowerShell module..." -ForegroundColor Yellow
$ModulePath = "$OD_DIR\PowerShell\OpenDirectory.psm1"
New-Item -ItemType Directory -Path (Split-Path $ModulePath) -Force

@"
# OpenDirectory PowerShell Module
# Provides cmdlets for interacting with OpenDirectory MDM

function Connect-OpenDirectory {
    param([string]`$ServerUrl = "$ServerUrl")
    
    `$global:OD_SERVER = `$ServerUrl
    Write-Host "Connected to OpenDirectory at `$ServerUrl" -ForegroundColor Green
}

function Get-ODComplianceStatus {
    try {
        `$result = Invoke-RestMethod -Uri "`$global:OD_SERVER/api/compliance/check" -Method POST -Body (@{
            device_id = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
            platform = "windows"
        } | ConvertTo-Json) -ContentType "application/json"
        return `$result
    } catch {
        Write-Error "Failed to check compliance: `$(`$_.Exception.Message)"
    }
}

function Install-ODApplication {
    param([string]`$AppId)
    
    try {
        `$result = Invoke-RestMethod -Uri "`$global:OD_SERVER/api/appstore/deploy" -Method POST -Body (@{
            appId = `$AppId
            deviceIds = @((Get-WmiObject -Class Win32_ComputerSystemProduct).UUID)
            schedule = "immediate"
        } | ConvertTo-Json) -ContentType "application/json"
        Write-Host "Application deployment scheduled: `$(`$result.deploymentId)" -ForegroundColor Green
        return `$result
    } catch {
        Write-Error "Failed to deploy application: `$(`$_.Exception.Message)"
    }
}

function Get-ODPatches {
    try {
        `$deviceId = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
        `$result = Invoke-RestMethod -Uri "`$global:OD_SERVER/api/patches/scan" -Method POST -Body (@{
            device_id = `$deviceId
            platform = "windows"
        } | ConvertTo-Json) -ContentType "application/json"
        return `$result
    } catch {
        Write-Error "Failed to scan for patches: `$(`$_.Exception.Message)"
    }
}

# Auto-connect on module import
Connect-OpenDirectory
"@ | Out-File -FilePath $ModulePath -Encoding UTF8

# Install PowerShell module
Import-Module $ModulePath -Force

# Create scheduled task for compliance checking
Write-Host "Setting up compliance monitoring..." -ForegroundColor Yellow
$TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command `"Import-Module '$ModulePath'; Get-ODComplianceStatus`""
$TaskTrigger = New-ScheduledTaskTrigger -Daily -At "09:00"
$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "OpenDirectory Compliance Check" -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -Force

# Register device with MDM
Write-Host "Registering device with OpenDirectory MDM..." -ForegroundColor Yellow
$DeviceInfo = @{
    device_id = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
    hostname = $env:COMPUTERNAME
    platform = "windows"
    os_version = (Get-WmiObject -Class Win32_OperatingSystem).Version
    enrollment_token = $EnrollmentToken
    installed_software = @()
}

try {
    $RegistrationResult = Invoke-RestMethod -Uri "$ServerUrl/api/devices/register" -Method POST -Body ($DeviceInfo | ConvertTo-Json) -ContentType "application/json"
    Write-Host "Device registered successfully" -ForegroundColor Green
    
    # Save device configuration
    $ConfigPath = "$OD_DIR\device-config.json"
    $DeviceConfig = @{
        device_id = $DeviceInfo.device_id
        server_url = $ServerUrl
        registered_at = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        enrollment_token = $EnrollmentToken
    }
    $DeviceConfig | ConvertTo-Json | Out-File -FilePath $ConfigPath
    
} catch {
    Write-Warning "Device registration failed: $($_.Exception.Message)"
}

# Create desktop shortcut for OpenDirectory tools
$ShortcutPath = "$env:PUBLIC\Desktop\OpenDirectory Tools.lnk"
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-Command `"Import-Module '$ModulePath'; Write-Host 'OpenDirectory Tools Loaded' -ForegroundColor Green; Write-Host 'Available commands: Get-ODComplianceStatus, Install-ODApplication, Get-ODPatches' -ForegroundColor Cyan`""
$Shortcut.WorkingDirectory = $OD_DIR
$Shortcut.IconLocation = "shell32.dll,21"
$Shortcut.Save()

Write-Host ""
Write-Host "OpenDirectory Windows Client installed successfully!" -ForegroundColor Green
Write-Host "Device ID: $($DeviceInfo.device_id)" -ForegroundColor Cyan
Write-Host "Server: $ServerUrl" -ForegroundColor Cyan
Write-Host ""
Write-Host "Available PowerShell commands:" -ForegroundColor Yellow
Write-Host "- Get-ODComplianceStatus" -ForegroundColor White
Write-Host "- Install-ODApplication -AppId <app-id>" -ForegroundColor White  
Write-Host "- Get-ODPatches" -ForegroundColor White
Write-Host ""
Write-Host "Desktop shortcut created: OpenDirectory Tools" -ForegroundColor Cyan