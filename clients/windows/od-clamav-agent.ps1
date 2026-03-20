# OpenDirectory ClamAV Antivirus Agent for Windows
# Installs, configures, and manages ClamAV with OpenDirectory MDM integration
# Communicates with the antivirus-protection server service on port 3905

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [string]$ServerUrl = "https://mdm.opendirectory.local:3905",

    [Parameter(Mandatory=$false)]
    [string]$DeviceId = "",

    [Parameter(Mandatory=$false)]
    [string]$ApiKey = "",

    [Parameter(Mandatory=$false)]
    [ValidateSet("Default", "Aggressive", "Light")]
    [string]$ScanSchedule = "Default",

    [Parameter(Mandatory=$false)]
    [ValidateSet("Install", "Uninstall", "Update", "Scan", "Status")]
    [string]$Action = "Install"
)

# ============================================================
# Constants and Configuration
# ============================================================

$CLAMAV_VERSION = "1.4.1"
$CLAMAV_DOWNLOAD_URL = "https://www.clamav.net/downloads/production/clamav-${CLAMAV_VERSION}.win.x64.msi"
$CLAMAV_INSTALL_DIR = "C:\Program Files\ClamAV"
$OD_DATA_DIR = "C:\ProgramData\OpenDirectory"
$QUARANTINE_DIR = "$OD_DATA_DIR\Quarantine"
$LOG_DIR = "$OD_DATA_DIR\Logs"
$LOG_FILE = "$LOG_DIR\clamav.log"
$CONFIG_DIR = "$OD_DATA_DIR\ClamAV"
$SERVICE_NAME = "OpenDirectory-ClamAV"
$HEARTBEAT_INTERVAL_SEC = 300
$QUICK_SCAN_PATHS = @("$env:USERPROFILE", "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA", "C:\Windows\Temp")
$FULL_SCAN_PATHS = @("C:\")

# Scan schedule presets (in minutes)
$SCAN_SCHEDULES = @{
    "Default"    = @{ QuickInterval = 60;  FullInterval = 10080 }  # hourly quick, weekly full
    "Aggressive" = @{ QuickInterval = 30;  FullInterval = 1440  }  # 30min quick, daily full
    "Light"      = @{ QuickInterval = 240; FullInterval = 10080 }  # 4hr quick, weekly full
}

# ============================================================
# Logging Functions
# ============================================================

function Initialize-Logging {
    if (!(Test-Path $LOG_DIR)) {
        New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LOG_FILE -Value $logEntry -ErrorAction SilentlyContinue
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
        "DEBUG" { Write-Host $logEntry -ForegroundColor Gray }
        default { Write-Host $logEntry -ForegroundColor White }
    }
}

# ============================================================
# API Communication Functions
# ============================================================

function Invoke-ODApi {
    param(
        [string]$Endpoint,
        [string]$Method = "POST",
        [hashtable]$Body = @{}
    )
    $uri = "$ServerUrl/api/v1/antivirus$Endpoint"
    $headers = @{
        "Content-Type"  = "application/json"
        "X-Api-Key"     = $script:ApiKey
        "X-Device-Id"   = $script:DeviceId
        "X-Agent-Version" = "1.0.0"
        "X-Platform"    = "windows"
    }
    try {
        $jsonBody = $Body | ConvertTo-Json -Depth 10
        $response = Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers -Body $jsonBody -ContentType "application/json" -TimeoutSec 30 -ErrorAction Stop
        return $response
    } catch {
        Write-Log "API call failed: $Endpoint - $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Send-Heartbeat {
    $clamVersion = "unknown"
    $sigVersion = "unknown"
    $sigDate = "unknown"

    try {
        if (Test-Path "$CLAMAV_INSTALL_DIR\clamscan.exe") {
            $versionOutput = & "$CLAMAV_INSTALL_DIR\clamscan.exe" --version 2>$null
            if ($versionOutput -match "ClamAV\s+([\d.]+)") {
                $clamVersion = $Matches[1]
            }
            if ($versionOutput -match "/(\d+)/") {
                $sigVersion = $Matches[1]
            }
        }
    } catch { }

    $quarantineCount = 0
    if (Test-Path $QUARANTINE_DIR) {
        $quarantineCount = (Get-ChildItem -Path $QUARANTINE_DIR -File -ErrorAction SilentlyContinue | Measure-Object).Count
    }

    $clamdRunning = $false
    try {
        $clamdProcess = Get-Process -Name "clamd" -ErrorAction SilentlyContinue
        $clamdRunning = ($null -ne $clamdProcess)
    } catch { }

    $diskUsage = @{}
    try {
        $drives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue
        foreach ($drive in $drives) {
            if ($drive.Used -gt 0 -or $drive.Free -gt 0) {
                $diskUsage[$drive.Name] = @{
                    used_bytes = $drive.Used
                    free_bytes = $drive.Free
                }
            }
        }
    } catch { }

    $body = @{
        device_id          = $script:DeviceId
        timestamp          = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        status             = if ($clamdRunning) { "active" } else { "degraded" }
        clamav_version     = $clamVersion
        signature_version  = $sigVersion
        engine_running     = $clamdRunning
        realtime_enabled   = $clamdRunning
        quarantine_count   = $quarantineCount
        last_quick_scan    = (Get-ItemProperty -Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV" -Name "LastQuickScan" -ErrorAction SilentlyContinue).LastQuickScan
        last_full_scan     = (Get-ItemProperty -Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV" -Name "LastFullScan" -ErrorAction SilentlyContinue).LastFullScan
        os_info            = @{
            platform   = "windows"
            version    = [System.Environment]::OSVersion.VersionString
            hostname   = $env:COMPUTERNAME
            arch       = $env:PROCESSOR_ARCHITECTURE
        }
        disk_usage         = $diskUsage
    }

    $result = Invoke-ODApi -Endpoint "/heartbeat" -Body $body
    if ($null -ne $result) {
        Write-Log "Heartbeat sent successfully" "DEBUG"
    }
    return $result
}

function Send-ScanReport {
    param(
        [string]$ScanType,
        [string]$ScanPath,
        [int]$FilesScanned,
        [int]$ThreatsFound,
        [array]$Threats,
        [int]$DurationSeconds,
        [string]$Status
    )

    $body = @{
        device_id       = $script:DeviceId
        scan_type       = $ScanType
        scan_path       = $ScanPath
        started_at      = (Get-Date).AddSeconds(-$DurationSeconds).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        completed_at    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        duration_seconds = $DurationSeconds
        files_scanned   = $FilesScanned
        threats_found   = $ThreatsFound
        threats         = $Threats
        status          = $Status
        platform        = "windows"
    }

    $result = Invoke-ODApi -Endpoint "/scan-report" -Body $body
    if ($null -ne $result) {
        Write-Log "Scan report submitted: $ScanType - $ThreatsFound threats found" "INFO"
    }
    return $result
}

function Send-ThreatReport {
    param(
        [string]$FilePath,
        [string]$ThreatName,
        [string]$ActionTaken,
        [string]$QuarantinePath
    )

    $body = @{
        device_id       = $script:DeviceId
        timestamp       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        file_path       = $FilePath
        threat_name     = $ThreatName
        action_taken    = $ActionTaken
        quarantine_path = $QuarantinePath
        platform        = "windows"
    }

    Invoke-ODApi -Endpoint "/threat-detected" -Body $body | Out-Null
}

# ============================================================
# ClamAV Installation and Configuration
# ============================================================

function Install-ClamAV {
    Write-Log "Starting ClamAV installation..." "INFO"

    # Create required directories
    foreach ($dir in @($OD_DATA_DIR, $QUARANTINE_DIR, $LOG_DIR, $CONFIG_DIR)) {
        if (!(Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Log "Created directory: $dir" "INFO"
        }
    }

    # Check if ClamAV is already installed
    if (Test-Path "$CLAMAV_INSTALL_DIR\clamscan.exe") {
        Write-Log "ClamAV is already installed at $CLAMAV_INSTALL_DIR" "INFO"
    } else {
        # Download ClamAV MSI
        $msiPath = "$env:TEMP\clamav-install.msi"
        Write-Log "Downloading ClamAV $CLAMAV_VERSION..." "INFO"

        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($CLAMAV_DOWNLOAD_URL, $msiPath)
            Write-Log "Download complete: $msiPath" "INFO"
        } catch {
            Write-Log "Failed to download ClamAV: $($_.Exception.Message)" "ERROR"

            # Fallback: try Chocolatey
            Write-Log "Attempting installation via Chocolatey..." "INFO"
            try {
                if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
                    Write-Log "Installing Chocolatey..." "INFO"
                    Set-ExecutionPolicy Bypass -Scope Process -Force
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
                }
                choco install clamav -y --no-progress
                Write-Log "ClamAV installed via Chocolatey" "INFO"
            } catch {
                Write-Log "All installation methods failed: $($_.Exception.Message)" "ERROR"
                throw "Cannot install ClamAV. Please install manually."
            }
            return
        }

        # Silent MSI install
        Write-Log "Installing ClamAV MSI (silent)..." "INFO"
        $msiArgs = "/i `"$msiPath`" /qn /norestart INSTALLDIR=`"$CLAMAV_INSTALL_DIR`""
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
        if ($process.ExitCode -ne 0) {
            Write-Log "MSI installation failed with exit code $($process.ExitCode)" "ERROR"
            throw "ClamAV MSI installation failed"
        }
        Write-Log "ClamAV MSI installation complete" "INFO"

        # Clean up
        Remove-Item -Path $msiPath -Force -ErrorAction SilentlyContinue
    }

    # Add ClamAV to system PATH
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($currentPath -notlike "*$CLAMAV_INSTALL_DIR*") {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$CLAMAV_INSTALL_DIR", "Machine")
        $env:Path = "$env:Path;$CLAMAV_INSTALL_DIR"
        Write-Log "Added ClamAV to system PATH" "INFO"
    }

    # Configure ClamAV
    Write-ClamdConf
    Write-FreshclamConf

    # Create registry key for state tracking
    if (!(Test-Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV")) {
        New-Item -Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV" -Name "InstalledAt" -Value (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    Set-ItemProperty -Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV" -Name "ServerUrl" -Value $ServerUrl
    Set-ItemProperty -Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV" -Name "DeviceId" -Value $script:DeviceId

    # Initial signature update
    Update-Signatures

    Write-Log "ClamAV installation and configuration complete" "INFO"
}

function Write-ClamdConf {
    Write-Log "Writing clamd.conf..." "INFO"
    $clamdConf = @"
# OpenDirectory ClamAV Daemon Configuration
# Generated by od-clamav-agent.ps1

# Logging
LogFile $LOG_DIR\clamd.log
LogFileMaxSize 50M
LogTime yes
LogRotate yes
LogVerbose no

# Daemon settings
DatabaseDirectory $CONFIG_DIR\signatures
LocalSocket \\.\pipe\clamd
FixStaleSocket yes
TCPSocket 3310
TCPAddr 127.0.0.1
MaxConnectionQueueLength 30
MaxThreads 12
ReadTimeout 180
CommandReadTimeout 30
SendBufTimeout 200
IdleTimeout 60

# Scanning limits
MaxScanSize 400M
MaxFileSize 100M
MaxRecursion 17
MaxFiles 10000
MaxEmbeddedPE 40M
MaxHTMLNormalize 40M
MaxHTMLNoTags 8M
MaxScriptNormalize 5M
MaxZipTypeRcg 1M
MaxPartitions 50
MaxIconsPE 200

# Scanning options
ScanPE yes
ScanELF yes
ScanOLE2 yes
ScanPDF yes
ScanSWF yes
ScanXMLDOCS yes
ScanHWP3 yes
ScanMail yes
ScanArchive yes
AlertBrokenExecutables yes
AlertEncrypted yes
AlertEncryptedArchive yes
AlertEncryptedDoc yes
AlertOLE2Macros yes
AlertExceedsMax yes

# Heuristics
HeuristicAlerts yes
HeuristicScanPrecedence yes

# On-access scanning (Windows real-time protection)
OnAccessIncludePath C:\Users
OnAccessIncludePath C:\Windows\Temp
OnAccessIncludePath C:\ProgramData
OnAccessExcludePath $QUARANTINE_DIR
OnAccessExcludePath $LOG_DIR
OnAccessMaxFileSize 50M
OnAccessPrevention yes
OnAccessDisableDDD no

# Bytecode engine
Bytecode yes
BytecodeSecurity TrustSigned
BytecodeTimeout 60000

# Self-check interval (database reload check in seconds)
SelfCheck 3600

# Exclude OpenDirectory own files from scanning
ExcludePath $QUARANTINE_DIR
ExcludePath $LOG_DIR
"@
    $clamdConf | Out-File -FilePath "$CONFIG_DIR\clamd.conf" -Encoding UTF8 -Force

    # Create signatures directory
    if (!(Test-Path "$CONFIG_DIR\signatures")) {
        New-Item -ItemType Directory -Path "$CONFIG_DIR\signatures" -Force | Out-Null
    }

    Write-Log "clamd.conf written to $CONFIG_DIR\clamd.conf" "INFO"
}

function Write-FreshclamConf {
    Write-Log "Writing freshclam.conf..." "INFO"
    $freshclamConf = @"
# OpenDirectory FreshClam Configuration
# Generated by od-clamav-agent.ps1

# Database settings
DatabaseDirectory $CONFIG_DIR\signatures
DatabaseOwner SYSTEM

# Update settings
UpdateLogFile $LOG_DIR\freshclam.log
LogFileMaxSize 10M
LogTime yes
LogRotate yes
LogVerbose no

# Mirror settings
DatabaseMirror database.clamav.net
ScriptedUpdates yes
CompressLocalDatabase no

# Check interval (in checks per day, max 50)
Checks 24

# Connection settings
ConnectTimeout 30
ReceiveTimeout 60
DNSDatabaseInfo current.cvd.clamav.net
MaxAttempts 3

# Notification - ping OpenDirectory server on update
NotifyClamd $CONFIG_DIR\clamd.conf

# Proxy settings (uncomment and configure if behind proxy)
# HTTPProxyServer proxy.example.com
# HTTPProxyPort 8080
# HTTPProxyUsername proxyuser
# HTTPProxyPassword proxypass

# Freshclam user agent
HTTPUserAgent OpenDirectory-ClamAV/1.0 (Windows)

# Safebrowsing (extra signatures)
SafeBrowsing yes
"@
    $freshclamConf | Out-File -FilePath "$CONFIG_DIR\freshclam.conf" -Encoding UTF8 -Force
    Write-Log "freshclam.conf written to $CONFIG_DIR\freshclam.conf" "INFO"
}

function Update-Signatures {
    Write-Log "Updating ClamAV signatures..." "INFO"
    $freshclamExe = "$CLAMAV_INSTALL_DIR\freshclam.exe"

    if (!(Test-Path $freshclamExe)) {
        Write-Log "freshclam.exe not found at $freshclamExe" "ERROR"
        return $false
    }

    try {
        $output = & $freshclamExe --config-file="$CONFIG_DIR\freshclam.conf" --datadir="$CONFIG_DIR\signatures" 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0 -or $exitCode -eq 1) {
            Write-Log "Signature update completed successfully" "INFO"
            Write-Log "freshclam output: $output" "DEBUG"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV" -Name "LastSignatureUpdate" -Value (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")

            # Report update to server
            Invoke-ODApi -Endpoint "/signature-update" -Body @{
                device_id  = $script:DeviceId
                timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                status     = "success"
                output     = ($output | Out-String).Substring(0, [Math]::Min(($output | Out-String).Length, 2000))
                platform   = "windows"
            } | Out-Null

            return $true
        } else {
            Write-Log "Signature update failed with exit code $exitCode : $output" "WARN"
            return $false
        }
    } catch {
        Write-Log "Signature update error: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# ============================================================
# Scanning Functions
# ============================================================

function Invoke-ClamScan {
    param(
        [string]$ScanType,
        [string[]]$Paths
    )

    $clamscanExe = "$CLAMAV_INSTALL_DIR\clamscan.exe"
    if (!(Test-Path $clamscanExe)) {
        Write-Log "clamscan.exe not found" "ERROR"
        return
    }

    $scanId = [guid]::NewGuid().ToString()
    $startTime = Get-Date
    Write-Log "Starting $ScanType scan (ID: $scanId)..." "INFO"

    $allThreats = @()
    $totalFilesScanned = 0
    $totalThreatsFound = 0

    foreach ($scanPath in $Paths) {
        if (!(Test-Path $scanPath)) {
            Write-Log "Scan path does not exist, skipping: $scanPath" "WARN"
            continue
        }

        Write-Log "Scanning: $scanPath" "INFO"

        $scanLogFile = "$LOG_DIR\scan-$scanId-$(Get-Date -Format 'yyyyMMddHHmmss').log"

        $clamscanArgs = @(
            "--database=`"$CONFIG_DIR\signatures`""
            "--log=`"$scanLogFile`""
            "--recursive"
            "--infected"
            "--move=`"$QUARANTINE_DIR`""
            "--max-filesize=100M"
            "--max-scansize=400M"
            "--max-recursion=17"
            "--max-files=50000"
            "--bell"
            "`"$scanPath`""
        )

        try {
            $output = & $clamscanExe @clamscanArgs 2>&1
            $exitCode = $LASTEXITCODE
        } catch {
            Write-Log "Scan execution error for $scanPath : $($_.Exception.Message)" "ERROR"
            continue
        }

        # Parse scan output
        $outputText = $output | Out-String

        # Extract summary values
        $filesScanned = 0
        $threatsFound = 0

        if ($outputText -match "Scanned files:\s*(\d+)") {
            $filesScanned = [int]$Matches[1]
        }
        if ($outputText -match "Infected files:\s*(\d+)") {
            $threatsFound = [int]$Matches[1]
        }

        $totalFilesScanned += $filesScanned
        $totalThreatsFound += $threatsFound

        # Parse individual threat lines (format: /path/to/file: ThreatName FOUND)
        $threatLines = $outputText -split "`n" | Where-Object { $_ -match ":\s+\S+\s+FOUND$" }
        foreach ($line in $threatLines) {
            if ($line -match "^(.+):\s+(\S+)\s+FOUND$") {
                $threatFilePath = $Matches[1].Trim()
                $threatName = $Matches[2].Trim()
                $quarantinedFile = Join-Path $QUARANTINE_DIR (Split-Path $threatFilePath -Leaf)

                $threat = @{
                    file_path       = $threatFilePath
                    threat_name     = $threatName
                    action          = "quarantined"
                    quarantine_path = $quarantinedFile
                    detected_at     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                }
                $allThreats += $threat

                Write-Log "THREAT DETECTED: $threatName in $threatFilePath - quarantined" "WARN"

                # Report each threat individually
                Send-ThreatReport -FilePath $threatFilePath -ThreatName $threatName -ActionTaken "quarantined" -QuarantinePath $quarantinedFile
            }
        }

        Write-Log "Scan of $scanPath complete: $filesScanned files scanned, $threatsFound threats found" "INFO"
    }

    $endTime = Get-Date
    $durationSeconds = [int]($endTime - $startTime).TotalSeconds

    # Update registry
    $scanTimestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    if ($ScanType -eq "quick") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV" -Name "LastQuickScan" -Value $scanTimestamp
    } else {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV" -Name "LastFullScan" -Value $scanTimestamp
    }

    # Send scan report to server
    Send-ScanReport -ScanType $ScanType `
        -ScanPath ($Paths -join "; ") `
        -FilesScanned $totalFilesScanned `
        -ThreatsFound $totalThreatsFound `
        -Threats $allThreats `
        -DurationSeconds $durationSeconds `
        -Status "completed"

    Write-Log "$ScanType scan complete: $totalFilesScanned files, $totalThreatsFound threats, ${durationSeconds}s elapsed" "INFO"

    return @{
        ScanType       = $ScanType
        FilesScanned   = $totalFilesScanned
        ThreatsFound   = $totalThreatsFound
        Threats        = $allThreats
        DurationSeconds = $durationSeconds
    }
}

# ============================================================
# Windows Service Management
# ============================================================

function Install-ClamAVService {
    Write-Log "Installing OpenDirectory-ClamAV Windows Service..." "INFO"

    # Create the main service script that runs as a persistent daemon
    $serviceScriptPath = "$OD_DATA_DIR\ClamAV\od-clamav-service.ps1"

    $serviceScript = @'
# OpenDirectory ClamAV Service Daemon
# This script runs as a Windows service and manages all ClamAV operations

param(
    [string]$ConfigDir = "C:\ProgramData\OpenDirectory\ClamAV",
    [string]$LogDir = "C:\ProgramData\OpenDirectory\Logs",
    [string]$QuarantineDir = "C:\ProgramData\OpenDirectory\Quarantine",
    [string]$ClamAVDir = "C:\Program Files\ClamAV"
)

$LOG_FILE = "$LogDir\clamav.log"

function Write-ServiceLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [SERVICE] [$Level] $Message"
    Add-Content -Path $LOG_FILE -Value $entry -ErrorAction SilentlyContinue
}

# Read configuration from registry
$regPath = "HKLM:\SOFTWARE\OpenDirectory\ClamAV"
$ServerUrl = (Get-ItemProperty -Path $regPath -Name "ServerUrl" -ErrorAction SilentlyContinue).ServerUrl
$DeviceId = (Get-ItemProperty -Path $regPath -Name "DeviceId" -ErrorAction SilentlyContinue).DeviceId
$ApiKey = (Get-ItemProperty -Path $regPath -Name "ApiKey" -ErrorAction SilentlyContinue).ApiKey
$QuickIntervalMin = (Get-ItemProperty -Path $regPath -Name "QuickIntervalMin" -ErrorAction SilentlyContinue).QuickIntervalMin
$FullIntervalMin = (Get-ItemProperty -Path $regPath -Name "FullIntervalMin" -ErrorAction SilentlyContinue).FullIntervalMin

if (!$QuickIntervalMin) { $QuickIntervalMin = 60 }
if (!$FullIntervalMin) { $FullIntervalMin = 10080 }

Write-ServiceLog "OpenDirectory ClamAV Service starting..."
Write-ServiceLog "Server: $ServerUrl | Device: $DeviceId"
Write-ServiceLog "Quick scan interval: ${QuickIntervalMin}m | Full scan interval: ${FullIntervalMin}m"

# ---- Start clamd daemon ----
$clamdExe = "$ClamAVDir\clamd.exe"
$clamdConf = "$ConfigDir\clamd.conf"
$clamdProcess = $null

if (Test-Path $clamdExe) {
    Write-ServiceLog "Starting clamd daemon..."
    try {
        $clamdProcess = Start-Process -FilePath $clamdExe -ArgumentList "--config-file=`"$clamdConf`"" -WindowStyle Hidden -PassThru
        Write-ServiceLog "clamd started with PID $($clamdProcess.Id)"
    } catch {
        Write-ServiceLog "Failed to start clamd: $($_.Exception.Message)" "ERROR"
    }
}

# ---- API helper ----
function Invoke-ServiceApi {
    param([string]$Endpoint, [hashtable]$Body = @{})
    $uri = "$ServerUrl/api/v1/antivirus$Endpoint"
    $headers = @{
        "Content-Type" = "application/json"
        "X-Api-Key" = $ApiKey
        "X-Device-Id" = $DeviceId
        "X-Platform" = "windows"
    }
    try {
        Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body ($Body | ConvertTo-Json -Depth 10) -ContentType "application/json" -TimeoutSec 30 -ErrorAction Stop
    } catch {
        Write-ServiceLog "API call failed: $Endpoint - $($_.Exception.Message)" "ERROR"
        $null
    }
}

# ---- Heartbeat ----
function Send-ServiceHeartbeat {
    $clamdRunning = $false
    if ($clamdProcess -and !$clamdProcess.HasExited) { $clamdRunning = $true }

    $quarantineCount = 0
    if (Test-Path $QuarantineDir) {
        $quarantineCount = (Get-ChildItem $QuarantineDir -File -ErrorAction SilentlyContinue | Measure-Object).Count
    }

    Invoke-ServiceApi -Endpoint "/heartbeat" -Body @{
        device_id = $DeviceId
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        status = if ($clamdRunning) { "active" } else { "degraded" }
        engine_running = $clamdRunning
        realtime_enabled = $clamdRunning
        quarantine_count = $quarantineCount
        platform = "windows"
    } | Out-Null
    Write-ServiceLog "Heartbeat sent (clamd running: $clamdRunning)" "DEBUG"
}

# ---- Scan function ----
function Invoke-ServiceScan {
    param([string]$ScanType)

    $clamscanExe = "$ClamAVDir\clamscan.exe"
    if (!(Test-Path $clamscanExe)) { Write-ServiceLog "clamscan not found" "ERROR"; return }

    $paths = if ($ScanType -eq "quick") {
        @("$env:USERPROFILE", "$env:TEMP", "$env:APPDATA", "C:\Windows\Temp")
    } else {
        @("C:\")
    }

    $startTime = Get-Date
    Write-ServiceLog "Starting $ScanType scan..."

    $totalFiles = 0; $totalThreats = 0; $threats = @()

    foreach ($p in $paths) {
        if (!(Test-Path $p)) { continue }
        $scanLog = "$LogDir\scan-$(Get-Date -Format 'yyyyMMddHHmmss').log"
        $output = & $clamscanExe --database="$ConfigDir\signatures" --log="$scanLog" --recursive --infected --move="$QuarantineDir" "$p" 2>&1
        $text = $output | Out-String

        if ($text -match "Scanned files:\s*(\d+)") { $totalFiles += [int]$Matches[1] }
        if ($text -match "Infected files:\s*(\d+)") { $totalThreats += [int]$Matches[1] }

        $text -split "`n" | Where-Object { $_ -match ":\s+\S+\s+FOUND$" } | ForEach-Object {
            if ($_ -match "^(.+):\s+(\S+)\s+FOUND$") {
                $threats += @{ file_path = $Matches[1].Trim(); threat_name = $Matches[2].Trim(); action = "quarantined" }
                Write-ServiceLog "THREAT: $($Matches[2]) in $($Matches[1])" "WARN"
            }
        }
    }

    $duration = [int]((Get-Date) - $startTime).TotalSeconds

    # Report to server
    Invoke-ServiceApi -Endpoint "/scan-report" -Body @{
        device_id = $DeviceId; scan_type = $ScanType; files_scanned = $totalFiles
        threats_found = $totalThreats; threats = $threats; duration_seconds = $duration
        status = "completed"; platform = "windows"
        completed_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    } | Out-Null

    # Update registry
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    if ($ScanType -eq "quick") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV" -Name "LastQuickScan" -Value $ts
    } else {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV" -Name "LastFullScan" -Value $ts
    }

    Write-ServiceLog "$ScanType scan done: $totalFiles files, $totalThreats threats, ${duration}s"
}

# ---- Signature update ----
function Update-ServiceSignatures {
    $freshclamExe = "$ClamAVDir\freshclam.exe"
    if (!(Test-Path $freshclamExe)) { return }
    Write-ServiceLog "Updating signatures..."
    $output = & $freshclamExe --config-file="$ConfigDir\freshclam.conf" --datadir="$ConfigDir\signatures" 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0 -or $exitCode -eq 1) {
        Write-ServiceLog "Signature update completed"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV" -Name "LastSignatureUpdate" -Value (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    } else {
        Write-ServiceLog "Signature update failed (exit $exitCode)" "WARN"
    }
}

# ---- Main service loop ----
$heartbeatTimer = [System.Diagnostics.Stopwatch]::StartNew()
$quickScanTimer = [System.Diagnostics.Stopwatch]::StartNew()
$fullScanTimer = [System.Diagnostics.Stopwatch]::StartNew()
$sigUpdateTimer = [System.Diagnostics.Stopwatch]::StartNew()

# Stagger: initial signature update
Update-ServiceSignatures
Send-ServiceHeartbeat

Write-ServiceLog "Entering main service loop"

while ($true) {
    try {
        # Heartbeat every 5 minutes
        if ($heartbeatTimer.Elapsed.TotalMinutes -ge 5) {
            Send-ServiceHeartbeat
            $heartbeatTimer.Restart()
        }

        # Quick scan
        if ($quickScanTimer.Elapsed.TotalMinutes -ge $QuickIntervalMin) {
            Invoke-ServiceScan -ScanType "quick"
            $quickScanTimer.Restart()
        }

        # Full scan
        if ($fullScanTimer.Elapsed.TotalMinutes -ge $FullIntervalMin) {
            Invoke-ServiceScan -ScanType "full"
            $fullScanTimer.Restart()
        }

        # Signature update every 4 hours
        if ($sigUpdateTimer.Elapsed.TotalHours -ge 4) {
            Update-ServiceSignatures
            $sigUpdateTimer.Restart()
        }

        # Restart clamd if it crashed
        if ($clamdProcess -and $clamdProcess.HasExited) {
            Write-ServiceLog "clamd process exited unexpectedly, restarting..." "WARN"
            try {
                $clamdProcess = Start-Process -FilePath $clamdExe -ArgumentList "--config-file=`"$clamdConf`"" -WindowStyle Hidden -PassThru
                Write-ServiceLog "clamd restarted with PID $($clamdProcess.Id)"
            } catch {
                Write-ServiceLog "Failed to restart clamd: $($_.Exception.Message)" "ERROR"
            }
        }

        # Check for server-side commands
        $commands = Invoke-ServiceApi -Endpoint "/pending-commands" -Body @{ device_id = $DeviceId }
        if ($commands -and $commands.commands) {
            foreach ($cmd in $commands.commands) {
                Write-ServiceLog "Received server command: $($cmd.action)"
                switch ($cmd.action) {
                    "quick_scan"  { Invoke-ServiceScan -ScanType "quick" }
                    "full_scan"   { Invoke-ServiceScan -ScanType "full" }
                    "update_sigs" { Update-ServiceSignatures }
                    default       { Write-ServiceLog "Unknown command: $($cmd.action)" "WARN" }
                }
            }
        }

    } catch {
        Write-ServiceLog "Service loop error: $($_.Exception.Message)" "ERROR"
    }

    Start-Sleep -Seconds 30
}
'@
    $serviceScript | Out-File -FilePath $serviceScriptPath -Encoding UTF8 -Force
    Write-Log "Service script written to $serviceScriptPath" "INFO"

    # Store schedule configuration in registry
    $schedule = $SCAN_SCHEDULES[$ScanSchedule]
    Set-ItemProperty -Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV" -Name "QuickIntervalMin" -Value $schedule.QuickInterval
    Set-ItemProperty -Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV" -Name "FullIntervalMin" -Value $schedule.FullInterval
    Set-ItemProperty -Path "HKLM:\SOFTWARE\OpenDirectory\ClamAV" -Name "ApiKey" -Value $script:ApiKey

    # Use NSSM (Non-Sucking Service Manager) or sc.exe to create the service
    # First try NSSM, fall back to a scheduled-task-based approach
    $nssmPath = "$OD_DATA_DIR\ClamAV\nssm.exe"
    $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
    $nssmInstalled = $false

    try {
        if (!(Test-Path $nssmPath)) {
            Write-Log "Downloading NSSM for service management..." "INFO"
            $nssmZip = "$env:TEMP\nssm.zip"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -ErrorAction Stop

            # Extract nssm.exe
            $nssmExtractDir = "$env:TEMP\nssm-extract"
            Expand-Archive -Path $nssmZip -DestinationPath $nssmExtractDir -Force
            $nssmExe = Get-ChildItem -Path $nssmExtractDir -Recurse -Filter "nssm.exe" | Where-Object { $_.FullName -like "*win64*" } | Select-Object -First 1
            if ($nssmExe) {
                Copy-Item -Path $nssmExe.FullName -Destination $nssmPath -Force
                $nssmInstalled = $true
            }
            Remove-Item -Path $nssmZip, $nssmExtractDir -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            $nssmInstalled = $true
        }
    } catch {
        Write-Log "NSSM download failed, falling back to scheduled task approach: $($_.Exception.Message)" "WARN"
    }

    if ($nssmInstalled) {
        # Remove existing service if present
        & $nssmPath stop $SERVICE_NAME 2>$null
        & $nssmPath remove $SERVICE_NAME confirm 2>$null

        # Install service via NSSM
        & $nssmPath install $SERVICE_NAME "powershell.exe" "-ExecutionPolicy Bypass -NoProfile -File `"$serviceScriptPath`""
        & $nssmPath set $SERVICE_NAME DisplayName "OpenDirectory ClamAV Antivirus Agent"
        & $nssmPath set $SERVICE_NAME Description "Manages ClamAV antivirus scanning and reports to OpenDirectory MDM server"
        & $nssmPath set $SERVICE_NAME Start SERVICE_AUTO_START
        & $nssmPath set $SERVICE_NAME ObjectName LocalSystem
        & $nssmPath set $SERVICE_NAME AppStdout "$LOG_DIR\service-stdout.log"
        & $nssmPath set $SERVICE_NAME AppStderr "$LOG_DIR\service-stderr.log"
        & $nssmPath set $SERVICE_NAME AppRotateFiles 1
        & $nssmPath set $SERVICE_NAME AppRotateBytes 10485760
        & $nssmPath set $SERVICE_NAME AppRestartDelay 10000

        # Start the service
        & $nssmPath start $SERVICE_NAME
        Write-Log "OpenDirectory-ClamAV service installed and started via NSSM" "INFO"
    } else {
        # Fallback: create a scheduled task that runs at startup and stays running
        Write-Log "Installing service as scheduled task (NSSM unavailable)..." "INFO"

        $existingTask = Get-ScheduledTask -TaskName $SERVICE_NAME -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $SERVICE_NAME -Confirm:$false
        }

        $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$serviceScriptPath`""
        $taskTrigger = New-ScheduledTaskTrigger -AtStartup
        $taskSettings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 1) `
            -ExecutionTimeLimit (New-TimeSpan -Days 365)
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        Register-ScheduledTask -TaskName $SERVICE_NAME `
            -Action $taskAction `
            -Trigger $taskTrigger `
            -Settings $taskSettings `
            -Principal $taskPrincipal `
            -Description "OpenDirectory ClamAV Antivirus Agent - manages scanning and reporting" `
            -Force

        Start-ScheduledTask -TaskName $SERVICE_NAME
        Write-Log "OpenDirectory-ClamAV service installed and started as scheduled task" "INFO"
    }
}

function Uninstall-ClamAVService {
    Write-Log "Uninstalling OpenDirectory-ClamAV service..." "INFO"

    # Stop clamd
    Stop-Process -Name "clamd" -Force -ErrorAction SilentlyContinue

    # Remove NSSM service
    $nssmPath = "$OD_DATA_DIR\ClamAV\nssm.exe"
    if (Test-Path $nssmPath) {
        & $nssmPath stop $SERVICE_NAME 2>$null
        & $nssmPath remove $SERVICE_NAME confirm 2>$null
    }

    # Remove scheduled task
    $task = Get-ScheduledTask -TaskName $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName $SERVICE_NAME -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $SERVICE_NAME -Confirm:$false
    }

    Write-Log "OpenDirectory-ClamAV service removed" "INFO"
}

# ============================================================
# Windows Security Center Integration
# ============================================================

function Register-SecurityCenter {
    Write-Log "Registering with Windows Security Center..." "INFO"

    try {
        # Register ClamAV as an antivirus product in Windows Security Center
        # Uses WMI SecurityCenter2 namespace
        $wscNamespace = "root\SecurityCenter2"

        # Check if we can access Security Center
        $existingAV = Get-CimInstance -Namespace $wscNamespace -ClassName AntiVirusProduct -ErrorAction Stop

        # Create registry entries that Windows Security Center reads
        $wscRegPath = "HKLM:\SOFTWARE\Microsoft\Security Center\Provider\Av\OpenDirectory-ClamAV"
        if (!(Test-Path $wscRegPath)) {
            New-Item -Path $wscRegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $wscRegPath -Name "PRODUCT" -Value "OpenDirectory ClamAV"
        Set-ItemProperty -Path $wscRegPath -Name "PRODUCTEXE" -Value "$CLAMAV_INSTALL_DIR\clamd.exe"
        Set-ItemProperty -Path $wscRegPath -Name "STATE" -Value 1  # Enabled and up-to-date

        # Also register via the SecurityCenter2 provider path
        $providerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\SecurityCenter"
        if (Test-Path $providerPath) {
            Write-Log "Security Center namespace found, registration entries created" "INFO"
        }

        Write-Log "Windows Security Center registration complete" "INFO"
    } catch {
        Write-Log "Security Center registration warning: $($_.Exception.Message)" "WARN"
        Write-Log "ClamAV will still function but may not appear in Windows Security Center" "WARN"
    }
}

# ============================================================
# Status Functions
# ============================================================

function Get-ClamAVStatus {
    Write-Host ""
    Write-Host "OpenDirectory ClamAV Agent Status" -ForegroundColor Green
    Write-Host "==================================" -ForegroundColor Green
    Write-Host ""

    # ClamAV Installation
    $clamInstalled = Test-Path "$CLAMAV_INSTALL_DIR\clamscan.exe"
    Write-Host "ClamAV Installed:     $(if ($clamInstalled) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($clamInstalled) { "Green" } else { "Red" })

    if ($clamInstalled) {
        try {
            $version = & "$CLAMAV_INSTALL_DIR\clamscan.exe" --version 2>$null
            Write-Host "ClamAV Version:       $version" -ForegroundColor Cyan
        } catch { }
    }

    # Service status
    $nssmPath = "$OD_DATA_DIR\ClamAV\nssm.exe"
    if (Test-Path $nssmPath) {
        $svcStatus = & $nssmPath status $SERVICE_NAME 2>$null
        Write-Host "Service Status:       $svcStatus" -ForegroundColor $(if ($svcStatus -match "RUNNING") { "Green" } else { "Yellow" })
    } else {
        $task = Get-ScheduledTask -TaskName $SERVICE_NAME -ErrorAction SilentlyContinue
        if ($task) {
            Write-Host "Service Status:       $($task.State)" -ForegroundColor $(if ($task.State -eq "Running") { "Green" } else { "Yellow" })
        } else {
            Write-Host "Service Status:       Not installed" -ForegroundColor Red
        }
    }

    # clamd status
    $clamdRunning = $null -ne (Get-Process -Name "clamd" -ErrorAction SilentlyContinue)
    Write-Host "clamd (Real-time):    $(if ($clamdRunning) { 'Running' } else { 'Stopped' })" -ForegroundColor $(if ($clamdRunning) { "Green" } else { "Yellow" })

    # Registry values
    $regPath = "HKLM:\SOFTWARE\OpenDirectory\ClamAV"
    if (Test-Path $regPath) {
        $lastQuick = (Get-ItemProperty -Path $regPath -Name "LastQuickScan" -ErrorAction SilentlyContinue).LastQuickScan
        $lastFull = (Get-ItemProperty -Path $regPath -Name "LastFullScan" -ErrorAction SilentlyContinue).LastFullScan
        $lastSigUpdate = (Get-ItemProperty -Path $regPath -Name "LastSignatureUpdate" -ErrorAction SilentlyContinue).LastSignatureUpdate

        Write-Host "Last Quick Scan:      $(if ($lastQuick) { $lastQuick } else { 'Never' })" -ForegroundColor White
        Write-Host "Last Full Scan:       $(if ($lastFull) { $lastFull } else { 'Never' })" -ForegroundColor White
        Write-Host "Last Sig Update:      $(if ($lastSigUpdate) { $lastSigUpdate } else { 'Never' })" -ForegroundColor White
    }

    # Quarantine
    $quarantineCount = 0
    if (Test-Path $QUARANTINE_DIR) {
        $quarantineCount = (Get-ChildItem $QUARANTINE_DIR -File -ErrorAction SilentlyContinue | Measure-Object).Count
    }
    Write-Host "Quarantined Items:    $quarantineCount" -ForegroundColor $(if ($quarantineCount -gt 0) { "Yellow" } else { "Green" })

    # Configuration
    Write-Host ""
    Write-Host "Server URL:           $ServerUrl" -ForegroundColor Cyan
    Write-Host "Device ID:            $script:DeviceId" -ForegroundColor Cyan
    Write-Host "Scan Schedule:        $ScanSchedule" -ForegroundColor Cyan
    Write-Host "Config Dir:           $CONFIG_DIR" -ForegroundColor Cyan
    Write-Host "Log File:             $LOG_FILE" -ForegroundColor Cyan
    Write-Host "Quarantine Dir:       $QUARANTINE_DIR" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================
# Main Execution
# ============================================================

# Initialize
Initialize-Logging

# Auto-detect Device ID if not provided
if ([string]::IsNullOrEmpty($DeviceId)) {
    try {
        $DeviceId = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
    } catch {
        $DeviceId = (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID
    }
    if ([string]::IsNullOrEmpty($DeviceId)) {
        $DeviceId = [guid]::NewGuid().ToString()
        Write-Log "Generated fallback Device ID: $DeviceId" "WARN"
    }
}

# Verify running as admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log "This script must be run as Administrator" "ERROR"
    exit 1
}

Write-Log "OpenDirectory ClamAV Agent starting (Action: $Action)" "INFO"
Write-Log "Server: $ServerUrl | Device: $DeviceId | Schedule: $ScanSchedule" "INFO"

switch ($Action) {
    "Install" {
        Write-Host ""
        Write-Host "OpenDirectory ClamAV Antivirus Agent - Windows" -ForegroundColor Green
        Write-Host "===============================================" -ForegroundColor Green
        Write-Host ""

        Install-ClamAV
        Install-ClamAVService
        Register-SecurityCenter

        # Send initial heartbeat
        Send-Heartbeat

        # Register with server
        Invoke-ODApi -Endpoint "/register" -Body @{
            device_id  = $DeviceId
            platform   = "windows"
            hostname   = $env:COMPUTERNAME
            os_version = [System.Environment]::OSVersion.VersionString
            agent_version = "1.0.0"
            clamav_dir = $CLAMAV_INSTALL_DIR
            config_dir = $CONFIG_DIR
            scan_schedule = $ScanSchedule
        } | Out-Null

        Write-Host ""
        Write-Host "Installation complete!" -ForegroundColor Green
        Write-Host ""
        Get-ClamAVStatus
    }

    "Uninstall" {
        Write-Host "Uninstalling OpenDirectory ClamAV Agent..." -ForegroundColor Yellow
        Uninstall-ClamAVService

        Invoke-ODApi -Endpoint "/deregister" -Body @{
            device_id = $DeviceId
            platform  = "windows"
            timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        } | Out-Null

        Write-Host "Uninstall complete. ClamAV binaries remain at $CLAMAV_INSTALL_DIR" -ForegroundColor Yellow
        Write-Host "Quarantined files remain at $QUARANTINE_DIR" -ForegroundColor Yellow
    }

    "Update" {
        Write-Host "Updating ClamAV signatures..." -ForegroundColor Yellow
        Update-Signatures
    }

    "Scan" {
        Write-Host "Running on-demand quick scan..." -ForegroundColor Yellow
        $result = Invoke-ClamScan -ScanType "quick" -Paths $QUICK_SCAN_PATHS
        if ($result) {
            Write-Host ""
            Write-Host "Scan complete: $($result.FilesScanned) files scanned, $($result.ThreatsFound) threats found" -ForegroundColor $(if ($result.ThreatsFound -gt 0) { "Yellow" } else { "Green" })
        }
    }

    "Status" {
        Get-ClamAVStatus
    }
}

Write-Log "OpenDirectory ClamAV Agent action '$Action' completed" "INFO"
