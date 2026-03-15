#Requires -RunAsAdministrator
# ============================================================================
# OpenDirectory Windows Agent Service
# Persistent background agent with WebSocket connection and Toast notifications
# ============================================================================

param(
    [ValidateSet('Install', 'Uninstall', 'Run', 'Status')]
    [string]$Action = 'Run'
)

$ErrorActionPreference = "Continue"
$script:AgentVersion = "1.0.0"
$script:ODPath = "C:\Program Files\OpenDirectory"
$script:LogPath = "$script:ODPath\Logs\Agent"
$script:ConfigPath = "$script:ODPath\device-config.json"
$script:ServiceName = "OpenDirectoryAgent"
$script:TaskName = "OpenDirectory-Agent"
$script:PollingIntervalSec = 60
$script:HeartbeatIntervalSec = 30
$script:ReconnectDelaySec = 5
$script:MaxReconnectDelaySec = 300
$script:WebSocketConnected = $false

# ============================================================================
# LOGGING
# ============================================================================
function Write-AgentLog {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    if (!(Test-Path $script:LogPath)) {
        New-Item -Path $script:LogPath -ItemType Directory -Force | Out-Null
    }

    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $LogEntry = "$Timestamp [$Level] $Message"
    $LogFile = Join-Path $script:LogPath "agent-$(Get-Date -Format 'yyyyMMdd').log"

    $LogEntry | Out-File -Append -FilePath $LogFile -Encoding UTF8

    # Rotate logs older than 14 days
    Get-ChildItem -Path $script:LogPath -Filter "agent-*.log" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-14) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

# ============================================================================
# CONFIGURATION
# ============================================================================
function Get-AgentConfig {
    if (Test-Path $script:ConfigPath) {
        return Get-Content $script:ConfigPath -Raw | ConvertFrom-Json
    }
    Write-AgentLog "No device configuration found at $script:ConfigPath" "ERROR"
    return $null
}

function Get-DeviceId {
    $Config = Get-AgentConfig
    if ($Config -and $Config.device_id) {
        return $Config.device_id
    }
    return (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
}

function Get-ServerUrl {
    $Config = Get-AgentConfig
    if ($Config -and $Config.server_url) {
        return $Config.server_url
    }
    return "https://mdm.opendirectory.local"
}

# ============================================================================
# TOAST NOTIFICATIONS
# ============================================================================
function Show-ODNotification {
    param(
        [string]$Title,
        [string]$Body,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info',
        [string]$Attribution = 'OpenDirectory',
        [string]$ActionUrl = $null
    )

    try {
        # Load required assemblies for Toast notifications
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] | Out-Null

        # Choose icon based on type
        $IconHint = switch ($Type) {
            'Success' { 'ms-appx:///Assets/success.png' }
            'Warning' { 'ms-appx:///Assets/warning.png' }
            'Error'   { 'ms-appx:///Assets/error.png' }
            default   { 'ms-appx:///Assets/info.png' }
        }

        # Build toast XML
        $ActionBlock = ""
        if ($ActionUrl) {
            $ActionBlock = @"
        <actions>
            <action content="Details anzeigen" arguments="$ActionUrl" activationType="protocol"/>
            <action content="Schliessen" arguments="dismiss" activationType="system"/>
        </actions>
"@
        }

        $ToastXml = @"
<toast duration="long">
    <visual>
        <binding template="ToastGeneric">
            <text>$([System.Security.SecurityElement]::Escape($Title))</text>
            <text>$([System.Security.SecurityElement]::Escape($Body))</text>
            <text placement="attribution">$([System.Security.SecurityElement]::Escape($Attribution))</text>
        </binding>
    </visual>
    <audio src="ms-winsoundevent:Notification.Default"/>
    $ActionBlock
</toast>
"@

        $XmlDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $XmlDoc.LoadXml($ToastXml)

        $AppId = "OpenDirectory.Agent"

        # Register app ID in registry if not present
        $RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\$AppId"
        if (!(Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
            Set-ItemProperty -Path $RegPath -Name "ShowInActionCenter" -Value 1 -Type DWord
        }

        $Toast = [Windows.UI.Notifications.ToastNotification]::new($XmlDoc)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Show($Toast)

        Write-AgentLog "Notification shown: [$Type] $Title - $Body"
    } catch {
        Write-AgentLog "Failed to show notification: $($_.Exception.Message)" "WARN"

        # Fallback: BalloonTip via NotifyIcon
        try {
            Show-BalloonNotification -Title $Title -Body $Body -Type $Type
        } catch {
            Write-AgentLog "Fallback notification also failed: $($_.Exception.Message)" "WARN"
        }
    }
}

function Show-BalloonNotification {
    param(
        [string]$Title,
        [string]$Body,
        [string]$Type = 'Info'
    )

    Add-Type -AssemblyName System.Windows.Forms

    $BalloonIcon = switch ($Type) {
        'Error'   { [System.Windows.Forms.ToolTipIcon]::Error }
        'Warning' { [System.Windows.Forms.ToolTipIcon]::Warning }
        default   { [System.Windows.Forms.ToolTipIcon]::Info }
    }

    $Balloon = New-Object System.Windows.Forms.NotifyIcon
    $Balloon.Icon = [System.Drawing.SystemIcons]::Information
    $Balloon.BalloonTipIcon = $BalloonIcon
    $Balloon.BalloonTipTitle = $Title
    $Balloon.BalloonTipText = $Body
    $Balloon.Visible = $true
    $Balloon.ShowBalloonTip(10000)

    # Cleanup after display
    Start-Sleep -Seconds 12
    $Balloon.Dispose()
}

# ============================================================================
# SERVER COMMUNICATION (HTTP Polling)
# ============================================================================
function Invoke-ServerCheckin {
    param([string]$ServerUrl, [string]$DeviceId)

    try {
        $SystemInfo = @{
            device_id    = $DeviceId
            hostname     = $env:COMPUTERNAME
            agent_version = $script:AgentVersion
            os_version   = (Get-WmiObject -Class Win32_OperatingSystem).Version
            os_build     = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
            uptime_hours = [math]::Round((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.Subtract((Get-Date)).TotalHours * -1, 1)
            timestamp    = (Get-Date).ToString("o")
        }

        $Response = Invoke-RestMethod -Uri "$ServerUrl/api/v1/devices/$DeviceId/checkin" `
            -Method POST `
            -Body ($SystemInfo | ConvertTo-Json -Depth 3) `
            -ContentType "application/json" `
            -TimeoutSec 30 `
            -ErrorAction Stop

        return $Response
    } catch {
        Write-AgentLog "Server checkin failed: $($_.Exception.Message)" "WARN"
        return $null
    }
}

function Get-PendingCommands {
    param([string]$ServerUrl, [string]$DeviceId)

    try {
        $Response = Invoke-RestMethod -Uri "$ServerUrl/api/v1/devices/$DeviceId/commands/pending" `
            -Method GET `
            -ContentType "application/json" `
            -TimeoutSec 15 `
            -ErrorAction Stop

        return $Response
    } catch {
        Write-AgentLog "Failed to fetch pending commands: $($_.Exception.Message)" "DEBUG"
        return $null
    }
}

function Send-CommandResult {
    param(
        [string]$ServerUrl,
        [string]$DeviceId,
        [string]$CommandId,
        [string]$Status,
        [string]$Output
    )

    try {
        Invoke-RestMethod -Uri "$ServerUrl/api/v1/devices/$DeviceId/commands/$CommandId/result" `
            -Method POST `
            -Body (@{
                status = $Status
                output = $Output
                timestamp = (Get-Date).ToString("o")
            } | ConvertTo-Json) `
            -ContentType "application/json" `
            -TimeoutSec 15 `
            -ErrorAction SilentlyContinue
    } catch {
        Write-AgentLog "Failed to send command result: $($_.Exception.Message)" "WARN"
    }
}

# ============================================================================
# NOTIFICATION HANDLER - Process server-pushed notifications
# ============================================================================
function Invoke-NotificationHandler {
    param([PSObject]$Notification)

    $Category = $Notification.category
    $Title = $Notification.title
    $Body = $Notification.body
    $Type = $Notification.type  # Info, Success, Warning, Error

    switch ($Category) {
        "app_update" {
            $AppName = $Notification.data.app_name
            $OldVersion = $Notification.data.old_version
            $NewVersion = $Notification.data.new_version

            Show-ODNotification `
                -Title "App aktualisiert: $AppName" `
                -Body "$AppName wurde von $OldVersion auf $NewVersion aktualisiert." `
                -Type "Success" `
                -Attribution "OpenDirectory - App Updates"

            Write-AgentLog "App update notification: $AppName $OldVersion -> $NewVersion"
        }

        "app_installed" {
            $AppName = $Notification.data.app_name
            Show-ODNotification `
                -Title "App installiert: $AppName" `
                -Body "$AppName wurde erfolgreich auf diesem Geraet installiert." `
                -Type "Success" `
                -Attribution "OpenDirectory - Software Deployment"

            Write-AgentLog "App install notification: $AppName"
        }

        "app_update_failed" {
            $AppName = $Notification.data.app_name
            $ErrorMsg = $Notification.data.error
            Show-ODNotification `
                -Title "Update fehlgeschlagen: $AppName" `
                -Body "Das Update von $AppName ist fehlgeschlagen: $ErrorMsg" `
                -Type "Error" `
                -Attribution "OpenDirectory - App Updates"

            Write-AgentLog "App update failed notification: $AppName - $ErrorMsg" "WARN"
        }

        "compliance_violation" {
            $Rule = $Notification.data.rule
            $Details = $Notification.data.details
            Show-ODNotification `
                -Title "Compliance-Verstoss erkannt" `
                -Body "$Rule - $Details. Bitte kontaktieren Sie den IT-Support." `
                -Type "Warning" `
                -Attribution "OpenDirectory - Compliance"

            Write-AgentLog "Compliance violation notification: $Rule" "WARN"
        }

        "compliance_restored" {
            Show-ODNotification `
                -Title "Compliance wiederhergestellt" `
                -Body "Ihr Geraet erfuellt wieder alle Sicherheitsrichtlinien." `
                -Type "Success" `
                -Attribution "OpenDirectory - Compliance"

            Write-AgentLog "Compliance restored notification"
        }

        "policy_deployed" {
            $PolicyName = $Notification.data.policy_name
            Show-ODNotification `
                -Title "Neue Richtlinie angewendet" `
                -Body "Die Richtlinie '$PolicyName' wurde auf diesem Geraet angewendet." `
                -Type "Info" `
                -Attribution "OpenDirectory - Policies"

            Write-AgentLog "Policy deployed notification: $PolicyName"
        }

        "policy_changed" {
            $PolicyName = $Notification.data.policy_name
            $Changes = $Notification.data.changes
            Show-ODNotification `
                -Title "Richtlinie geaendert: $PolicyName" `
                -Body "Die Richtlinie '$PolicyName' wurde aktualisiert. $Changes" `
                -Type "Info" `
                -Attribution "OpenDirectory - Policies"

            Write-AgentLog "Policy changed notification: $PolicyName"
        }

        "device_action" {
            $ActionType = $Notification.data.action_type
            Show-ODNotification `
                -Title "Geraete-Aktion: $ActionType" `
                -Body "$($Notification.body)" `
                -Type "Warning" `
                -Attribution "OpenDirectory - Geraeteverwaltung"

            Write-AgentLog "Device action notification: $ActionType"
        }

        "winget_update_summary" {
            $Updated = $Notification.data.updated_count
            $Failed = $Notification.data.failed_count
            $Apps = $Notification.data.updated_apps -join ", "

            if ($Failed -gt 0) {
                Show-ODNotification `
                    -Title "App Updates abgeschlossen" `
                    -Body "$Updated Apps aktualisiert, $Failed fehlgeschlagen. Aktualisiert: $Apps" `
                    -Type "Warning" `
                    -Attribution "OpenDirectory - Winget Auto-Update"
            } else {
                Show-ODNotification `
                    -Title "App Updates abgeschlossen" `
                    -Body "$Updated Apps erfolgreich aktualisiert: $Apps" `
                    -Type "Success" `
                    -Attribution "OpenDirectory - Winget Auto-Update"
            }

            Write-AgentLog "Winget update summary: $Updated updated, $Failed failed"
        }

        "security_alert" {
            Show-ODNotification `
                -Title "Sicherheitswarnung" `
                -Body "$($Notification.body)" `
                -Type "Error" `
                -Attribution "OpenDirectory - Sicherheit"

            Write-AgentLog "Security alert: $($Notification.body)" "WARN"
        }

        default {
            # Generic notification
            if ($Title -and $Body) {
                Show-ODNotification -Title $Title -Body $Body -Type ($Type ?? "Info")
                Write-AgentLog "Generic notification: $Title"
            }
        }
    }
}

# ============================================================================
# COMMAND EXECUTION
# ============================================================================
function Invoke-AgentCommand {
    param(
        [PSObject]$Command,
        [string]$ServerUrl,
        [string]$DeviceId
    )

    $CommandId = $Command.id
    $CommandType = $Command.type

    Write-AgentLog "Executing command: $CommandType (ID: $CommandId)"

    try {
        switch ($CommandType) {
            "run_script" {
                $ScriptContent = $Command.data.script
                $Output = Invoke-Expression $ScriptContent 2>&1 | Out-String
                Send-CommandResult -ServerUrl $ServerUrl -DeviceId $DeviceId -CommandId $CommandId -Status "completed" -Output $Output

                # Notify user if configured
                if ($Command.data.notify_user) {
                    Show-ODNotification `
                        -Title "Script ausgefuehrt" `
                        -Body "Ein Verwaltungsscript wurde auf diesem Geraet ausgefuehrt." `
                        -Type "Info"
                }
            }

            "install_app" {
                $AppId = $Command.data.app_id
                $AppName = $Command.data.app_name ?? $AppId

                Show-ODNotification `
                    -Title "App wird installiert..." `
                    -Body "$AppName wird installiert. Bitte warten." `
                    -Type "Info" `
                    -Attribution "OpenDirectory - Software"

                $Output = & winget install --id $AppId --silent --accept-source-agreements --accept-package-agreements --source winget 2>&1 | Out-String

                if ($LASTEXITCODE -eq 0) {
                    Send-CommandResult -ServerUrl $ServerUrl -DeviceId $DeviceId -CommandId $CommandId -Status "completed" -Output $Output
                    Show-ODNotification `
                        -Title "App installiert: $AppName" `
                        -Body "$AppName wurde erfolgreich installiert." `
                        -Type "Success"
                } else {
                    Send-CommandResult -ServerUrl $ServerUrl -DeviceId $DeviceId -CommandId $CommandId -Status "failed" -Output $Output
                    Show-ODNotification `
                        -Title "Installation fehlgeschlagen" `
                        -Body "$AppName konnte nicht installiert werden." `
                        -Type "Error"
                }
            }

            "update_app" {
                $AppId = $Command.data.app_id
                $AppName = $Command.data.app_name ?? $AppId
                $Output = & winget upgrade --id $AppId --silent --accept-source-agreements --accept-package-agreements --source winget 2>&1 | Out-String

                if ($LASTEXITCODE -eq 0) {
                    Send-CommandResult -ServerUrl $ServerUrl -DeviceId $DeviceId -CommandId $CommandId -Status "completed" -Output $Output
                    Show-ODNotification `
                        -Title "App aktualisiert: $AppName" `
                        -Body "$AppName wurde aktualisiert." `
                        -Type "Success"
                } else {
                    Send-CommandResult -ServerUrl $ServerUrl -DeviceId $DeviceId -CommandId $CommandId -Status "failed" -Output $Output
                }
            }

            "sync_policies" {
                $Output = "Policy sync requested"
                Invoke-PolicySync -ServerUrl $ServerUrl -DeviceId $DeviceId
                Send-CommandResult -ServerUrl $ServerUrl -DeviceId $DeviceId -CommandId $CommandId -Status "completed" -Output $Output
                Show-ODNotification `
                    -Title "Richtlinien synchronisiert" `
                    -Body "Die Geraeterichtlinien wurden mit dem Server synchronisiert." `
                    -Type "Info"
            }

            "show_notification" {
                Invoke-NotificationHandler -Notification $Command.data
                Send-CommandResult -ServerUrl $ServerUrl -DeviceId $DeviceId -CommandId $CommandId -Status "completed" -Output "Notification shown"
            }

            "collect_inventory" {
                $Inventory = Get-DeviceInventory
                Send-CommandResult -ServerUrl $ServerUrl -DeviceId $DeviceId -CommandId $CommandId -Status "completed" -Output ($Inventory | ConvertTo-Json -Depth 3)
            }

            default {
                Write-AgentLog "Unknown command type: $CommandType" "WARN"
                Send-CommandResult -ServerUrl $ServerUrl -DeviceId $DeviceId -CommandId $CommandId -Status "failed" -Output "Unknown command type: $CommandType"
            }
        }
    } catch {
        Write-AgentLog "Command execution failed: $($_.Exception.Message)" "ERROR"
        Send-CommandResult -ServerUrl $ServerUrl -DeviceId $DeviceId -CommandId $CommandId -Status "failed" -Output $_.Exception.Message
    }
}

# ============================================================================
# POLICY SYNC
# ============================================================================
function Invoke-PolicySync {
    param([string]$ServerUrl, [string]$DeviceId)

    try {
        $Policies = Invoke-RestMethod -Uri "$ServerUrl/api/v1/devices/$DeviceId/policies" `
            -Method GET `
            -ContentType "application/json" `
            -TimeoutSec 30 `
            -ErrorAction Stop

        if ($Policies -and $Policies.policies) {
            foreach ($Policy in $Policies.policies) {
                if ($Policy.script) {
                    Write-AgentLog "Applying policy: $($Policy.name)"
                    try {
                        Invoke-Expression $Policy.script 2>&1 | Out-Null
                        Write-AgentLog "Policy applied successfully: $($Policy.name)"
                    } catch {
                        Write-AgentLog "Policy application failed: $($Policy.name) - $($_.Exception.Message)" "ERROR"
                    }
                }
            }
        }
    } catch {
        Write-AgentLog "Policy sync failed: $($_.Exception.Message)" "WARN"
    }
}

# ============================================================================
# DEVICE INVENTORY
# ============================================================================
function Get-DeviceInventory {
    $Inventory = @{
        device_id   = Get-DeviceId
        hostname    = $env:COMPUTERNAME
        timestamp   = (Get-Date).ToString("o")
        os          = @{
            name     = (Get-WmiObject Win32_OperatingSystem).Caption
            version  = (Get-WmiObject Win32_OperatingSystem).Version
            build    = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
            arch     = $env:PROCESSOR_ARCHITECTURE
        }
        hardware    = @{
            cpu         = (Get-WmiObject Win32_Processor | Select-Object -First 1).Name
            ram_gb      = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
            disk_free_gb = [math]::Round((Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB, 1)
        }
        network     = @{
            ip_addresses = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' }).IPAddress
            domain       = (Get-WmiObject Win32_ComputerSystem).Domain
            domain_joined = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
        }
        agent       = @{
            version   = $script:AgentVersion
            uptime    = [math]::Round(((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalHours, 1)
        }
        winget      = @{
            installed = [bool](Get-Command winget -ErrorAction SilentlyContinue)
            version   = if (Get-Command winget -ErrorAction SilentlyContinue) { (& winget --version 2>$null).Trim() } else { $null }
        }
    }

    return $Inventory
}

# ============================================================================
# MAIN AGENT LOOP
# ============================================================================
function Start-AgentLoop {
    $ServerUrl = Get-ServerUrl
    $DeviceId = Get-DeviceId

    Write-AgentLog "========================================="
    Write-AgentLog "OpenDirectory Agent v$script:AgentVersion starting"
    Write-AgentLog "Device ID: $DeviceId"
    Write-AgentLog "Server: $ServerUrl"
    Write-AgentLog "Polling interval: ${script:PollingIntervalSec}s"
    Write-AgentLog "========================================="

    # Initial checkin
    $CheckinResult = Invoke-ServerCheckin -ServerUrl $ServerUrl -DeviceId $DeviceId
    if ($CheckinResult) {
        Write-AgentLog "Initial server checkin successful"
    } else {
        Write-AgentLog "Initial server checkin failed - will retry" "WARN"
    }

    # Show startup notification
    Show-ODNotification `
        -Title "OpenDirectory Agent gestartet" `
        -Body "Der OpenDirectory Agent ist aktiv und verbunden." `
        -Type "Info" `
        -Attribution "OpenDirectory"

    $LastCheckin = Get-Date
    $LastHeartbeat = Get-Date
    $PollingCycle = 0

    # Main loop
    while ($true) {
        try {
            $Now = Get-Date
            $PollingCycle++

            # Heartbeat (every 30 seconds)
            if (($Now - $LastHeartbeat).TotalSeconds -ge $script:HeartbeatIntervalSec) {
                Invoke-ServerCheckin -ServerUrl $ServerUrl -DeviceId $DeviceId | Out-Null
                $LastHeartbeat = $Now
            }

            # Poll for pending commands (every polling interval)
            if (($Now - $LastCheckin).TotalSeconds -ge $script:PollingIntervalSec) {
                $PendingCommands = Get-PendingCommands -ServerUrl $ServerUrl -DeviceId $DeviceId

                if ($PendingCommands -and $PendingCommands.commands) {
                    foreach ($Command in $PendingCommands.commands) {
                        Invoke-AgentCommand -Command $Command -ServerUrl $ServerUrl -DeviceId $DeviceId
                    }
                }

                # Check for pending notifications
                if ($PendingCommands -and $PendingCommands.notifications) {
                    foreach ($Notification in $PendingCommands.notifications) {
                        Invoke-NotificationHandler -Notification $Notification
                    }
                }

                $LastCheckin = $Now
            }

            # Log status every 60 cycles (approx every hour)
            if ($PollingCycle % 60 -eq 0) {
                Write-AgentLog "Agent running - cycle $PollingCycle, server: $ServerUrl"
            }

        } catch {
            Write-AgentLog "Agent loop error: $($_.Exception.Message)" "ERROR"
        }

        Start-Sleep -Seconds 10
    }
}

# ============================================================================
# SERVICE INSTALLATION / MANAGEMENT
# ============================================================================
function Install-Agent {
    Write-Host "Installing OpenDirectory Agent..." -ForegroundColor Green

    # Ensure directories exist
    @($script:ODPath, $script:LogPath, "$script:ODPath\Scripts", "$script:ODPath\Config") | ForEach-Object {
        if (!(Test-Path $_)) { New-Item -Path $_ -ItemType Directory -Force | Out-Null }
    }

    # Copy agent script to install directory
    $AgentScript = "$script:ODPath\OpenDirectoryAgent.ps1"
    Copy-Item -Path $PSCommandPath -Destination $AgentScript -Force

    # Create scheduled task that runs at startup and keeps running
    $TaskName = $script:TaskName
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

    $Action = New-ScheduledTaskAction `
        -Execute "PowerShell.exe" `
        -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$AgentScript`" -Action Run"

    $TriggerStartup = New-ScheduledTaskTrigger -AtStartup
    $TriggerLogon = New-ScheduledTaskTrigger -AtLogOn

    $Settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero)

    $Principal = New-ScheduledTaskPrincipal -UserID "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $Action `
        -Trigger @($TriggerStartup, $TriggerLogon) `
        -Settings $Settings `
        -Principal $Principal `
        -Description "OpenDirectory Agent - Background service for device management, policy sync, and notifications" `
        -Force

    # Start the task immediately
    Start-ScheduledTask -TaskName $TaskName

    Write-Host "OpenDirectory Agent installed and started" -ForegroundColor Green
    Write-Host "Task Name: $TaskName" -ForegroundColor Cyan
    Write-Host "Agent Path: $AgentScript" -ForegroundColor Cyan
    Write-Host "Log Path: $script:LogPath" -ForegroundColor Cyan
}

function Uninstall-Agent {
    Write-Host "Uninstalling OpenDirectory Agent..." -ForegroundColor Yellow

    # Stop and remove scheduled task
    Stop-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction SilentlyContinue

    # Remove agent script (keep config and logs)
    $AgentScript = "$script:ODPath\OpenDirectoryAgent.ps1"
    if (Test-Path $AgentScript) {
        Remove-Item $AgentScript -Force
    }

    Write-Host "OpenDirectory Agent uninstalled" -ForegroundColor Green
    Write-Host "Note: Configuration and logs were preserved in $script:ODPath" -ForegroundColor Cyan
}

function Get-AgentStatus {
    $Task = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    $TaskInfo = Get-ScheduledTaskInfo -TaskName $script:TaskName -ErrorAction SilentlyContinue

    $Status = @{
        Installed    = [bool]$Task
        TaskState    = if ($Task) { $Task.State.ToString() } else { "Not installed" }
        LastRunTime  = if ($TaskInfo) { $TaskInfo.LastRunTime } else { $null }
        LastResult   = if ($TaskInfo) { $TaskInfo.LastTaskResult } else { $null }
        AgentVersion = $script:AgentVersion
        DeviceId     = Get-DeviceId
        ServerUrl    = Get-ServerUrl
        ConfigExists = Test-Path $script:ConfigPath
        LogPath      = $script:LogPath
    }

    Write-Host "`nOpenDirectory Agent Status" -ForegroundColor Green
    Write-Host "=========================" -ForegroundColor Green
    $Status.GetEnumerator() | Sort-Object Name | ForEach-Object {
        Write-Host "$($_.Key): $($_.Value)" -ForegroundColor Cyan
    }

    return $Status
}

# ============================================================================
# ENTRY POINT
# ============================================================================
switch ($Action) {
    'Install'   { Install-Agent }
    'Uninstall' { Uninstall-Agent }
    'Status'    { Get-AgentStatus }
    'Run'       { Start-AgentLoop }
}
