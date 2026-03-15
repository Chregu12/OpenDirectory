#Requires -RunAsAdministrator
# ============================================================================
# OpenDirectory Windows Agent
# Persistent WebSocket connection to server - receives commands & notifications
# Server pushes to agent (no polling)
# ============================================================================

param(
    [ValidateSet('Install', 'Uninstall', 'Run', 'Status')]
    [string]$Action = 'Run'
)

$ErrorActionPreference = "Continue"
$script:AgentVersion = "2.0.0"
$script:Platform = "windows"
$script:ODPath = "C:\Program Files\OpenDirectory"
$script:LogPath = "$script:ODPath\Logs\Agent"
$script:ConfigPath = "$script:ODPath\device-config.json"
$script:TaskName = "OpenDirectory-Agent"
$script:HeartbeatIntervalSec = 30
$script:ReconnectDelaySec = 5
$script:MaxReconnectDelaySec = 300

# ============================================================================
# LOGGING
# ============================================================================
function Write-AgentLog {
    param([string]$Message, [string]$Level = 'INFO')
    if (!(Test-Path $script:LogPath)) { New-Item -Path $script:LogPath -ItemType Directory -Force | Out-Null }
    $LogFile = Join-Path $script:LogPath "agent-$(Get-Date -Format 'yyyyMMdd').log"
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') [$Level] $Message" | Out-File -Append -FilePath $LogFile -Encoding UTF8
    Get-ChildItem -Path $script:LogPath -Filter "agent-*.log" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-14) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

# ============================================================================
# CONFIGURATION
# ============================================================================
function Get-AgentConfig {
    if (Test-Path $script:ConfigPath) { return Get-Content $script:ConfigPath -Raw | ConvertFrom-Json }
    return $null
}

function Get-DeviceId {
    $c = Get-AgentConfig; if ($c -and $c.device_id) { return $c.device_id }
    return (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
}

function Get-ServerUrl {
    $c = Get-AgentConfig; if ($c -and $c.server_url) { return $c.server_url }
    return "https://mdm.opendirectory.local"
}

function Get-WebSocketUrl {
    $url = Get-ServerUrl
    $wsUrl = $url -replace '^https://', 'wss://' -replace '^http://', 'ws://'
    return "$wsUrl/ws/devices"
}

# ============================================================================
# TOAST NOTIFICATIONS (Windows-specific)
# ============================================================================
function Show-ODNotification {
    param(
        [string]$Title, [string]$Body,
        [string]$Type = 'Info', [string]$Attribution = 'OpenDirectory'
    )
    try {
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] | Out-Null
        $ToastXml = @"
<toast duration="long">
    <visual><binding template="ToastGeneric">
        <text>$([System.Security.SecurityElement]::Escape($Title))</text>
        <text>$([System.Security.SecurityElement]::Escape($Body))</text>
        <text placement="attribution">$([System.Security.SecurityElement]::Escape($Attribution))</text>
    </binding></visual>
    <audio src="ms-winsoundevent:Notification.Default"/>
</toast>
"@
        $XmlDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $XmlDoc.LoadXml($ToastXml)
        $AppId = "OpenDirectory.Agent"
        $RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\$AppId"
        if (!(Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
            Set-ItemProperty -Path $RegPath -Name "ShowInActionCenter" -Value 1 -Type DWord
        }
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Show(
            [Windows.UI.Notifications.ToastNotification]::new($XmlDoc))
        Write-AgentLog "Notification: [$Type] $Title"
    } catch {
        Write-AgentLog "Notification failed: $($_.Exception.Message)" "WARN"
        try {
            Add-Type -AssemblyName System.Windows.Forms
            $b = New-Object System.Windows.Forms.NotifyIcon
            $b.Icon = [System.Drawing.SystemIcons]::Information
            $b.BalloonTipTitle = $Title; $b.BalloonTipText = $Body; $b.Visible = $true
            $b.ShowBalloonTip(10000); Start-Sleep -Seconds 12; $b.Dispose()
        } catch { Write-AgentLog "Fallback notification failed: $($_.Exception.Message)" "WARN" }
    }
}

# ============================================================================
# NOTIFICATION HANDLER (generic - same message format across all platforms)
# ============================================================================
function Invoke-NotificationHandler {
    param([PSObject]$Message)
    $d = $Message.data
    $cat = $Message.category

    $map = @{
        "app_update"           = @{ Title = "App aktualisiert: $($d.app_name)"; Body = "$($d.app_name) $($d.old_version) -> $($d.new_version)"; Type = "Success"; Attr = "App Updates" }
        "app_installed"        = @{ Title = "App installiert: $($d.app_name)"; Body = "$($d.app_name) wurde installiert."; Type = "Success"; Attr = "Software" }
        "app_update_failed"    = @{ Title = "Update fehlgeschlagen: $($d.app_name)"; Body = "$($d.error)"; Type = "Error"; Attr = "App Updates" }
        "compliance_violation" = @{ Title = "Compliance-Verstoss"; Body = "$($d.rule) - $($d.details)"; Type = "Warning"; Attr = "Compliance" }
        "compliance_restored"  = @{ Title = "Compliance OK"; Body = "Alle Richtlinien erfuellt."; Type = "Success"; Attr = "Compliance" }
        "policy_deployed"      = @{ Title = "Richtlinie angewendet"; Body = "$($d.policy_name)"; Type = "Info"; Attr = "Policies" }
        "policy_changed"       = @{ Title = "Richtlinie geaendert"; Body = "$($d.policy_name): $($d.changes)"; Type = "Info"; Attr = "Policies" }
        "security_alert"       = @{ Title = "Sicherheitswarnung"; Body = "$($Message.body)"; Type = "Error"; Attr = "Sicherheit" }
        "winget_update_summary"= @{ Title = "App Updates"; Body = "$($d.updated_count) aktualisiert, $($d.failed_count) fehlgeschlagen"; Type = if ($d.failed_count -gt 0) { "Warning" } else { "Success" }; Attr = "Auto-Update" }
        "device_action"        = @{ Title = "Geraete-Aktion: $($d.action_type)"; Body = "$($Message.body)"; Type = "Warning"; Attr = "Verwaltung" }
    }

    $entry = $map[$cat]
    if ($entry) {
        Show-ODNotification -Title $entry.Title -Body $entry.Body -Type $entry.Type -Attribution "OpenDirectory - $($entry.Attr)"
    } elseif ($Message.title -and $Message.body) {
        Show-ODNotification -Title $Message.title -Body $Message.body -Type ($Message.notification_type ?? "Info")
    }
    Write-AgentLog "Notification handled: $cat"
}

# ============================================================================
# COMMAND EXECUTION (generic - commands come via WebSocket push)
# ============================================================================
function Invoke-AgentCommand {
    param([PSObject]$Command, [System.Net.WebSockets.ClientWebSocket]$WS)

    $CommandId = $Command.id
    $CommandType = $Command.command_type ?? $Command.type
    Write-AgentLog "Executing command: $CommandType (ID: $CommandId)"

    $Result = @{ commandId = $CommandId; status = "completed"; output = "" }

    try {
        switch ($CommandType) {
            "run_script" {
                $Result.output = Invoke-Expression $Command.data.script 2>&1 | Out-String
                if ($Command.data.notify_user) {
                    Show-ODNotification -Title "Script ausgefuehrt" -Body "Verwaltungsscript wurde ausgefuehrt." -Type "Info"
                }
            }
            "install_app" {
                $AppId = $Command.data.app_id; $AppName = $Command.data.app_name ?? $AppId
                Show-ODNotification -Title "Installiere $AppName..." -Body "Bitte warten." -Type "Info" -Attribution "OpenDirectory"
                $Result.output = & winget install --id $AppId --silent --accept-source-agreements --accept-package-agreements --source winget 2>&1 | Out-String
                if ($LASTEXITCODE -eq 0) {
                    Show-ODNotification -Title "Installiert: $AppName" -Body "Erfolgreich installiert." -Type "Success"
                } else {
                    $Result.status = "failed"
                    Show-ODNotification -Title "Fehlgeschlagen: $AppName" -Body "Installation fehlgeschlagen." -Type "Error"
                }
            }
            "update_app" {
                $AppId = $Command.data.app_id; $AppName = $Command.data.app_name ?? $AppId
                $Result.output = & winget upgrade --id $AppId --silent --accept-source-agreements --accept-package-agreements --source winget 2>&1 | Out-String
                if ($LASTEXITCODE -eq 0) {
                    Show-ODNotification -Title "Aktualisiert: $AppName" -Body "$AppName wurde aktualisiert." -Type "Success"
                } else { $Result.status = "failed" }
            }
            "sync_policies" {
                $ServerUrl = Get-ServerUrl; $DeviceId = Get-DeviceId
                try {
                    $Policies = Invoke-RestMethod -Uri "$ServerUrl/api/v1/devices/$DeviceId/policies" -Method GET -ContentType "application/json" -TimeoutSec 30
                    if ($Policies.policies) {
                        foreach ($p in $Policies.policies) { if ($p.script) { Invoke-Expression $p.script 2>&1 | Out-Null } }
                    }
                    $Result.output = "Policies synced: $($Policies.policies.Count)"
                } catch { $Result.status = "failed"; $Result.output = $_.Exception.Message }
                Show-ODNotification -Title "Richtlinien synchronisiert" -Body "Policies wurden angewendet." -Type "Info"
            }
            "show_notification" {
                Invoke-NotificationHandler -Message $Command.data
                $Result.output = "Notification shown"
            }
            "collect_inventory" {
                $Result.output = (Get-DeviceInventory | ConvertTo-Json -Depth 3)
            }
            default {
                $Result.status = "failed"; $Result.output = "Unknown command: $CommandType"
            }
        }
    } catch {
        $Result.status = "failed"; $Result.output = $_.Exception.Message
        Write-AgentLog "Command failed: $($_.Exception.Message)" "ERROR"
    }

    # Send result back via WebSocket
    Send-WSMessage -WS $WS -Message @{ type = "command_result"; data = $Result }
}

# ============================================================================
# DEVICE INVENTORY
# ============================================================================
function Get-DeviceInventory {
    return @{
        device_id = Get-DeviceId; hostname = $env:COMPUTERNAME; platform = "windows"
        timestamp = (Get-Date).ToString("o")
        os = @{
            name = (Get-WmiObject Win32_OperatingSystem).Caption
            version = (Get-WmiObject Win32_OperatingSystem).Version
            build = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
            arch = $env:PROCESSOR_ARCHITECTURE
        }
        hardware = @{
            cpu = (Get-WmiObject Win32_Processor | Select-Object -First 1).Name
            ram_gb = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
            disk_free_gb = [math]::Round((Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB, 1)
        }
        network = @{
            ip_addresses = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' }).IPAddress
            domain = (Get-WmiObject Win32_ComputerSystem).Domain
            domain_joined = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
        }
        winget = @{
            installed = [bool](Get-Command winget -ErrorAction SilentlyContinue)
            version = if (Get-Command winget -ErrorAction SilentlyContinue) { (& winget --version 2>$null).Trim() } else { $null }
        }
    }
}

# ============================================================================
# WEBSOCKET CLIENT - Server pushes messages to us
# ============================================================================
function Send-WSMessage {
    param([System.Net.WebSockets.ClientWebSocket]$WS, [hashtable]$Message)
    try {
        $json = ($Message | ConvertTo-Json -Depth 5 -Compress)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $segment = New-Object System.ArraySegment[byte] -ArgumentList @(,$bytes)
        $WS.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [System.Threading.CancellationToken]::None).Wait()
    } catch {
        Write-AgentLog "WebSocket send failed: $($_.Exception.Message)" "WARN"
    }
}

function Receive-WSMessage {
    param([System.Net.WebSockets.ClientWebSocket]$WS)
    $buffer = New-Object byte[] 65536
    $segment = New-Object System.ArraySegment[byte] -ArgumentList @(,$buffer)
    $result = $WS.ReceiveAsync($segment, [System.Threading.CancellationToken]::None).Result

    if ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
        return $null
    }

    $json = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $result.Count)
    return $json | ConvertFrom-Json
}

function Connect-WebSocket {
    param([string]$Url, [string]$DeviceId)

    $WS = New-Object System.Net.WebSockets.ClientWebSocket
    $WS.Options.SetRequestHeader("X-Device-Id", $DeviceId)
    $WS.Options.SetRequestHeader("X-Device-Platform", $script:Platform)
    $WS.Options.SetRequestHeader("X-Agent-Version", $script:AgentVersion)
    $WS.Options.KeepAliveInterval = [TimeSpan]::FromSeconds(30)

    $uri = New-Object System.Uri($Url)
    $WS.ConnectAsync($uri, [System.Threading.CancellationToken]::None).Wait()

    # Register agent
    Send-WSMessage -WS $WS -Message @{
        type = "agent_register"
        data = @{
            deviceId = $DeviceId
            platform = $script:Platform
            agentVersion = $script:AgentVersion
            hostname = $env:COMPUTERNAME
        }
    }

    return $WS
}

# ============================================================================
# MAIN AGENT LOOP (WebSocket-based, server pushes to us)
# ============================================================================
function Start-AgentLoop {
    $ServerUrl = Get-ServerUrl
    $WsUrl = Get-WebSocketUrl
    $DeviceId = Get-DeviceId
    $ReconnectDelay = $script:ReconnectDelaySec

    Write-AgentLog "========================================="
    Write-AgentLog "OpenDirectory Agent v$script:AgentVersion (WebSocket)"
    Write-AgentLog "Device ID: $DeviceId"
    Write-AgentLog "Server: $ServerUrl"
    Write-AgentLog "WebSocket: $WsUrl"
    Write-AgentLog "Platform: $script:Platform"
    Write-AgentLog "========================================="

    Show-ODNotification -Title "OpenDirectory Agent" -Body "Agent gestartet, verbinde mit Server..." -Type "Info"

    # Reconnect loop - agent stays connected, server pushes messages
    while ($true) {
        $WS = $null
        try {
            Write-AgentLog "Connecting to WebSocket: $WsUrl"
            $WS = Connect-WebSocket -Url $WsUrl -DeviceId $DeviceId

            Write-AgentLog "WebSocket connected"
            Show-ODNotification -Title "OpenDirectory Agent" -Body "Verbunden mit Server." -Type "Success"
            $ReconnectDelay = $script:ReconnectDelaySec  # Reset on successful connect

            $LastHeartbeat = Get-Date

            # Message receive loop - server pushes, we react
            while ($WS.State -eq [System.Net.WebSockets.WebSocketState]::Open) {

                # Send heartbeat periodically
                if (((Get-Date) - $LastHeartbeat).TotalSeconds -ge $script:HeartbeatIntervalSec) {
                    Send-WSMessage -WS $WS -Message @{
                        type = "device_heartbeat"
                        data = @{ deviceId = $DeviceId; timestamp = (Get-Date).ToString("o") }
                    }
                    $LastHeartbeat = Get-Date
                }

                # Check if data available (non-blocking with timeout)
                # Use a short timeout so heartbeats can still fire
                try {
                    $buffer = New-Object byte[] 65536
                    $segment = New-Object System.ArraySegment[byte] -ArgumentList @(,$buffer)
                    $cts = New-Object System.Threading.CancellationTokenSource(5000) # 5s timeout
                    $task = $WS.ReceiveAsync($segment, $cts.Token)

                    try {
                        $task.Wait()
                        $result = $task.Result

                        if ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
                            Write-AgentLog "Server closed connection" "WARN"
                            break
                        }

                        $json = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $result.Count)
                        $msg = $json | ConvertFrom-Json

                        # Handle server-pushed message
                        switch ($msg.type) {
                            "notification" {
                                Write-AgentLog "Received notification: $($msg.category)"
                                Invoke-NotificationHandler -Message $msg
                            }
                            "command" {
                                Write-AgentLog "Received command: $($msg.command_type ?? $msg.type)"
                                Invoke-AgentCommand -Command $msg -WS $WS
                            }
                            "heartbeat_ack" {
                                # Server acknowledged heartbeat
                            }
                            "agent_registered" {
                                Write-AgentLog "Agent registration confirmed by server"
                            }
                            "connection" {
                                Write-AgentLog "Connection confirmed: $($msg.connectionId)"
                            }
                            "policy_sync" {
                                Write-AgentLog "Server requests policy sync"
                                Invoke-AgentCommand -Command @{ id = "policy-sync-$(Get-Date -Format 'yyyyMMddHHmmss')"; type = "sync_policies"; data = @{} } -WS $WS
                            }
                            default {
                                Write-AgentLog "Unknown message type: $($msg.type)" "DEBUG"
                            }
                        }
                    } catch [System.AggregateException] {
                        # Timeout - no message received, loop continues (heartbeat check)
                        if ($_.Exception.InnerException -is [System.OperationCanceledException]) {
                            # Normal timeout, continue loop
                        } else {
                            throw $_.Exception.InnerException
                        }
                    } finally {
                        $cts.Dispose()
                    }
                } catch [System.OperationCanceledException] {
                    # Timeout, continue
                } catch {
                    Write-AgentLog "Receive error: $($_.Exception.Message)" "ERROR"
                    break
                }
            }

        } catch {
            Write-AgentLog "WebSocket error: $($_.Exception.Message)" "ERROR"
        } finally {
            if ($WS -and $WS.State -ne [System.Net.WebSockets.WebSocketState]::Closed) {
                try { $WS.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "Reconnecting", [System.Threading.CancellationToken]::None).Wait() } catch {}
                $WS.Dispose()
            }
        }

        # Exponential backoff reconnect
        Write-AgentLog "Reconnecting in ${ReconnectDelay}s..."
        Start-Sleep -Seconds $ReconnectDelay
        $ReconnectDelay = [math]::Min($ReconnectDelay * 2, $script:MaxReconnectDelaySec)
    }
}

# ============================================================================
# SERVICE INSTALLATION / MANAGEMENT
# ============================================================================
function Install-Agent {
    Write-Host "Installing OpenDirectory Agent v$script:AgentVersion..." -ForegroundColor Green
    @($script:ODPath, $script:LogPath, "$script:ODPath\Scripts", "$script:ODPath\Config") | ForEach-Object {
        if (!(Test-Path $_)) { New-Item -Path $_ -ItemType Directory -Force | Out-Null }
    }
    $AgentScript = "$script:ODPath\OpenDirectoryAgent.ps1"
    Copy-Item -Path $PSCommandPath -Destination $AgentScript -Force

    Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$AgentScript`" -Action Run"
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
    $Principal = New-ScheduledTaskPrincipal -UserID "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $script:TaskName -Action $Action -Trigger @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -AtLogOn)) -Settings $Settings -Principal $Principal -Description "OpenDirectory Agent - WebSocket-based device management" -Force
    Start-ScheduledTask -TaskName $script:TaskName

    Write-Host "Agent installed and started (WebSocket mode)" -ForegroundColor Green
    Write-Host "Task: $($script:TaskName) | Logs: $script:LogPath" -ForegroundColor Cyan
}

function Uninstall-Agent {
    Stop-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
    $s = "$script:ODPath\OpenDirectoryAgent.ps1"; if (Test-Path $s) { Remove-Item $s -Force }
    Write-Host "Agent uninstalled (config/logs preserved)" -ForegroundColor Green
}

function Get-AgentStatus {
    $Task = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    $Info = Get-ScheduledTaskInfo -TaskName $script:TaskName -ErrorAction SilentlyContinue
    @{
        Version = $script:AgentVersion; Mode = "WebSocket (server-push)"
        Platform = $script:Platform; DeviceId = Get-DeviceId; Server = Get-ServerUrl
        Installed = [bool]$Task; State = if ($Task) { $Task.State.ToString() } else { "Not installed" }
        LastRun = if ($Info) { $Info.LastRunTime } else { $null }
    } | Format-Table -AutoSize
}

# ============================================================================
switch ($Action) {
    'Install'   { Install-Agent }
    'Uninstall' { Uninstall-Agent }
    'Status'    { Get-AgentStatus }
    'Run'       { Start-AgentLoop }
}
