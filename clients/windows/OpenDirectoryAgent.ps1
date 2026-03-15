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

            # ── Printer Commands (platform-specific: Windows) ──────────────
            "deploy_printers" {
                $Result.output = (Invoke-DeployPrinters -Data $Command.data | ConvertTo-Json -Depth 3)
            }
            "remove_printer" {
                $Result.output = (Invoke-RemovePrinter -PrinterName $Command.data.printerName | Out-String)
            }
            "set_default_printer" {
                $Result.output = (Invoke-SetDefaultPrinter -PrinterName $Command.data.printerName | Out-String)
            }
            "list_printers" {
                $Result.output = (Get-InstalledPrinters | ConvertTo-Json -Depth 3)
            }
            "get_printer_status" {
                $Result.output = (Get-PrinterStatusDetail -PrinterName $Command.data.printerName | ConvertTo-Json -Depth 3)
            }
            "update_printer_settings" {
                $Result.output = (Invoke-UpdatePrinterSettings -PrinterName $Command.data.printerName -Settings $Command.data.settings | Out-String)
            }
            "apply_printer_policy" {
                $Result.output = (Invoke-ApplyPrinterPolicy -Data $Command.data | ConvertTo-Json -Depth 3)
            }
            "set_printer_paused" {
                if ($Command.data.paused) {
                    $Result.output = (Set-Printer -Name $Command.data.printerName -PrinterStatus Paused 2>&1 | Out-String)
                } else {
                    $Result.output = (Set-Printer -Name $Command.data.printerName -PrinterStatus Normal 2>&1 | Out-String)
                }
            }
            "cancel_print_job" {
                $Result.output = (Remove-PrintJob -PrinterName $Command.data.printerName -ID $Command.data.jobId 2>&1 | Out-String)
            }
            "clear_print_queue" {
                $Result.output = (Get-PrintJob -PrinterName $Command.data.printerName | Remove-PrintJob 2>&1 | Out-String)
            }
            "test_print" {
                $Result.output = (Invoke-TestPrint -PrinterName $Command.data.printerName | Out-String)
            }

            # ── Policy Commands (platform-specific: Windows) ──────────────
            "apply_policy" {
                $Result.output = (Invoke-ApplyPolicy -Data $Command.data | ConvertTo-Json -Depth 5)
            }
            "remove_policy" {
                $Result.output = (Invoke-RemovePolicy -Data $Command.data | Out-String)
            }
            "check_compliance" {
                $report = Invoke-CheckCompliance -Data $Command.data
                $Result.output = ($report | ConvertTo-Json -Depth 5)
                $Result.complianceReport = $report
            }
            "check_all_compliance" {
                $report = Invoke-CheckAllCompliance -Data $Command.data
                $Result.output = ($report | ConvertTo-Json -Depth 5)
                $Result.complianceReport = $report
            }
            "detect_drift" {
                $report = Invoke-DetectDrift -Data $Command.data
                $Result.output = ($report | ConvertTo-Json -Depth 5)
                $Result.driftReport = $report
            }
            "rollback_policy" {
                $Result.output = (Invoke-RollbackPolicy -Data $Command.data | Out-String)
            }
            "resync_policies" {
                foreach ($pol in $Command.data.policies) {
                    Invoke-ApplyPolicy -Data $pol | Out-Null
                }
                $Result.output = "Resynced $($Command.data.policies.Count) policies"
            }
            "apply_policy_module" {
                $Result.output = (Invoke-ApplyPolicyModule -Module $Command.data.module -Settings $Command.data.settings | Out-String)
            }

            # ── Update Management Commands ──────────────────────────────────
            "configure_updates" {
                $output = Invoke-ConfigureUpdates -Json $json
            }
            "check_update_status" {
                $output = Invoke-CheckUpdateStatus
            }
            "trigger_update" {
                $output = Invoke-TriggerUpdate -Json $json
            }
            "get_update_compliance" {
                $output = Invoke-GetUpdateCompliance
            }
            "configure_winget" {
                $output = Invoke-ConfigureWinget -Json $json
            }
            "check_winget_status" {
                $output = Invoke-CheckWingetStatus
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
# POLICY ENFORCEMENT (Windows-specific: Registry, GPO, secedit, BitLocker)
# ============================================================================
$script:PolicyBackupPath = "$script:ODPath\PolicyBackups"

function Invoke-ApplyPolicy {
    param([PSObject]$Data)
    $policyId = $Data.policyId; $policyName = $Data.policyName
    $settings = $Data.settings; $mode = $Data.enforceMode ?? "enforce"
    Write-AgentLog "Applying policy: $policyName ($policyId) mode=$mode"

    # Backup current state before applying
    Invoke-BackupPolicyState -PolicyId $policyId

    $applied = @()
    $errors = @()

    # Security → Password
    if ($settings.security?.password) {
        try {
            $p = $settings.security.password
            $cmds = @()
            if ($null -ne $p.minLength)         { $cmds += "net accounts /minpwlen:$($p.minLength)" }
            if ($null -ne $p.maxAgeDays)         { $cmds += "net accounts /maxpwage:$($p.maxAgeDays)" }
            if ($null -ne $p.historyLength)      { $cmds += "net accounts /uniquepw:$($p.historyLength)" }
            if ($null -ne $p.lockoutThreshold)   { $cmds += "net accounts /lockoutthreshold:$($p.lockoutThreshold)" }
            if ($null -ne $p.lockoutDuration)    { $cmds += "net accounts /lockoutduration:$($p.lockoutDuration)" }
            foreach ($cmd in $cmds) { Invoke-Expression $cmd 2>&1 | Out-Null }
            $applied += "password"
        } catch { $errors += "password: $($_.Exception.Message)" }
    }

    # Security → Screen Lock
    if ($settings.security?.screenLock?.enabled) {
        try {
            $sl = $settings.security.screenLock
            if ($null -ne $sl.timeoutMinutes) {
                Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value ($sl.timeoutMinutes * 60) -ErrorAction Stop
                Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value "1" -ErrorAction Stop
            }
            if ($sl.requirePassword) {
                Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value "1" -ErrorAction Stop
            }
            $applied += "screenLock"
        } catch { $errors += "screenLock: $($_.Exception.Message)" }
    }

    # Security → Firewall
    if ($settings.security?.firewall) {
        try {
            $fw = $settings.security.firewall
            if ($fw.enabled) {
                Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop
            } else {
                Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False -ErrorAction Stop
            }
            if ($fw.defaultDeny) {
                Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -ErrorAction Stop
            }
            $applied += "firewall"
        } catch { $errors += "firewall: $($_.Exception.Message)" }
    }

    # Security → Encryption (BitLocker)
    if ($settings.security?.encryption?.required) {
        try {
            $blStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
            if ($blStatus -and $blStatus.ProtectionStatus -ne "On") {
                Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
            }
            $applied += "encryption"
        } catch { $errors += "encryption: $($_.Exception.Message)" }
    }

    # Security → Audit
    if ($settings.security?.audit?.enabled) {
        try {
            auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>&1 | Out-Null
            auditpol /set /subcategory:"Logoff" /success:enable 2>&1 | Out-Null
            auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable 2>&1 | Out-Null
            auditpol /set /subcategory:"File System" /success:enable /failure:enable 2>&1 | Out-Null
            $applied += "audit"
        } catch { $errors += "audit: $($_.Exception.Message)" }
    }

    # Browser → Edge
    if ($settings.browser?.homepage) {
        try {
            $edgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            if (!(Test-Path $edgePath)) { New-Item -Path $edgePath -Force | Out-Null }
            Set-ItemProperty -Path $edgePath -Name "HomepageLocation" -Value $settings.browser.homepage -ErrorAction Stop
            Set-ItemProperty -Path $edgePath -Name "HomepageIsNewTabPage" -Value 0 -Type DWord -ErrorAction Stop
            $applied += "browser"
        } catch { $errors += "browser: $($_.Exception.Message)" }
    }

    # Software → Updates
    if ($null -ne $settings.software?.updates?.automatic) {
        try {
            $auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            if (!(Test-Path $auPath)) { New-Item -Path $auPath -Force | Out-Null }
            Set-ItemProperty -Path $auPath -Name "AUOptions" -Value $(if ($settings.software.updates.automatic) { 4 } else { 1 }) -Type DWord
            $applied += "updates"
        } catch { $errors += "updates: $($_.Exception.Message)" }
    }

    # Save applied state
    $stateFile = "$script:ODPath\Config\policy-$policyId.json"
    @{ policyId = $policyId; policyName = $policyName; version = $Data.version; applied = $applied; appliedAt = (Get-Date).ToString("o"); settings = $settings } | ConvertTo-Json -Depth 5 | Out-File -FilePath $stateFile -Encoding UTF8

    if ($Data.notifyUser) {
        Show-ODNotification -Title "Richtlinie angewendet" -Body "$policyName ($($applied.Count) Module)" -Type "Info" -Attribution "OpenDirectory - Policies"
    }
    Write-AgentLog "Policy applied: $policyName (modules: $($applied -join ', '))"
    return @{ policyId = $policyId; applied = $applied; errors = $errors; status = if ($errors.Count -eq 0) { "success" } else { "partial" } }
}

function Invoke-RemovePolicy {
    param([PSObject]$Data)
    $policyId = $Data.policyId
    $stateFile = "$script:ODPath\Config\policy-$policyId.json"
    if (Test-Path $stateFile) {
        Remove-Item $stateFile -Force
        Write-AgentLog "Policy removed: $policyId"
        # Attempt rollback to backup
        Invoke-RollbackPolicy -Data $Data | Out-Null
        return "Policy removed and rolled back: $policyId"
    }
    return "Policy not found: $policyId"
}

function Invoke-CheckCompliance {
    param([PSObject]$Data)
    $violations = @()
    $settings = $Data.expectedSettings

    # Check password policy
    if ($settings.security?.password) {
        $p = $settings.security.password
        $netAccounts = net accounts 2>$null
        if ($null -ne $p.minLength) {
            $current = ($netAccounts | Select-String "Minimum password length" | ForEach-Object { ($_ -split ":\s*")[1].Trim() })
            if ([int]$current -lt $p.minLength) { $violations += @{ module = "password"; setting = "minLength"; expected = $p.minLength; actual = $current } }
        }
    }

    # Check firewall
    if ($settings.security?.firewall?.enabled) {
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        foreach ($profile in $profiles) {
            if (-not $profile.Enabled) {
                $violations += @{ module = "firewall"; setting = "enabled"; expected = $true; actual = $false; detail = "$($profile.Name) disabled" }
            }
        }
    }

    # Check BitLocker
    if ($settings.security?.encryption?.required) {
        $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if (-not $bl -or $bl.ProtectionStatus -ne "On") {
            $violations += @{ module = "encryption"; setting = "BitLocker"; expected = "On"; actual = $(if ($bl) { $bl.ProtectionStatus } else { "NotAvailable" }) }
        }
    }

    # Check screen lock
    if ($settings.security?.screenLock?.enabled) {
        $timeout = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
        if (-not $timeout -or $timeout.ScreenSaveTimeOut -eq "0") {
            $violations += @{ module = "screenLock"; setting = "timeout"; expected = "enabled"; actual = "disabled" }
        }
    }

    return @{ compliant = ($violations.Count -eq 0); violations = $violations; checkedAt = (Get-Date).ToString("o"); policyId = $Data.policyId }
}

function Invoke-CheckAllCompliance {
    param([PSObject]$Data)
    $allViolations = @()
    foreach ($pol in $Data.policies) {
        $report = Invoke-CheckCompliance -Data @{ policyId = $pol.policyId; expectedSettings = $pol.settings }
        $allViolations += $report.violations
    }
    return @{ compliant = ($allViolations.Count -eq 0); violations = $allViolations; checkedAt = (Get-Date).ToString("o") }
}

function Invoke-DetectDrift {
    param([PSObject]$Data)
    $drifted = @(); $missing = @()
    foreach ($pol in $Data.expectedPolicies) {
        $stateFile = "$script:ODPath\Config\policy-$($pol.policyId).json"
        if (Test-Path $stateFile) {
            $state = Get-Content $stateFile -Raw | ConvertFrom-Json
            if ($state.version -ne $pol.version) {
                $drifted += @{ policyId = $pol.policyId; expectedVersion = $pol.version; actualVersion = $state.version }
            }
        } else {
            $missing += $pol.policyId
        }
    }
    return @{ drifted = $drifted; missing = $missing; checkedAt = (Get-Date).ToString("o") }
}

function Invoke-BackupPolicyState {
    param([string]$PolicyId)
    if (!(Test-Path $script:PolicyBackupPath)) { New-Item -Path $script:PolicyBackupPath -ItemType Directory -Force | Out-Null }
    $backup = @{
        policyId = $PolicyId; backedUpAt = (Get-Date).ToString("o")
        passwordPolicy = (net accounts 2>$null | Out-String)
        firewallProfiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled, DefaultInboundAction)
    }
    $backup | ConvertTo-Json -Depth 3 | Out-File "$script:PolicyBackupPath\$PolicyId.json" -Encoding UTF8
}

function Invoke-RollbackPolicy {
    param([PSObject]$Data)
    $backupFile = "$script:PolicyBackupPath\$($Data.policyId).json"
    if (Test-Path $backupFile) {
        Write-AgentLog "Rolling back policy: $($Data.policyId)"
        # Remove policy state
        Remove-Item "$script:ODPath\Config\policy-$($Data.policyId).json" -ErrorAction SilentlyContinue
        Show-ODNotification -Title "Richtlinie zurueckgesetzt" -Body "Policy $($Data.policyId) wurde zurueckgesetzt." -Type "Info" -Attribution "OpenDirectory - Policies"
        return "Rolled back: $($Data.policyId)"
    }
    return "No backup found for: $($Data.policyId)"
}

function Invoke-ApplyPolicyModule {
    param([string]$Module, [PSObject]$Settings)
    $wrapperSettings = @{ security = @{}; browser = $null; software = @{} }
    switch ($Module) {
        "password"   { $wrapperSettings.security.password = $Settings }
        "screenLock" { $wrapperSettings.security.screenLock = $Settings }
        "firewall"   { $wrapperSettings.security.firewall = $Settings }
        "encryption" { $wrapperSettings.security.encryption = $Settings }
        "audit"      { $wrapperSettings.security.audit = $Settings }
        "browser"    { $wrapperSettings.browser = $Settings }
        "updates"    { $wrapperSettings.software.updates = $Settings }
    }
    return Invoke-ApplyPolicy -Data @{ policyId = "module-$Module"; policyName = "Module: $Module"; settings = $wrapperSettings; enforceMode = "enforce"; notifyUser = $false }
}

# ============================================================================
# UPDATE MANAGEMENT (Windows: PSWindowsUpdate, winget, Registry, Scheduled Tasks)
# ============================================================================

function Invoke-ConfigureUpdates {
    param([string]$Json)
    try {
        $data = ($Json | ConvertFrom-Json).data
        $settings = $data.settings

        # Configure Windows Update via Registry
        $WUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        $AUPath = "$WUPath\AU"
        if (!(Test-Path $WUPath)) { New-Item -Path $WUPath -Force | Out-Null }
        if (!(Test-Path $AUPath)) { New-Item -Path $AUPath -Force | Out-Null }

        # Automatic updates
        $auOptions = if ($settings.automatic) { 4 } else { 1 }
        Set-ItemProperty -Path $AUPath -Name "AUOptions" -Value $auOptions -Type DWord
        Set-ItemProperty -Path $AUPath -Name "NoAutoUpdate" -Value 0 -Type DWord

        # Deferrals (Windows-specific)
        if ($settings.deferrals) {
            if ($null -ne $settings.deferrals.featureUpdates) {
                Set-ItemProperty -Path $WUPath -Name "DeferFeatureUpdates" -Value 1 -Type DWord
                Set-ItemProperty -Path $WUPath -Name "DeferFeatureUpdatesPeriodInDays" -Value $settings.deferrals.featureUpdates -Type DWord
            }
            if ($null -ne $settings.deferrals.qualityUpdates) {
                Set-ItemProperty -Path $WUPath -Name "DeferQualityUpdates" -Value 1 -Type DWord
                Set-ItemProperty -Path $WUPath -Name "DeferQualityUpdatesPeriodInDays" -Value $settings.deferrals.qualityUpdates -Type DWord
            }
        }

        # Windows-specific extensions
        if ($settings._windows) {
            $winExt = $settings._windows
            if ($winExt.wsusUrl) {
                Set-ItemProperty -Path $WUPath -Name "WUServer" -Value $winExt.wsusUrl -Type String
                Set-ItemProperty -Path $WUPath -Name "WUStatusServer" -Value $winExt.wsusUrl -Type String
                Set-ItemProperty -Path $AUPath -Name "UseWUServer" -Value 1 -Type DWord
            }
            if ($winExt.targetReleaseVersion) {
                Set-ItemProperty -Path $WUPath -Name "TargetReleaseVersion" -Value 1 -Type DWord
                Set-ItemProperty -Path $WUPath -Name "TargetReleaseVersionInfo" -Value $winExt.targetReleaseVersion -Type String
            }
        }

        # Restart Windows Update service
        Restart-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue

        @{ status = "success"; configured = @("windowsUpdate", "deferrals") } | ConvertTo-Json -Compress
    } catch {
        @{ status = "failed"; error = $_.Exception.Message } | ConvertTo-Json -Compress
    }
}

function Invoke-CheckUpdateStatus {
    try {
        $pending = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 5
        $rebootPending = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        $lastScan = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect" -ErrorAction SilentlyContinue).LastSuccessTime

        @{
            status = "success"
            updateStatus = @{
                rebootPending = $rebootPending
                lastScanTime = $lastScan
                recentUpdates = @($pending | ForEach-Object { @{ id = $_.HotFixID; installed = $_.InstalledOn.ToString("o") } })
            }
        } | ConvertTo-Json -Depth 4 -Compress
    } catch {
        @{ status = "failed"; error = $_.Exception.Message } | ConvertTo-Json -Compress
    }
}

function Invoke-TriggerUpdate {
    param([string]$Json)
    try {
        $data = ($Json | ConvertFrom-Json).data
        # Use Windows Update COM API or UsoClient
        Start-Process -FilePath "UsoClient.exe" -ArgumentList "StartInteractiveScan" -NoNewWindow -Wait -ErrorAction SilentlyContinue
        Start-Process -FilePath "UsoClient.exe" -ArgumentList "StartDownload" -NoNewWindow -Wait -ErrorAction SilentlyContinue
        @{ status = "success"; triggered = $true } | ConvertTo-Json -Compress
    } catch {
        @{ status = "failed"; error = $_.Exception.Message } | ConvertTo-Json -Compress
    }
}

function Invoke-GetUpdateCompliance {
    try {
        $rebootPending = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        $lastInstall = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install" -ErrorAction SilentlyContinue).LastSuccessTime

        @{
            status = "success"
            complianceReport = @{
                compliant = -not $rebootPending
                rebootPending = $rebootPending
                lastInstallTime = $lastInstall
            }
        } | ConvertTo-Json -Depth 3 -Compress
    } catch {
        @{ status = "failed"; error = $_.Exception.Message } | ConvertTo-Json -Compress
    }
}

function Invoke-ConfigureWinget {
    param([string]$Json)
    try {
        $data = ($Json | ConvertFrom-Json).data
        $settings = $data.settings

        # Ensure winget is available
        $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $wingetCmd) {
            # Try to install App Installer from Microsoft Store
            Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction SilentlyContinue
        }

        # Store config in registry
        $RegPath = "HKLM:\SOFTWARE\Policies\OpenDirectory\WingetAutoUpdate"
        if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
        Set-ItemProperty -Path $RegPath -Name "Enabled" -Value ([int]$settings.enabled) -Type DWord
        Set-ItemProperty -Path $RegPath -Name "UpdateMode" -Value $settings.updateMode -Type String
        Set-ItemProperty -Path $RegPath -Name "UpdateInterval" -Value $settings.schedule.interval -Type String
        Set-ItemProperty -Path $RegPath -Name "UpdateTime" -Value $settings.schedule.time -Type String
        Set-ItemProperty -Path $RegPath -Name "Notifications" -Value $settings.notifications -Type String

        # Write app lists
        $ConfigPath = "C:\OpenDirectory\Config"
        if (!(Test-Path $ConfigPath)) { New-Item -Path $ConfigPath -ItemType Directory -Force | Out-Null }
        if ($settings.whitelist -and $settings.whitelist.Count -gt 0) {
            $settings.whitelist | Out-File -FilePath "$ConfigPath\winget-whitelist.txt" -Force
        }
        if ($settings.blacklist -and $settings.blacklist.Count -gt 0) {
            $settings.blacklist | Out-File -FilePath "$ConfigPath\winget-blacklist.txt" -Force
        }

        # Create scheduled task for winget updates
        $TaskName = "OpenDirectory-WingetAutoUpdate"
        $triggerTime = [datetime]::Parse($settings.schedule.time)
        $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -Command `"& { winget upgrade --all --accept-source-agreements --accept-package-agreements 2>&1 | Out-File 'C:\OpenDirectory\Logs\winget-update.log' -Append }`""
        $Trigger = New-ScheduledTaskTrigger -Daily -At $triggerTime
        $Principal = New-ScheduledTaskPrincipal -UserID "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Description "OpenDirectory Winget Auto-Update" -Force | Out-Null

        @{ status = "success"; configured = @("registry", "appLists", "scheduledTask") } | ConvertTo-Json -Compress
    } catch {
        @{ status = "failed"; error = $_.Exception.Message } | ConvertTo-Json -Compress
    }
}

function Invoke-CheckWingetStatus {
    try {
        $wingetAvailable = $null -ne (Get-Command winget -ErrorAction SilentlyContinue)
        $upgradable = @()
        if ($wingetAvailable) {
            $raw = winget upgrade --accept-source-agreements 2>$null
            $upgradable = @($raw | Where-Object { $_ -match '\S+\s+\S+\s+\S+\s+winget' } | ForEach-Object {
                $parts = $_ -split '\s{2,}'
                @{ name = $parts[0]; currentVersion = $parts[1]; availableVersion = $parts[2] }
            })
        }
        @{
            status = "success"
            updateStatus = @{
                wingetAvailable = $wingetAvailable
                upgradableApps = $upgradable
                count = $upgradable.Count
            }
        } | ConvertTo-Json -Depth 4 -Compress
    } catch {
        @{ status = "failed"; error = $_.Exception.Message } | ConvertTo-Json -Compress
    }
}

# ============================================================================
# PRINTER MANAGEMENT (Windows-specific: Add-Printer, PrintManagement cmdlets)
# ============================================================================
function Invoke-DeployPrinters {
    param([PSObject]$Data)
    $results = @()

    if ($Data.removeExisting) {
        Get-Printer | Where-Object { $_.Name -like "OD_*" } | ForEach-Object {
            Remove-Printer -Name $_.Name -ErrorAction SilentlyContinue
            Write-AgentLog "Removed existing managed printer: $($_.Name)"
        }
    }

    foreach ($p in $Data.printers) {
        try {
            $printerName = "OD_$($p.name)"
            $portName = "IP_$($p.address)"

            # Remove existing printer if already installed
            Remove-Printer -Name $printerName -ErrorAction SilentlyContinue
            Remove-PrinterPort -Name $portName -ErrorAction SilentlyContinue

            # Create printer port
            $portParams = @{ Name = $portName; PrinterHostAddress = $p.address }
            if ($p.protocol -eq 'ipp') {
                $portParams.PortNumber = if ($p.port) { $p.port } else { 631 }
            } else {
                $portParams.PortNumber = if ($p.port) { $p.port } else { 9100 }
            }
            Add-PrinterPort @portParams -ErrorAction Stop

            # Resolve driver
            $driverName = $p.driver
            if (-not $driverName -or $driverName -eq 'auto') {
                $driverName = "Microsoft IPP Class Driver"
                $fallbacks = @("Microsoft IPP Class Driver", "Generic / Text Only")
                foreach ($fb in $fallbacks) {
                    if (Get-PrinterDriver -Name $fb -ErrorAction SilentlyContinue) {
                        $driverName = $fb; break
                    }
                }
            }

            # Add printer
            Add-Printer -Name $printerName -PortName $portName -DriverName $driverName -ErrorAction Stop
            if ($p.location) { Set-Printer -Name $printerName -Location $p.location -ErrorAction SilentlyContinue }
            if ($p.description) { Set-Printer -Name $printerName -Comment $p.description -ErrorAction SilentlyContinue }
            if ($p.shared) { Set-Printer -Name $printerName -Shared $true -ShareName $p.name -ErrorAction SilentlyContinue }

            # Set as default
            if ($p.isDefault -or $p.name -eq $Data.setDefault) {
                (New-Object -ComObject WScript.Network).SetDefaultPrinter($printerName)
            }

            $results += @{ name = $printerName; status = "installed" }
            Write-AgentLog "Printer installed: $printerName at $($p.address)"

            if ($Data.notifyUser) {
                Show-ODNotification -Title "Drucker installiert" -Body "$($p.displayName ?? $p.name)" -Type "Success" -Attribution "OpenDirectory - Drucker"
            }
        } catch {
            $results += @{ name = "OD_$($p.name)"; status = "failed"; error = $_.Exception.Message }
            Write-AgentLog "Printer install failed: $($p.name) - $($_.Exception.Message)" "ERROR"
        }
    }
    return @{ printers = $results }
}

function Invoke-RemovePrinter {
    param([string]$PrinterName)
    $target = if ($PrinterName -like "OD_*") { $PrinterName } else { "OD_$PrinterName" }
    $printer = Get-Printer -Name $target -ErrorAction SilentlyContinue
    if ($printer) {
        $portName = $printer.PortName
        Remove-Printer -Name $target -ErrorAction Stop
        Remove-PrinterPort -Name $portName -ErrorAction SilentlyContinue
        Write-AgentLog "Printer removed: $target"
        Show-ODNotification -Title "Drucker entfernt" -Body $target -Type "Info" -Attribution "OpenDirectory - Drucker"
        return "Removed: $target"
    }
    return "Printer not found: $target"
}

function Invoke-SetDefaultPrinter {
    param([string]$PrinterName)
    $target = if ($PrinterName -like "OD_*") { $PrinterName } else { "OD_$PrinterName" }
    (New-Object -ComObject WScript.Network).SetDefaultPrinter($target)
    Write-AgentLog "Default printer set: $target"
    return "Default printer: $target"
}

function Get-InstalledPrinters {
    return @(Get-Printer | Select-Object Name, DriverName, PortName, PrinterStatus, Shared, @{N='IsDefault';E={ $_.Name -eq (Get-WmiObject -Query "SELECT * FROM Win32_Printer WHERE Default=$true" -ErrorAction SilentlyContinue).Name }})
}

function Get-PrinterStatusDetail {
    param([string]$PrinterName)
    $target = if ($PrinterName -like "OD_*") { $PrinterName } else { "OD_$PrinterName" }
    $p = Get-Printer -Name $target -ErrorAction Stop
    $jobs = @(Get-PrintJob -PrinterName $target -ErrorAction SilentlyContinue)
    return @{
        name = $p.Name; status = $p.PrinterStatus.ToString()
        driver = $p.DriverName; port = $p.PortName
        shared = $p.Shared; location = $p.Location; comment = $p.Comment
        jobCount = $jobs.Count
        jobs = $jobs | Select-Object -First 10 Id, JobStatus, DocumentName, UserName, TotalPages
    }
}

function Invoke-UpdatePrinterSettings {
    param([string]$PrinterName, [PSObject]$Settings)
    $target = if ($PrinterName -like "OD_*") { $PrinterName } else { "OD_$PrinterName" }
    $params = @{ Name = $target }
    if ($null -ne $Settings.location) { $params.Location = $Settings.location }
    if ($null -ne $Settings.comment) { $params.Comment = $Settings.comment }
    if ($null -ne $Settings.shared) { $params.Shared = $Settings.shared }
    Set-Printer @params -ErrorAction Stop

    # Printing preferences via PrintConfiguration
    if ($Settings.duplex) {
        $config = Get-PrintConfiguration -PrinterName $target
        $config.DuplexingMode = switch ($Settings.duplex) {
            "long"  { [System.Printing.Duplexing]::TwoSidedLongEdge }
            "short" { [System.Printing.Duplexing]::TwoSidedShortEdge }
            default { [System.Printing.Duplexing]::OneSided }
        }
        Set-PrintConfiguration -PrinterName $target -PrintConfiguration $config -ErrorAction SilentlyContinue
    }
    Write-AgentLog "Printer settings updated: $target"
    return "Settings updated: $target"
}

function Invoke-ApplyPrinterPolicy {
    param([PSObject]$Data)
    # Remove unmanaged OD_ printers if policy requires
    if ($Data.removeUnmanaged) {
        $managedNames = $Data.printers | ForEach-Object { "OD_$($_.name)" }
        Get-Printer | Where-Object { $_.Name -like "OD_*" -and $_.Name -notin $managedNames } | ForEach-Object {
            Remove-Printer -Name $_.Name -ErrorAction SilentlyContinue
            Write-AgentLog "Policy: removed unmanaged printer $($_.Name)"
        }
    }
    # Deploy policy printers
    $result = Invoke-DeployPrinters -Data $Data
    if ($Data.policyId) {
        Write-AgentLog "Printer policy applied: $($Data.policyId)"
        Show-ODNotification -Title "Drucker-Richtlinie angewendet" -Body "$($Data.printers.Count) Drucker konfiguriert" -Type "Info" -Attribution "OpenDirectory - Policies"
    }
    return $result
}

function Invoke-TestPrint {
    param([string]$PrinterName)
    $target = if ($PrinterName -like "OD_*") { $PrinterName } else { "OD_$PrinterName" }
    $testContent = "OpenDirectory Test Print`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`nDevice: $env:COMPUTERNAME`nPrinter: $target"
    $tempFile = [System.IO.Path]::GetTempFileName() + ".txt"
    $testContent | Out-File -FilePath $tempFile -Encoding UTF8
    Start-Process -FilePath "notepad.exe" -ArgumentList "/p `"$tempFile`"" -Wait -NoNewWindow -ErrorAction Stop
    Remove-Item $tempFile -ErrorAction SilentlyContinue
    Write-AgentLog "Test print sent to: $target"
    return "Test print sent to $target"
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
