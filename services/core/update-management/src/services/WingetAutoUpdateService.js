const { EventEmitter } = require('events');
const logger = require('../utils/logger');
const AuditLogger = require('../audit/AuditLogger');

/**
 * Winget Auto-Update Service
 * Manages automatic application updates via Windows Package Manager (winget)
 * Inspired by Romanitho/Winget-AutoUpdate - implemented natively in OpenDirectory
 */
class WingetAutoUpdateService extends EventEmitter {
    constructor(updateAgentService) {
        super();
        this.auditLogger = new AuditLogger();
        this.updateAgentService = updateAgentService; // Generic agent dispatch
        this.deviceConfigs = new Map();
        this.appPolicies = new Map();
    }

    /**
     * Configure Winget Auto-Update on a device according to policy
     */
    async configureWingetAutoUpdate(deviceId, policy) {
        try {
            logger.info(`Configuring Winget Auto-Update for device: ${deviceId}`);

            const config = {
                deviceId,
                enabled: policy.enabled !== false,
                updateMode: policy.updateMode || 'blacklist',
                whitelist: policy.whitelist || [],
                blacklist: policy.blacklist || [],
                schedule: {
                    interval: (policy.schedule && policy.schedule.interval) || 'Daily',
                    time: (policy.schedule && policy.schedule.time) || '06:00',
                    timeDelay: (policy.schedule && policy.schedule.timeDelay) || 0,
                    daysOfWeek: (policy.schedule && policy.schedule.daysOfWeek) || ['Monday']
                },
                notifications: policy.notifications || 'Full',
                userContext: policy.userContext || false,
                acceptAllSourceAgreements: policy.acceptAllSourceAgreements !== false,
                maxConcurrentUpdates: policy.maxConcurrentUpdates || 3
            };

            this.deviceConfigs.set(deviceId, config);

            // Dispatch to agent via WebSocket (agent handles winget-specific enforcement)
            let agentResult = null;
            if (this.updateAgentService) {
                agentResult = this.updateAgentService.configureWingetAutoUpdate(deviceId, config);
            }

            await this.auditLogger.log('winget_autoupdate_configured', {
                deviceId,
                config,
                agentDispatched: !!agentResult,
                timestamp: new Date().toISOString()
            });

            this.emit('wingetAutoUpdateConfigured', { deviceId, config });

            return {
                success: true,
                policyId: `wau-policy-${deviceId}`,
                agentResult,
                config
            };

        } catch (error) {
            logger.error('Error configuring Winget Auto-Update:', error);
            throw error;
        }
    }

    /**
     * Generate PowerShell script to ensure winget is available
     */
    generateWingetPrerequisiteScript() {
        return `
# ============================================================
# OpenDirectory Winget Prerequisite Check
# ============================================================

$ErrorActionPreference = "Stop"
$LogPath = "C:\\OpenDirectory\\Logs\\WingetAutoUpdate"
if (!(Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$Timestamp [$Level] $Message" | Out-File -Append -FilePath "$LogPath\\winget-autoupdate.log"
    Write-Output "[$Level] $Message"
}

# Check if winget is available
$WingetPath = $null
$WingetCmd = Get-Command winget -ErrorAction SilentlyContinue
if ($WingetCmd) {
    $WingetPath = $WingetCmd.Source
    $WingetVersion = & winget --version 2>$null
    Write-Log "Winget found: $WingetPath (Version: $WingetVersion)"
} else {
    Write-Log "Winget not found. Attempting to install..." "WARN"

    # Try to install via Add-AppxPackage (App Installer from Microsoft Store)
    try {
        $ProgressPreference = 'SilentlyContinue'

        # Download latest Microsoft.DesktopAppInstaller
        $ApiUrl = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
        $Release = Invoke-RestMethod -Uri $ApiUrl -Headers @{ "User-Agent" = "OpenDirectory" }
        $MsixUrl = ($Release.assets | Where-Object { $_.name -match "Microsoft.DesktopAppInstaller.*\\.msixbundle$" }).browser_download_url
        $LicenseUrl = ($Release.assets | Where-Object { $_.name -match "License.*\\.xml$" }).browser_download_url

        $MsixPath = "$env:TEMP\\Microsoft.DesktopAppInstaller.msixbundle"
        $LicensePath = "$env:TEMP\\WingetLicense.xml"

        Invoke-WebRequest -Uri $MsixUrl -OutFile $MsixPath
        Invoke-WebRequest -Uri $LicenseUrl -OutFile $LicensePath

        # Install VCLibs dependency
        Add-AppxPackage -Path "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -ErrorAction SilentlyContinue

        # Install winget
        Add-AppxProvisionedPackage -Online -PackagePath $MsixPath -LicensePath $LicensePath -ErrorAction Stop
        Write-Log "Winget installed successfully"

        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    } catch {
        Write-Log "Failed to install winget: $($_.Exception.Message)" "ERROR"
        throw "Winget installation failed. Cannot proceed with auto-update configuration."
    }
}

# Verify winget works
try {
    $TestOutput = & winget list --count 1 --accept-source-agreements 2>$null
    Write-Log "Winget operational check passed"
} catch {
    Write-Log "Winget operational check failed: $($_.Exception.Message)" "ERROR"
    throw "Winget is not operational."
}`;
    }

    /**
     * Generate the main winget update PowerShell script that will be run by the scheduled task
     */
    generateWingetUpdateScript(config) {
        const appFilterBlock = this.generateAppListScript(config);

        return `
# ============================================================
# OpenDirectory Winget Auto-Update Script
# Generated on: ${new Date().toISOString()}
# Device ID: ${config.deviceId}
# Update Mode: ${config.updateMode}
# ============================================================

$ErrorActionPreference = "Continue"
$LogFile = "C:\\OpenDirectory\\Logs\\WingetAutoUpdate\\update-run-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-UpdateLog {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$Timestamp [$Level] $Message" | Out-File -Append -FilePath $LogFile
}

Write-UpdateLog "=== OpenDirectory Winget Auto-Update started ==="
Write-UpdateLog "Update mode: ${config.updateMode}"
Write-UpdateLog "User context: ${config.userContext}"
Write-UpdateLog "Notifications: ${config.notifications}"

# Store policy configuration in registry for compliance checks
$PolicyRegPath = "HKLM:\\SOFTWARE\\Policies\\OpenDirectory\\WingetAutoUpdate"
if (!(Test-Path $PolicyRegPath)) { New-Item -Path $PolicyRegPath -Force | Out-Null }
Set-ItemProperty -Path $PolicyRegPath -Name "Enabled" -Value 1 -Type DWord
Set-ItemProperty -Path $PolicyRegPath -Name "UpdateMode" -Value "${config.updateMode}" -Type String
Set-ItemProperty -Path $PolicyRegPath -Name "Schedule" -Value "${config.schedule.interval}" -Type String
Set-ItemProperty -Path $PolicyRegPath -Name "LastConfigured" -Value (Get-Date).ToString("o") -Type String
Set-ItemProperty -Path $PolicyRegPath -Name "Notifications" -Value "${config.notifications}" -Type String

${appFilterBlock}

# Get list of available upgrades
Write-UpdateLog "Checking for available upgrades..."
$UpgradeListJson = & winget upgrade --source winget ${config.acceptAllSourceAgreements ? '--accept-source-agreements' : ''} 2>$null

# Parse available updates and apply filters
$UpdateResults = @{
    TotalChecked = 0
    Updated = @()
    Skipped = @()
    Failed = @()
    StartTime = (Get-Date).ToString("o")
}

# Get upgradeable packages as structured data
$UpgradeableRaw = & winget upgrade --source winget --accept-source-agreements 2>$null
$UpgradeLines = $UpgradeableRaw | Where-Object { $_ -match "\\S" } | Select-Object -Skip 1

$PackagesToUpdate = @()
foreach ($Line in $UpgradeLines) {
    # Parse winget upgrade output (ID is the second column)
    if ($Line -match "^(.+?)\\s{2,}(\\S+)\\s+(\\S+)\\s+(\\S+)") {
        $PackageId = $Matches[2].Trim()
        if ($PackageId -and $PackageId -ne "Id" -and $PackageId -notmatch "^-+$") {
            $UpdateResults.TotalChecked++

            # Apply whitelist/blacklist filter
            $ShouldUpdate = $false
            if ($UpdateMode -eq "whitelist") {
                $ShouldUpdate = $AllowedApps | Where-Object { $PackageId -like $_ }
            } else {
                $ShouldUpdate = -not ($BlockedApps | Where-Object { $PackageId -like $_ })
            }

            if ($ShouldUpdate) {
                $PackagesToUpdate += $PackageId
            } else {
                $UpdateResults.Skipped += $PackageId
                Write-UpdateLog "Skipped (filtered by policy): $PackageId"
            }
        }
    }
}

Write-UpdateLog "Found $($PackagesToUpdate.Count) packages to update (filtered from $($UpdateResults.TotalChecked) available)"

# Update packages with concurrency limit
$RunningJobs = @()
$MaxConcurrent = ${config.maxConcurrentUpdates}

foreach ($PackageId in $PackagesToUpdate) {
    # Wait if we've reached the concurrency limit
    while ($RunningJobs.Count -ge $MaxConcurrent) {
        $CompletedJob = $RunningJobs | Wait-Job -Any
        $JobResult = Receive-Job -Job $CompletedJob
        $RunningJobs = $RunningJobs | Where-Object { $_.Id -ne $CompletedJob.Id }
        Remove-Job -Job $CompletedJob
    }

    Write-UpdateLog "Updating: $PackageId"

    $Job = Start-Job -ScriptBlock {
        param($Id, $AcceptAgreements)
        $Args = @("upgrade", "--id", $Id, "--source", "winget", "--silent")
        if ($AcceptAgreements) {
            $Args += "--accept-source-agreements"
            $Args += "--accept-package-agreements"
        }
        $Result = & winget @Args 2>&1
        @{ Id = $Id; Output = ($Result -join "`n"); ExitCode = $LASTEXITCODE }
    } -ArgumentList $PackageId, $${config.acceptAllSourceAgreements}

    $RunningJobs += $Job
}

# Wait for remaining jobs
foreach ($Job in $RunningJobs) {
    $JobResult = Receive-Job -Job $Job -Wait
    if ($JobResult.ExitCode -eq 0) {
        $UpdateResults.Updated += $JobResult.Id
        Write-UpdateLog "Successfully updated: $($JobResult.Id)"
    } else {
        $UpdateResults.Failed += @{ Id = $JobResult.Id; Error = $JobResult.Output }
        Write-UpdateLog "Failed to update: $($JobResult.Id) - $($JobResult.Output)" "ERROR"
    }
    Remove-Job -Job $Job
}

$UpdateResults.EndTime = (Get-Date).ToString("o")

# Save results to registry for compliance reporting
Set-ItemProperty -Path $PolicyRegPath -Name "LastRunTime" -Value $UpdateResults.EndTime -Type String
Set-ItemProperty -Path $PolicyRegPath -Name "LastRunUpdated" -Value ($UpdateResults.Updated.Count) -Type DWord
Set-ItemProperty -Path $PolicyRegPath -Name "LastRunFailed" -Value ($UpdateResults.Failed.Count) -Type DWord
Set-ItemProperty -Path $PolicyRegPath -Name "LastRunSkipped" -Value ($UpdateResults.Skipped.Count) -Type DWord

# Save detailed results as JSON
$UpdateResults | ConvertTo-Json -Depth 3 | Out-File -FilePath "C:\\OpenDirectory\\Logs\\WingetAutoUpdate\\last-results.json" -Force

Write-UpdateLog "=== Update run completed ==="
Write-UpdateLog "Updated: $($UpdateResults.Updated.Count), Failed: $($UpdateResults.Failed.Count), Skipped: $($UpdateResults.Skipped.Count)"

${config.notifications !== 'None' ? `
# Show notification to logged-in user
$NotifyLevel = "${config.notifications}"
$ShowNotification = $false

switch ($NotifyLevel) {
    "Full" { $ShowNotification = $true }
    "SuccessOnly" { $ShowNotification = $UpdateResults.Updated.Count -gt 0 -and $UpdateResults.Failed.Count -eq 0 }
    "ErrorsOnly" { $ShowNotification = $UpdateResults.Failed.Count -gt 0 }
}

if ($ShowNotification) {
    $UpdatedList = ($UpdateResults.Updated -join ", ")
    $FailedList = ($UpdateResults.Failed | ForEach-Object { $_.Id }) -join ", "

    $Title = "OpenDirectory - App Updates"
    $Body = "Updated: $($UpdateResults.Updated.Count)"
    if ($UpdateResults.Failed.Count -gt 0) { $Body += " | Failed: $($UpdateResults.Failed.Count)" }

    # Toast notification via scheduled task running as user
    $ToastXml = @"
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text>$Title</text>
            <text>$Body</text>
        </binding>
    </visual>
</toast>
"@

    try {
        $XmlDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $XmlDoc.LoadXml($ToastXml)
        $AppId = "OpenDirectory.WingetAutoUpdate"
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Show(
            [Windows.UI.Notifications.ToastNotification]::new($XmlDoc)
        )
    } catch {
        Write-UpdateLog "Could not show notification: $($_.Exception.Message)" "WARN"
    }
}
` : '# Notifications disabled by policy'}

# Report results to OpenDirectory server
$UpdateResults | ConvertTo-Json -Depth 3`;
    }

    /**
     * Generate PowerShell whitelist/blacklist filter variables
     */
    generateAppListScript(config) {
        if (config.updateMode === 'whitelist') {
            const appLines = config.whitelist.map(id => `    "${id}"`).join(',\n');
            return `
# Whitelist mode: only update these apps
$UpdateMode = "whitelist"
$AllowedApps = @(
${appLines}
)
$BlockedApps = @()

Write-UpdateLog "Whitelist mode active: $($AllowedApps.Count) apps allowed"
# Write app list to file for reference
$AllowedApps | Out-File -FilePath "C:\\OpenDirectory\\Config\\winget-whitelist.txt" -Force`;
        } else {
            const appLines = config.blacklist.map(id => `    "${id}"`).join(',\n');
            return `
# Blacklist mode: update all apps except these
$UpdateMode = "blacklist"
$AllowedApps = @()
$BlockedApps = @(
${appLines}
)

Write-UpdateLog "Blacklist mode active: $($BlockedApps.Count) apps blocked"
# Write app list to file for reference
$BlockedApps | Out-File -FilePath "C:\\OpenDirectory\\Config\\winget-blacklist.txt" -Force`;
        }
    }

    /**
     * Generate PowerShell script to create/update the scheduled task
     */
    generateScheduleScript(config) {
        const intervalMap = {
            'Daily': '-Daily',
            'BiDaily': '-Daily -DaysInterval 2',
            'Weekly': `-Weekly -DaysOfWeek ${config.schedule.daysOfWeek.join(', ')}`,
            'BiWeekly': `-Weekly -WeeksInterval 2 -DaysOfWeek ${config.schedule.daysOfWeek.join(', ')}`,
            'Monthly': '-Daily -DaysInterval 30'
        };
        const triggerArgs = intervalMap[config.schedule.interval] || '-Daily';

        return `
# ============================================================
# Configure Scheduled Task for Winget Auto-Update
# ============================================================

$TaskName = "OpenDirectory-WingetAutoUpdate"
$ScriptPath = "C:\\OpenDirectory\\Scripts\\Invoke-WingetAutoUpdate.ps1"
$ConfigPath = "C:\\OpenDirectory\\Config"

# Ensure directories exist
@($ConfigPath, "C:\\OpenDirectory\\Scripts", "C:\\OpenDirectory\\Logs\\WingetAutoUpdate") | ForEach-Object {
    if (!(Test-Path $_)) { New-Item -Path $_ -ItemType Directory -Force | Out-Null }
}

# Save the update script to disk
$UpdateScriptContent = @'
# This script is managed by OpenDirectory - do not edit manually
# Re-run the OpenDirectory Winget Auto-Update policy to regenerate
'@

# Remove existing task if it exists
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Create scheduled task
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File \`"$ScriptPath\`""
$Trigger = New-ScheduledTaskTrigger ${triggerArgs} -At "${config.schedule.time}"
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2)
$Principal = New-ScheduledTaskPrincipal -UserID "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

${config.schedule.timeDelay > 0 ? `
# Add random delay to prevent all devices updating simultaneously
$Trigger.RandomDelay = [System.Xml.XmlConvert]::ToString((New-TimeSpan -Minutes ${config.schedule.timeDelay}))
` : '# No random delay configured'}

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "OpenDirectory Winget Auto-Update - Automatic application updates managed by policy" -Force

Write-Log "Scheduled task '$TaskName' configured"
Write-Log "Schedule: ${config.schedule.interval} at ${config.schedule.time}${config.schedule.timeDelay > 0 ? ` (random delay up to ${config.schedule.timeDelay} min)` : ''}"

${config.userContext ? `
# Also create a user-context task for user-scope apps
$UserTaskName = "OpenDirectory-WingetAutoUpdate-User"
Unregister-ScheduledTask -TaskName $UserTaskName -Confirm:$false -ErrorAction SilentlyContinue

$UserAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -Command \\"& { winget upgrade --all --silent --accept-source-agreements --accept-package-agreements --scope user 2>&1 | Out-File -Append 'C:\\OpenDirectory\\Logs\\WingetAutoUpdate\\user-update.log' }\\" "
$UserTrigger = New-ScheduledTaskTrigger -AtLogOn
$UserSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName $UserTaskName -Action $UserAction -Trigger $UserTrigger -Settings $UserSettings -Description "OpenDirectory Winget Auto-Update (User Context)" -Force

Write-Log "User-context task '$UserTaskName' configured (runs at logon)"
` : '# User-context updates disabled by policy'}`;
    }

    /**
     * Configure update schedule for a device
     */
    async configureSchedule(deviceId, scheduleConfig) {
        try {
            logger.info(`Configuring Winget Auto-Update schedule for device: ${deviceId}`);

            const existingConfig = this.deviceConfigs.get(deviceId);
            if (existingConfig) {
                existingConfig.schedule = {
                    interval: scheduleConfig.interval || existingConfig.schedule.interval,
                    time: scheduleConfig.time || existingConfig.schedule.time,
                    timeDelay: scheduleConfig.timeDelay || existingConfig.schedule.timeDelay,
                    daysOfWeek: scheduleConfig.daysOfWeek || existingConfig.schedule.daysOfWeek
                };
                this.deviceConfigs.set(deviceId, existingConfig);
            }

            const config = existingConfig || {
                deviceId,
                schedule: {
                    interval: scheduleConfig.interval || 'Daily',
                    time: scheduleConfig.time || '06:00',
                    timeDelay: scheduleConfig.timeDelay || 0,
                    daysOfWeek: scheduleConfig.daysOfWeek || ['Monday']
                },
                userContext: scheduleConfig.userContext || false
            };

            const script = this.generateScheduleScript(config);

            await this.auditLogger.log('winget_schedule_configured', {
                deviceId,
                schedule: config.schedule,
                timestamp: new Date().toISOString()
            });

            return {
                success: true,
                deviceId,
                schedule: config.schedule,
                script
            };

        } catch (error) {
            logger.error('Error configuring Winget Auto-Update schedule:', error);
            throw error;
        }
    }

    /**
     * Check Winget Auto-Update status on a device
     */
    async checkWingetUpdateStatus(deviceId) {
        try {
            logger.info(`Checking Winget Auto-Update status for device: ${deviceId}`);

            const statusScript = `
# OpenDirectory Winget Auto-Update Status Check
$Status = @{
    DeviceId = $env:COMPUTERNAME
    Timestamp = (Get-Date).ToString("o")
    WingetInstalled = $false
    WingetVersion = $null
    ScheduledTaskExists = $false
    ScheduledTaskState = $null
    LastRunTime = $null
    LastRunResult = $null
    PolicyConfigured = $false
    UpdateMode = $null
    PendingUpdates = @()
}

# Check winget
$WingetCmd = Get-Command winget -ErrorAction SilentlyContinue
if ($WingetCmd) {
    $Status.WingetInstalled = $true
    $Status.WingetVersion = (& winget --version 2>$null).Trim()
}

# Check scheduled task
$Task = Get-ScheduledTask -TaskName "OpenDirectory-WingetAutoUpdate" -ErrorAction SilentlyContinue
if ($Task) {
    $Status.ScheduledTaskExists = $true
    $Status.ScheduledTaskState = $Task.State.ToString()
    $TaskInfo = Get-ScheduledTaskInfo -TaskName "OpenDirectory-WingetAutoUpdate" -ErrorAction SilentlyContinue
    if ($TaskInfo) {
        $Status.LastRunTime = $TaskInfo.LastRunTime.ToString("o")
        $Status.LastRunResult = $TaskInfo.LastTaskResult
    }
}

# Check policy registry
$PolicyRegPath = "HKLM:\\SOFTWARE\\Policies\\OpenDirectory\\WingetAutoUpdate"
if (Test-Path $PolicyRegPath) {
    $Status.PolicyConfigured = $true
    $Status.UpdateMode = (Get-ItemProperty -Path $PolicyRegPath -Name "UpdateMode" -ErrorAction SilentlyContinue).UpdateMode
    $Status.LastConfigured = (Get-ItemProperty -Path $PolicyRegPath -Name "LastConfigured" -ErrorAction SilentlyContinue).LastConfigured
    $Status.LastRunUpdated = (Get-ItemProperty -Path $PolicyRegPath -Name "LastRunUpdated" -ErrorAction SilentlyContinue).LastRunUpdated
    $Status.LastRunFailed = (Get-ItemProperty -Path $PolicyRegPath -Name "LastRunFailed" -ErrorAction SilentlyContinue).LastRunFailed
}

# Check for pending updates
if ($Status.WingetInstalled) {
    try {
        $UpgradeOutput = & winget upgrade --source winget --accept-source-agreements 2>$null
        $PendingCount = ($UpgradeOutput | Where-Object { $_ -match "\\S" -and $_ -notmatch "^(Name|--|\\d+ upgrade)" }).Count
        $Status.PendingUpdatesCount = [Math]::Max(0, $PendingCount - 1)
    } catch {
        $Status.PendingUpdatesCount = -1
    }
}

# Read last results if available
$ResultsFile = "C:\\OpenDirectory\\Logs\\WingetAutoUpdate\\last-results.json"
if (Test-Path $ResultsFile) {
    $Status.LastResults = Get-Content $ResultsFile -Raw | ConvertFrom-Json
}

$Status | ConvertTo-Json -Depth 4`;

            return {
                success: true,
                deviceId,
                script: statusScript,
                timestamp: new Date().toISOString()
            };

        } catch (error) {
            logger.error('Error checking Winget Auto-Update status:', error);
            throw error;
        }
    }

    /**
     * Get compliance report for Winget Auto-Update across devices
     */
    async getComplianceReport(deviceIds = []) {
        try {
            const report = {
                timestamp: new Date().toISOString(),
                devices: [],
                summary: {
                    configured: 0,
                    notConfigured: 0,
                    updatesAvailable: 0,
                    lastRunFailed: 0
                }
            };

            const complianceScript = `
# OpenDirectory Winget Auto-Update Compliance Report
$Compliance = @{
    DeviceId = $env:COMPUTERNAME
    Timestamp = (Get-Date).ToString("o")
    Compliant = $true
    Issues = @()
}

# Check 1: Winget installed
$WingetAvailable = [bool](Get-Command winget -ErrorAction SilentlyContinue)
if (-not $WingetAvailable) {
    $Compliance.Compliant = $false
    $Compliance.Issues += "Winget is not installed"
}

# Check 2: Scheduled task exists and is running
$Task = Get-ScheduledTask -TaskName "OpenDirectory-WingetAutoUpdate" -ErrorAction SilentlyContinue
if (-not $Task) {
    $Compliance.Compliant = $false
    $Compliance.Issues += "Scheduled task not found"
} elseif ($Task.State -ne "Ready" -and $Task.State -ne "Running") {
    $Compliance.Compliant = $false
    $Compliance.Issues += "Scheduled task is in state: $($Task.State)"
}

# Check 3: Policy is configured in registry
$PolicyRegPath = "HKLM:\\SOFTWARE\\Policies\\OpenDirectory\\WingetAutoUpdate"
if (-not (Test-Path $PolicyRegPath)) {
    $Compliance.Compliant = $false
    $Compliance.Issues += "Policy not configured in registry"
} else {
    $Enabled = (Get-ItemProperty -Path $PolicyRegPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    if ($Enabled -ne 1) {
        $Compliance.Compliant = $false
        $Compliance.Issues += "Policy is disabled"
    }
}

# Check 4: Last run was recent (within 2x the scheduled interval)
$TaskInfo = Get-ScheduledTaskInfo -TaskName "OpenDirectory-WingetAutoUpdate" -ErrorAction SilentlyContinue
if ($TaskInfo -and $TaskInfo.LastRunTime) {
    $DaysSinceLastRun = ((Get-Date) - $TaskInfo.LastRunTime).TotalDays
    if ($DaysSinceLastRun -gt 3) {
        $Compliance.Issues += "Last run was $([math]::Round($DaysSinceLastRun, 1)) days ago"
    }

    # Check if last run failed
    if ($TaskInfo.LastTaskResult -ne 0) {
        $Compliance.Issues += "Last run exit code: $($TaskInfo.LastTaskResult)"
    }
}

# Check 5: Pending updates count
if ($WingetAvailable) {
    try {
        $UpgradeOutput = & winget upgrade --source winget --accept-source-agreements 2>$null
        $Lines = $UpgradeOutput | Where-Object { $_ -match "\\S" -and $_ -notmatch "^(Name|--|\\d+ upgrade)" }
        $Compliance.PendingUpdates = [Math]::Max(0, $Lines.Count - 1)
    } catch {
        $Compliance.PendingUpdates = -1
    }
}

# Read app lists for drift detection
$WhitelistFile = "C:\\OpenDirectory\\Config\\winget-whitelist.txt"
$BlacklistFile = "C:\\OpenDirectory\\Config\\winget-blacklist.txt"
if (Test-Path $WhitelistFile) {
    $Compliance.DeployedWhitelist = Get-Content $WhitelistFile | Where-Object { $_.Trim() }
}
if (Test-Path $BlacklistFile) {
    $Compliance.DeployedBlacklist = Get-Content $BlacklistFile | Where-Object { $_.Trim() }
}

$Compliance | ConvertTo-Json -Depth 3`;

            return {
                success: true,
                complianceScript,
                reportTemplate: report
            };

        } catch (error) {
            logger.error('Error generating Winget Auto-Update compliance report:', error);
            throw error;
        }
    }

    /**
     * Force an immediate update run on a device
     */
    async forceUpdate(deviceId, appIds = []) {
        try {
            logger.info(`Forcing Winget update for device: ${deviceId}`);

            let forceScript;
            if (appIds.length > 0) {
                const idList = appIds.map(id => `"${id}"`).join(', ');
                forceScript = `
# OpenDirectory - Force Winget Update (Selective)
$AppsToUpdate = @(${idList})

foreach ($AppId in $AppsToUpdate) {
    Write-Output "Updating: $AppId"
    & winget upgrade --id $AppId --silent --accept-source-agreements --accept-package-agreements --source winget 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Output "Successfully updated: $AppId"
    } else {
        Write-Warning "Failed to update: $AppId (exit code: $LASTEXITCODE)"
    }
}`;
            } else {
                forceScript = `
# OpenDirectory - Force Winget Update (All)
Write-Output "Running forced winget upgrade for all packages..."
& winget upgrade --all --silent --accept-source-agreements --accept-package-agreements --source winget 2>&1
Write-Output "Force update completed with exit code: $LASTEXITCODE"`;
            }

            await this.auditLogger.log('winget_update_forced', {
                deviceId,
                appIds,
                timestamp: new Date().toISOString()
            });

            this.emit('wingetUpdateForced', { deviceId, appIds });

            return {
                success: true,
                deviceId,
                script: forceScript,
                appIds
            };

        } catch (error) {
            logger.error('Error forcing Winget update:', error);
            throw error;
        }
    }

    /**
     * Remove Winget Auto-Update configuration from a device
     */
    async removeConfiguration(deviceId) {
        try {
            logger.info(`Removing Winget Auto-Update configuration for device: ${deviceId}`);

            const removeScript = `
# OpenDirectory - Remove Winget Auto-Update Configuration
Write-Output "Removing OpenDirectory Winget Auto-Update configuration..."

# Remove scheduled tasks
Unregister-ScheduledTask -TaskName "OpenDirectory-WingetAutoUpdate" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "OpenDirectory-WingetAutoUpdate-User" -Confirm:$false -ErrorAction SilentlyContinue
Write-Output "Scheduled tasks removed"

# Remove policy registry keys
$PolicyRegPath = "HKLM:\\SOFTWARE\\Policies\\OpenDirectory\\WingetAutoUpdate"
if (Test-Path $PolicyRegPath) {
    Remove-Item -Path $PolicyRegPath -Recurse -Force
    Write-Output "Policy registry keys removed"
}

# Remove configuration files
$ConfigFiles = @(
    "C:\\OpenDirectory\\Config\\winget-whitelist.txt",
    "C:\\OpenDirectory\\Config\\winget-blacklist.txt",
    "C:\\OpenDirectory\\Scripts\\Invoke-WingetAutoUpdate.ps1"
)
foreach ($File in $ConfigFiles) {
    if (Test-Path $File) {
        Remove-Item -Path $File -Force
        Write-Output "Removed: $File"
    }
}

Write-Output "Winget Auto-Update configuration removed successfully"`;

            this.deviceConfigs.delete(deviceId);

            await this.auditLogger.log('winget_autoupdate_removed', {
                deviceId,
                timestamp: new Date().toISOString()
            });

            this.emit('wingetAutoUpdateRemoved', { deviceId });

            return {
                success: true,
                deviceId,
                script: removeScript
            };

        } catch (error) {
            logger.error('Error removing Winget Auto-Update configuration:', error);
            throw error;
        }
    }
}

module.exports = WingetAutoUpdateService;
