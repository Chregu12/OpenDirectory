const { EventEmitter } = require('events');
const logger = require('../utils/logger');
const AuditLogger = require('../audit/AuditLogger');

class WindowsUpdateService extends EventEmitter {
    constructor() {
        super();
        this.auditLogger = new AuditLogger();
        this.updateSessions = new Map();
        this.deferralPolicies = new Map();
        this.maintenanceWindows = new Map();
    }

    /**
     * Windows Update for Business Management
     * Implements Microsoft's recommended enterprise update policies
     */
    async configureUpdatePolicy(deviceId, policy) {
        try {
            logger.info(`Configuring Windows update policy for device: ${deviceId}`);
            
            const updatePolicy = {
                deviceId,
                featureUpdateDeferralPeriod: policy.featureUpdateDeferralDays || 0,
                qualityUpdateDeferralPeriod: policy.qualityUpdateDeferralDays || 0,
                driverUpdatesDeferral: policy.deferDriverUpdates || false,
                automaticMaintenanceEnabled: policy.automaticMaintenance || true,
                updateServiceUrl: policy.wsusUrl || null,
                targetReleaseVersion: policy.targetVersion || null,
                pauseUpdates: policy.pauseUpdates || false,
                pauseFeatureUpdates: policy.pauseFeatureUpdates || false,
                pauseQualityUpdates: policy.pauseQualityUpdates || false,
                activeHoursStart: policy.activeHoursStart || '08:00',
                activeHoursEnd: policy.activeHoursEnd || '17:00',
                restartGracePeriod: policy.restartGracePeriod || 15,
                autoRestartRequiredNotificationDismissal: policy.autoRestartNotification || '15m',
                scheduleRestartWarning: policy.scheduleRestartWarning || '4h',
                scheduleImminentRestartWarning: policy.scheduleImminentRestartWarning || '15m',
                deadlineForFeatureUpdates: policy.featureUpdateDeadline || null,
                deadlineForQualityUpdates: policy.qualityUpdateDeadline || null,
                deadlineGracePeriod: policy.deadlineGracePeriod || 7,
                allowMUUpdateService: policy.allowMUUpdateService || true,
                branchReadinessLevel: policy.branchReadinessLevel || 'Current Branch for Business',
                updateRing: policy.updateRing || 'Production'
            };

            // Store policy for device
            this.deferralPolicies.set(deviceId, updatePolicy);

            // Generate PowerShell script for Windows Update configuration
            const psScript = this.generateWindowsUpdatePSScript(updatePolicy);
            
            await this.auditLogger.log('windows_update_policy_configured', {
                deviceId,
                policy: updatePolicy,
                timestamp: new Date().toISOString()
            });

            this.emit('policyConfigured', { deviceId, policy: updatePolicy });

            return {
                success: true,
                policyId: `wu-policy-${deviceId}`,
                script: psScript,
                policy: updatePolicy
            };

        } catch (error) {
            logger.error('Error configuring Windows update policy:', error);
            throw error;
        }
    }

    /**
     * Generate PowerShell script for Windows Update configuration
     */
    generateWindowsUpdatePSScript(policy) {
        return `
# OpenDirectory Windows Update Configuration Script
# Generated on: ${new Date().toISOString()}
# Device ID: ${policy.deviceId}

# Import required modules
Import-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue

# Configure Windows Update for Business settings via Registry
$WUfBPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"
$AUPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"

# Ensure registry paths exist
if (!(Test-Path $WUfBPath)) { New-Item -Path $WUfBPath -Force }
if (!(Test-Path $AUPath)) { New-Item -Path $AUPath -Force }

# Configure update deferrals
Set-ItemProperty -Path $WUfBPath -Name "DeferFeatureUpdates" -Value 1 -Type DWord
Set-ItemProperty -Path $WUfBPath -Name "DeferFeatureUpdatesPeriodInDays" -Value ${policy.featureUpdateDeferralPeriod} -Type DWord
Set-ItemProperty -Path $WUfBPath -Name "DeferQualityUpdates" -Value 1 -Type DWord
Set-ItemProperty -Path $WUfBPath -Name "DeferQualityUpdatesPeriodInDays" -Value ${policy.qualityUpdateDeferralPeriod} -Type DWord

# Configure driver updates
Set-ItemProperty -Path $WUfBPath -Name "ExcludeWUDriversInQualityUpdate" -Value $(if ($${policy.driverUpdatesDeferral}) { 1 } else { 0 }) -Type DWord

# Configure automatic updates
Set-ItemProperty -Path $AUPath -Name "NoAutoUpdate" -Value 0 -Type DWord
Set-ItemProperty -Path $AUPath -Name "AUOptions" -Value 4 -Type DWord
Set-ItemProperty -Path $AUPath -Name "ScheduledInstallDay" -Value 0 -Type DWord
Set-ItemProperty -Path $AUPath -Name "ScheduledInstallTime" -Value 3 -Type DWord

# Configure active hours
Set-ItemProperty -Path $AUPath -Name "ActiveHoursStart" -Value ${policy.activeHoursStart.replace(':', '')} -Type DWord
Set-ItemProperty -Path $AUPath -Name "ActiveHoursEnd" -Value ${policy.activeHoursEnd.replace(':', '')} -Type DWord

# Configure restart behavior
Set-ItemProperty -Path $AUPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord
Set-ItemProperty -Path $AUPath -Name "RebootRelaunchTimeout" -Value ${policy.restartGracePeriod} -Type DWord

# Configure update source if WSUS is specified
${policy.updateServiceUrl ? `
Set-ItemProperty -Path $WUfBPath -Name "WUServer" -Value "${policy.updateServiceUrl}" -Type String
Set-ItemProperty -Path $WUfBPath -Name "WUStatusServer" -Value "${policy.updateServiceUrl}" -Type String
Set-ItemProperty -Path $AUPath -Name "UseWUServer" -Value 1 -Type DWord
` : '# No WSUS server configured'}

# Configure target release version if specified
${policy.targetReleaseVersion ? `
Set-ItemProperty -Path $WUfBPath -Name "TargetReleaseVersion" -Value 1 -Type DWord
Set-ItemProperty -Path $WUfBPath -Name "TargetReleaseVersionInfo" -Value "${policy.targetReleaseVersion}" -Type String
` : '# No target release version specified'}

# Configure pause settings
Set-ItemProperty -Path $WUfBPath -Name "PauseFeatureUpdates" -Value $(if ($${policy.pauseFeatureUpdates}) { 1 } else { 0 }) -Type DWord
Set-ItemProperty -Path $WUfBPath -Name "PauseQualityUpdates" -Value $(if ($${policy.pauseQualityUpdates}) { 1 } else { 0 }) -Type DWord

# Apply Group Policy settings
gpupdate /force

# Restart Windows Update service to apply changes
Restart-Service -Name "wuauserv" -Force

Write-Output "Windows Update policy configured successfully for device: ${policy.deviceId}"
Write-Output "Update Ring: ${policy.updateRing}"
Write-Output "Feature Update Deferral: ${policy.featureUpdateDeferralPeriod} days"
Write-Output "Quality Update Deferral: ${policy.qualityUpdateDeferralPeriod} days"

# Register scheduled task for update compliance reporting
$TaskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-Command \\"& { Get-WUHistory | Export-Csv -Path 'C:\\OpenDirectory\\UpdateHistory.csv' -NoTypeInformation; Invoke-WebRequest -Uri 'https://opendirectory-api/v1/compliance/windows-updates' -Method POST -ContentType 'application/json' -Body (Get-Content 'C:\\OpenDirectory\\UpdateHistory.csv' | ConvertTo-Json) }\\"
$TaskTrigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"
$TaskPrincipal = New-ScheduledTaskPrincipal -UserID "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "OpenDirectory-UpdateCompliance" -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal -Description "OpenDirectory Windows Update Compliance Reporting" -Force
`;
    }

    /**
     * Check Windows Update status and compliance
     */
    async checkUpdateStatus(deviceId) {
        try {
            logger.info(`Checking Windows update status for device: ${deviceId}`);

            const statusScript = `
# Get Windows Update status
Import-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue

$UpdateStatus = @{
    PendingReboot = (Get-WmiObject -Class Win32_ComputerSystem).RebootPending
    AvailableUpdates = @()
    InstalledUpdates = @()
    FailedUpdates = @()
    LastScanTime = (Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Detect" -Name LastSuccessTime -ErrorAction SilentlyContinue).LastSuccessTime
    LastInstallTime = (Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Install" -Name LastSuccessTime -ErrorAction SilentlyContinue).LastSuccessTime
}

# Get available updates
try {
    $AvailableUpdates = Get-WUList -ErrorAction SilentlyContinue
    $UpdateStatus.AvailableUpdates = $AvailableUpdates | Select-Object Title, Size, Description, RebootRequired
} catch {
    Write-Warning "Could not retrieve available updates: $($_)"
}

# Get update history
try {
    $UpdateHistory = Get-WUHistory -Last 30 -ErrorAction SilentlyContinue
    $UpdateStatus.InstalledUpdates = $UpdateHistory | Where-Object {$_.Result -eq "Succeeded"} | Select-Object Title, Date, Description
    $UpdateStatus.FailedUpdates = $UpdateHistory | Where-Object {$_.Result -eq "Failed"} | Select-Object Title, Date, Description, HResult
} catch {
    Write-Warning "Could not retrieve update history: $($_)"
}

# Get Windows version information
$OSInfo = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, WindowsBuildLabEx, TotalPhysicalMemory

$UpdateStatus | Add-Member -NotePropertyName "OSInfo" -NotePropertyValue $OSInfo

$UpdateStatus | ConvertTo-Json -Depth 3
`;

            return {
                success: true,
                deviceId,
                script: statusScript,
                timestamp: new Date().toISOString()
            };

        } catch (error) {
            logger.error('Error checking Windows update status:', error);
            throw error;
        }
    }

    /**
     * Force Windows Update installation
     */
    async forceUpdateInstallation(deviceId, updateIds = []) {
        try {
            logger.info(`Forcing update installation for device: ${deviceId}`);

            const installScript = updateIds.length > 0 ? 
                this.generateSelectiveUpdateScript(updateIds) : 
                this.generateFullUpdateScript();

            await this.auditLogger.log('windows_update_forced', {
                deviceId,
                updateIds,
                timestamp: new Date().toISOString()
            });

            this.emit('updateForced', { deviceId, updateIds });

            return {
                success: true,
                deviceId,
                script: installScript,
                updateIds
            };

        } catch (error) {
            logger.error('Error forcing Windows update installation:', error);
            throw error;
        }
    }

    generateSelectiveUpdateScript(updateIds) {
        return `
# OpenDirectory Selective Windows Update Installation
Import-Module PSWindowsUpdate -Force

$UpdateIDs = @('${updateIds.join("', '")}')

Write-Output "Installing specific updates: $($UpdateIDs -join ', ')"

foreach ($UpdateID in $UpdateIDs) {
    try {
        Install-WindowsUpdate -KBArticleID $UpdateID -AcceptAll -AutoReboot -Verbose
        Write-Output "Successfully initiated installation of update: $UpdateID"
    } catch {
        Write-Error "Failed to install update $UpdateID: $($_)"
    }
}

Write-Output "Selective update installation completed."
`;
    }

    generateFullUpdateScript() {
        return `
# OpenDirectory Full Windows Update Installation
Import-Module PSWindowsUpdate -Force

Write-Output "Starting full Windows Update installation..."

try {
    # Install all available updates
    Get-WUInstall -AcceptAll -AutoReboot -Verbose | Out-String
    Write-Output "All available updates have been installed or scheduled for installation."
} catch {
    Write-Error "Failed to install updates: $($_)"
}

Write-Output "Full update installation completed."
`;
    }

    /**
     * Configure Windows Update maintenance window
     */
    async configureMaintenanceWindow(deviceId, maintenanceConfig) {
        try {
            const config = {
                deviceId,
                enabled: maintenanceConfig.enabled || true,
                startTime: maintenanceConfig.startTime || '02:00',
                duration: maintenanceConfig.duration || 4, // hours
                daysOfWeek: maintenanceConfig.daysOfWeek || ['Sunday'],
                allowRebootDuringMaintenance: maintenanceConfig.allowReboot || true,
                wakeDeviceForMaintenance: maintenanceConfig.wakeDevice || false
            };

            this.maintenanceWindows.set(deviceId, config);

            const maintenanceScript = `
# Configure Windows Update Maintenance Window
$TaskName = "OpenDirectory-MaintenanceWindow"
$StartTime = "${config.startTime}"
$DaysOfWeek = @('${config.daysOfWeek.join("', '")}')

# Remove existing task if it exists
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Create maintenance window scheduled task
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -Command \\"& { Import-Module PSWindowsUpdate; Get-WUInstall -AcceptAll ${config.allowRebootDuringMaintenance ? '-AutoReboot' : ''} -Verbose | Out-File 'C:\\OpenDirectory\\MaintenanceLog.txt' -Append }\\"
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $DaysOfWeek -At $StartTime
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable ${config.wakeDeviceForMaintenance ? '-WakeToRun' : ''}
$Principal = New-ScheduledTaskPrincipal -UserID "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "OpenDirectory Maintenance Window for Windows Updates"

Write-Output "Maintenance window configured successfully"
Write-Output "Schedule: $($DaysOfWeek -join ', ') at $StartTime"
Write-Output "Duration: ${config.duration} hours"
`;

            await this.auditLogger.log('maintenance_window_configured', {
                deviceId,
                config,
                timestamp: new Date().toISOString()
            });

            return {
                success: true,
                deviceId,
                config,
                script: maintenanceScript
            };

        } catch (error) {
            logger.error('Error configuring maintenance window:', error);
            throw error;
        }
    }

    /**
     * Get Windows Update compliance report
     */
    async getComplianceReport(deviceIds = []) {
        try {
            const report = {
                timestamp: new Date().toISOString(),
                devices: [],
                summary: {
                    compliant: 0,
                    nonCompliant: 0,
                    pendingReboot: 0,
                    updatesPending: 0
                }
            };

            // Generate compliance check script
            const complianceScript = `
# Windows Update Compliance Check Script
$ComplianceData = @{
    DeviceId = $env:COMPUTERNAME
    Timestamp = (Get-Date).ToString('o')
    WindowsVersion = (Get-ComputerInfo).WindowsVersion
    LastUpdateScan = (Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Detect" -Name LastSuccessTime -ErrorAction SilentlyContinue).LastSuccessTime
    LastUpdateInstall = (Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Install" -Name LastSuccessTime -ErrorAction SilentlyContinue).LastSuccessTime
    PendingReboot = [bool](Get-ChildItem "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired" -ErrorAction SilentlyContinue)
    AvailableUpdatesCount = 0
    CriticalUpdatesCount = 0
    SecurityUpdatesCount = 0
    FeatureUpdatesCount = 0
}

try {
    $AvailableUpdates = Get-WUList -ErrorAction SilentlyContinue
    $ComplianceData.AvailableUpdatesCount = $AvailableUpdates.Count
    $ComplianceData.CriticalUpdatesCount = ($AvailableUpdates | Where-Object {$_.MsrcSeverity -eq "Critical"}).Count
    $ComplianceData.SecurityUpdatesCount = ($AvailableUpdates | Where-Object {$_.Categories -match "Security"}).Count
    $ComplianceData.FeatureUpdatesCount = ($AvailableUpdates | Where-Object {$_.Categories -match "Feature"}).Count
} catch {
    Write-Warning "Could not retrieve update information"
}

$ComplianceData | ConvertTo-Json -Depth 2
`;

            return {
                success: true,
                complianceScript,
                reportTemplate: report
            };

        } catch (error) {
            logger.error('Error generating compliance report:', error);
            throw error;
        }
    }
}

module.exports = WindowsUpdateService;