const { EventEmitter } = require('events');

/**
 * Generates platform-specific remediation scripts for detected issues.
 * Produces PowerShell for Windows, bash for macOS/Linux.
 */
class ScriptGenerator extends EventEmitter {
    constructor() {
        super();

        // Script templates indexed by issue type and platform
        this.templates = this._buildTemplates();
    }

    /**
     * Generate a remediation script for a given issue
     */
    generateScript(issue) {
        const platform = (issue.platform || 'windows').toLowerCase();
        const issueType = issue.type;

        const templateFn = this.templates[issueType];
        if (!templateFn) {
            return {
                issueId: issue.id,
                platform,
                language: platform === 'windows' ? 'powershell' : 'bash',
                script: this._generateGenericScript(issue, platform),
                generated: true,
                generatedAt: new Date().toISOString(),
                warning: `No specific template for issue type "${issueType}"; generic script generated`
            };
        }

        const script = templateFn(issue, platform);

        return {
            issueId: issue.id,
            platform,
            language: script.language,
            script: script.content,
            description: script.description,
            requiresReboot: script.requiresReboot || false,
            estimatedDuration: script.estimatedDuration || '5 minutes',
            generated: true,
            generatedAt: new Date().toISOString()
        };
    }

    /**
     * Build all script templates
     */
    _buildTemplates() {
        return {
            'bitlocker-disabled': (issue, platform) => {
                if (platform === 'windows') {
                    return {
                        language: 'powershell',
                        description: 'Enable BitLocker drive encryption on the system drive',
                        requiresReboot: true,
                        estimatedDuration: '30 minutes',
                        content: `# OpenDirectory Auto-Remediation Script
# Issue: BitLocker not enabled
# Device: ${issue.deviceHostname || 'N/A'}
# Generated: ${new Date().toISOString()}
# WARNING: This script requires administrator privileges

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "C:\\OpenDirectory\\Logs\\bitlocker-remediation-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -Append -FilePath $LogFile
    Write-Host "$timestamp - $Message"
}

try {
    # Ensure log directory exists
    New-Item -ItemType Directory -Path "C:\\OpenDirectory\\Logs" -Force | Out-Null

    Write-Log "Starting BitLocker remediation..."

    # Check if TPM is available
    $tpm = Get-Tpm
    if (-not $tpm.TpmPresent) {
        Write-Log "ERROR: TPM is not present on this device. BitLocker requires TPM."
        exit 1
    }

    if (-not $tpm.TpmReady) {
        Write-Log "Initializing TPM..."
        Initialize-Tpm -AllowClear -AllowPhysicalPresence
    }

    # Check current BitLocker status
    $blStatus = Get-BitLockerVolume -MountPoint "C:"

    if ($blStatus.ProtectionStatus -eq "On") {
        Write-Log "BitLocker is already enabled on C: drive."
        exit 0
    }

    Write-Log "Enabling BitLocker on C: drive..."

    # Enable BitLocker with TPM protector
    Enable-BitLocker -MountPoint "C:" \`
        -EncryptionMethod XtsAes256 \`
        -UsedSpaceOnly \`
        -TpmProtector

    # Add recovery password protector
    $recoveryProtector = Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
    $recoveryPassword = ($recoveryProtector.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }).RecoveryPassword

    Write-Log "BitLocker enabled successfully."
    Write-Log "Recovery Password: $recoveryPassword"
    Write-Log "IMPORTANT: Back up the recovery key to Azure AD or save securely."

    # Backup recovery key to AD (if domain joined)
    try {
        $keyProtectors = (Get-BitLockerVolume -MountPoint "C:").KeyProtector
        foreach ($protector in $keyProtectors) {
            if ($protector.KeyProtectorType -eq "RecoveryPassword") {
                Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $protector.KeyProtectorId
                Write-Log "Recovery key backed up to Active Directory."
            }
        }
    } catch {
        Write-Log "WARNING: Could not back up recovery key to AD: $_"
    }

    Write-Log "BitLocker remediation completed. A reboot may be required to start encryption."

} catch {
    Write-Log "ERROR: BitLocker remediation failed: $_"
    exit 1
}`
                    };
                }
                if (platform === 'macos') {
                    return {
                        language: 'bash',
                        description: 'Enable FileVault disk encryption',
                        requiresReboot: true,
                        estimatedDuration: '30 minutes',
                        content: `#!/bin/bash
# OpenDirectory Auto-Remediation Script
# Issue: FileVault not enabled
# Device: ${issue.deviceHostname || 'N/A'}
# Generated: ${new Date().toISOString()}
# WARNING: This script requires root privileges

set -euo pipefail

LOG_DIR="/var/log/opendirectory"
LOG_FILE="$LOG_DIR/filevault-remediation-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "$LOG_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

if [ "$(id -u)" -ne 0 ]; then
    log "ERROR: This script must be run as root."
    exit 1
fi

log "Starting FileVault remediation..."

# Check current FileVault status
FV_STATUS=$(fdesetup status)
log "Current FileVault status: $FV_STATUS"

if echo "$FV_STATUS" | grep -q "FileVault is On"; then
    log "FileVault is already enabled."
    exit 0
fi

# Enable FileVault using deferred enablement (activates at next logout)
log "Enabling FileVault with deferred activation..."
fdesetup enable -defer /var/opendirectory/filevault-recovery-key.plist -forceatlogin 0 -dontaskatlogout

log "FileVault deferred enablement configured."
log "FileVault will be enabled when the user next logs in."
log "Recovery key will be stored at /var/opendirectory/filevault-recovery-key.plist"
log "IMPORTANT: Ensure recovery key is escrowed to MDM server."

exit 0`
                    };
                }
                return {
                    language: 'bash',
                    description: 'Enable LUKS disk encryption',
                    requiresReboot: false,
                    estimatedDuration: '60 minutes',
                    content: `#!/bin/bash
# OpenDirectory Auto-Remediation Script
# Issue: Disk encryption not enabled
# Device: ${issue.deviceHostname || 'N/A'}
# Generated: ${new Date().toISOString()}

echo "WARNING: Enabling full-disk encryption on a running Linux system"
echo "requires careful planning and typically a fresh installation."
echo ""
echo "Recommended steps:"
echo "1. Back up all data"
echo "2. Reinstall with LUKS encryption enabled"
echo "3. Restore data from backup"
echo ""
echo "For non-root partitions, use cryptsetup:"
echo "  cryptsetup luksFormat /dev/sdX"
echo "  cryptsetup open /dev/sdX encrypted_volume"
echo "  mkfs.ext4 /dev/mapper/encrypted_volume"
echo ""
echo "This requires manual intervention. Please contact IT support."
exit 1`
                };
            },

            'missing-updates': (issue, platform) => {
                if (platform === 'windows') {
                    return {
                        language: 'powershell',
                        description: 'Install all pending Windows updates',
                        requiresReboot: true,
                        estimatedDuration: '30-60 minutes',
                        content: `# OpenDirectory Auto-Remediation Script
# Issue: Missing Windows Updates
# Device: ${issue.deviceHostname || 'N/A'}
# Pending updates: ${issue.details?.pendingCount || 'unknown'}
# Generated: ${new Date().toISOString()}

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "C:\\OpenDirectory\\Logs\\update-remediation-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -Append -FilePath $LogFile
    Write-Host "$timestamp - $Message"
}

try {
    New-Item -ItemType Directory -Path "C:\\OpenDirectory\\Logs" -Force | Out-Null

    Write-Log "Starting Windows Update remediation..."

    # Install NuGet provider if needed
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Write-Log "Installing NuGet package provider..."
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    }

    # Install PSWindowsUpdate module if needed
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Log "Installing PSWindowsUpdate module..."
        Install-Module -Name PSWindowsUpdate -Force -Confirm:$false
    }

    Import-Module PSWindowsUpdate

    # Scan for available updates
    Write-Log "Scanning for available updates..."
    $updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot

    if ($updates.Count -eq 0) {
        Write-Log "No updates available."
        exit 0
    }

    Write-Log "Found $($updates.Count) update(s) to install."

    foreach ($update in $updates) {
        Write-Log "  - $($update.Title) (KB$($update.KBArticleIDs -join ', KB'))"
    }

    # Install updates
    Write-Log "Installing updates..."
    Install-WindowsUpdate -AcceptAll -AutoReboot:$false -IgnoreReboot

    Write-Log "Updates installed successfully."

    # Check if reboot is required
    $rebootRequired = (Get-WURebootStatus).RebootRequired
    if ($rebootRequired) {
        Write-Log "A reboot is required to complete the update installation."
        Write-Log "Schedule a reboot during the next maintenance window."
    }

    Write-Log "Update remediation completed."

} catch {
    Write-Log "ERROR: Update remediation failed: $_"
    exit 1
}`
                    };
                }
                if (platform === 'macos') {
                    return {
                        language: 'bash',
                        description: 'Install all pending macOS updates',
                        requiresReboot: true,
                        estimatedDuration: '30-60 minutes',
                        content: `#!/bin/bash
# OpenDirectory Auto-Remediation Script
# Issue: Missing macOS Updates
# Device: ${issue.deviceHostname || 'N/A'}
# Generated: ${new Date().toISOString()}

set -euo pipefail

LOG_DIR="/var/log/opendirectory"
LOG_FILE="$LOG_DIR/update-remediation-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "$LOG_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

if [ "$(id -u)" -ne 0 ]; then
    log "ERROR: This script must be run as root."
    exit 1
fi

log "Starting macOS update remediation..."

# List available updates
log "Checking for available updates..."
softwareupdate --list 2>&1 | tee -a "$LOG_FILE"

# Install all available updates
log "Installing all available updates..."
softwareupdate --install --all --agree-to-license 2>&1 | tee -a "$LOG_FILE"

# Check if restart is required
if softwareupdate --list 2>&1 | grep -q "restart"; then
    log "A restart is required to complete the update installation."
    log "Schedule a restart during the next maintenance window."
fi

log "Update remediation completed."
exit 0`
                    };
                }
                return {
                    language: 'bash',
                    description: 'Install all pending Linux updates',
                    requiresReboot: true,
                    estimatedDuration: '15-30 minutes',
                    content: `#!/bin/bash
# OpenDirectory Auto-Remediation Script
# Issue: Missing Linux Updates
# Device: ${issue.deviceHostname || 'N/A'}
# Generated: ${new Date().toISOString()}

set -euo pipefail

LOG_DIR="/var/log/opendirectory"
LOG_FILE="$LOG_DIR/update-remediation-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "$LOG_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

if [ "$(id -u)" -ne 0 ]; then
    log "ERROR: This script must be run as root."
    exit 1
fi

log "Starting Linux update remediation..."

# Detect package manager
if command -v apt-get &>/dev/null; then
    log "Detected apt package manager"
    apt-get update -y 2>&1 | tee -a "$LOG_FILE"
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y 2>&1 | tee -a "$LOG_FILE"
    apt-get autoremove -y 2>&1 | tee -a "$LOG_FILE"
elif command -v dnf &>/dev/null; then
    log "Detected dnf package manager"
    dnf check-update 2>&1 | tee -a "$LOG_FILE" || true
    dnf upgrade -y 2>&1 | tee -a "$LOG_FILE"
elif command -v yum &>/dev/null; then
    log "Detected yum package manager"
    yum check-update 2>&1 | tee -a "$LOG_FILE" || true
    yum update -y 2>&1 | tee -a "$LOG_FILE"
else
    log "ERROR: No supported package manager found."
    exit 1
fi

# Check if reboot is needed
if [ -f /var/run/reboot-required ]; then
    log "A reboot is required to complete the update installation."
fi

log "Update remediation completed."
exit 0`
                };
            },

            'firewall-disabled': (issue, platform) => {
                if (platform === 'windows') {
                    return {
                        language: 'powershell',
                        description: 'Enable Windows Firewall on all profiles',
                        requiresReboot: false,
                        estimatedDuration: '2 minutes',
                        content: `# OpenDirectory Auto-Remediation Script
# Issue: Windows Firewall disabled
# Device: ${issue.deviceHostname || 'N/A'}
# Generated: ${new Date().toISOString()}

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "C:\\OpenDirectory\\Logs\\firewall-remediation-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -Append -FilePath $LogFile
    Write-Host "$timestamp - $Message"
}

try {
    New-Item -ItemType Directory -Path "C:\\OpenDirectory\\Logs" -Force | Out-Null

    Write-Log "Starting firewall remediation..."

    # Enable firewall for all profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

    Write-Log "Windows Firewall enabled for all profiles (Domain, Public, Private)."

    # Verify
    $profiles = Get-NetFirewallProfile
    foreach ($profile in $profiles) {
        Write-Log "  $($profile.Name): Enabled=$($profile.Enabled)"
    }

    # Enable logging
    Set-NetFirewallProfile -Profile Domain,Public,Private \`
        -LogAllowed True \`
        -LogBlocked True \`
        -LogFileName "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log"

    Write-Log "Firewall logging enabled."
    Write-Log "Firewall remediation completed."

} catch {
    Write-Log "ERROR: Firewall remediation failed: $_"
    exit 1
}`
                    };
                }
                if (platform === 'macos') {
                    return {
                        language: 'bash',
                        description: 'Enable macOS Application Firewall',
                        requiresReboot: false,
                        estimatedDuration: '2 minutes',
                        content: `#!/bin/bash
# OpenDirectory Auto-Remediation Script
# Issue: macOS Firewall disabled
# Device: ${issue.deviceHostname || 'N/A'}
# Generated: ${new Date().toISOString()}

set -euo pipefail

LOG_DIR="/var/log/opendirectory"
LOG_FILE="$LOG_DIR/firewall-remediation-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "$LOG_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

if [ "$(id -u)" -ne 0 ]; then
    log "ERROR: This script must be run as root."
    exit 1
fi

log "Starting firewall remediation..."

# Enable the application firewall
/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
log "Application Firewall enabled."

# Enable stealth mode
/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
log "Stealth mode enabled."

# Enable logging
/usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on
log "Firewall logging enabled."

# Verify
STATUS=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate)
log "Firewall status: $STATUS"

log "Firewall remediation completed."
exit 0`
                    };
                }
                return {
                    language: 'bash',
                    description: 'Enable and configure UFW or firewalld',
                    requiresReboot: false,
                    estimatedDuration: '5 minutes',
                    content: `#!/bin/bash
# OpenDirectory Auto-Remediation Script
# Issue: Linux Firewall disabled
# Device: ${issue.deviceHostname || 'N/A'}
# Generated: ${new Date().toISOString()}

set -euo pipefail

LOG_DIR="/var/log/opendirectory"
LOG_FILE="$LOG_DIR/firewall-remediation-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "$LOG_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

if [ "$(id -u)" -ne 0 ]; then
    log "ERROR: This script must be run as root."
    exit 1
fi

log "Starting firewall remediation..."

if command -v ufw &>/dev/null; then
    log "Detected UFW"
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw logging on
    log "UFW enabled with default deny incoming policy."
elif command -v firewall-cmd &>/dev/null; then
    log "Detected firewalld"
    systemctl enable --now firewalld
    firewall-cmd --set-default-zone=public
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --reload
    log "firewalld enabled with public zone."
else
    log "ERROR: No supported firewall tool found (ufw or firewalld)."
    exit 1
fi

log "Firewall remediation completed."
exit 0`
                };
            },

            'edr-missing': (issue, platform) => {
                if (platform === 'windows') {
                    return {
                        language: 'powershell',
                        description: 'Install and configure EDR agent (Windows Defender for Endpoint)',
                        requiresReboot: false,
                        estimatedDuration: '10 minutes',
                        content: `# OpenDirectory Auto-Remediation Script
# Issue: EDR agent not installed
# Device: ${issue.deviceHostname || 'N/A'}
# Generated: ${new Date().toISOString()}

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "C:\\OpenDirectory\\Logs\\edr-remediation-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -Append -FilePath $LogFile
    Write-Host "$timestamp - $Message"
}

try {
    New-Item -ItemType Directory -Path "C:\\OpenDirectory\\Logs" -Force | Out-Null

    Write-Log "Starting EDR agent remediation..."

    # Ensure Windows Defender is enabled
    Write-Log "Checking Windows Defender status..."
    $defenderStatus = Get-MpComputerStatus

    if (-not $defenderStatus.AntivirusEnabled) {
        Write-Log "Enabling Windows Defender Antivirus..."
        Set-MpPreference -DisableRealtimeMonitoring $false
    }

    # Enable real-time protection
    Set-MpPreference -DisableRealtimeMonitoring $false
    Write-Log "Real-time protection enabled."

    # Enable cloud-delivered protection
    Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -SubmitSamplesConsent SendAllSamples
    Write-Log "Cloud-delivered protection enabled."

    # Enable tamper protection check
    Write-Log "Checking tamper protection status..."

    # Update definitions
    Write-Log "Updating virus definitions..."
    Update-MpSignature
    Write-Log "Virus definitions updated."

    # Run quick scan
    Write-Log "Running quick scan..."
    Start-MpScan -ScanType QuickScan
    Write-Log "Quick scan completed."

    # Verify
    $status = Get-MpComputerStatus
    Write-Log "Defender Status:"
    Write-Log "  Antivirus Enabled: $($status.AntivirusEnabled)"
    Write-Log "  Real-time Protection: $($status.RealTimeProtectionEnabled)"
    Write-Log "  Antivirus Signature Age: $($status.AntivirusSignatureAge) day(s)"

    Write-Log "EDR remediation completed."

} catch {
    Write-Log "ERROR: EDR remediation failed: $_"
    exit 1
}`
                    };
                }
                return {
                    language: 'bash',
                    description: 'Install EDR agent',
                    requiresReboot: false,
                    estimatedDuration: '10 minutes',
                    content: `#!/bin/bash
# OpenDirectory Auto-Remediation Script
# Issue: EDR agent not installed
# Device: ${issue.deviceHostname || 'N/A'}
# Platform: ${platform}
# Generated: ${new Date().toISOString()}

set -euo pipefail

LOG_DIR="/var/log/opendirectory"
LOG_FILE="$LOG_DIR/edr-remediation-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "$LOG_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "Starting EDR agent remediation..."
log "Platform: ${platform}"

# NOTE: Replace the download URL with your organization's EDR agent package
EDR_PACKAGE_URL="\${EDR_PACKAGE_URL:-https://packages.example.com/edr-agent/latest}"
EDR_ONBOARDING_KEY="\${EDR_ONBOARDING_KEY:-}"

log "Downloading EDR agent package..."
log "Package URL: $EDR_PACKAGE_URL"

# Download and install based on platform
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

curl -sL "$EDR_PACKAGE_URL" -o edr-agent-installer

if [ "${platform}" = "macos" ]; then
    log "Installing EDR agent for macOS..."
    # For .pkg files
    # installer -pkg edr-agent-installer.pkg -target /
    log "NOTE: Replace this with your actual EDR vendor install command."
else
    log "Installing EDR agent for Linux..."
    chmod +x edr-agent-installer
    # ./edr-agent-installer --onboarding-key "$EDR_ONBOARDING_KEY"
    log "NOTE: Replace this with your actual EDR vendor install command."
fi

# Cleanup
cd /
rm -rf "$TEMP_DIR"

log "EDR agent installation script completed."
log "Verify agent status with your EDR management console."
exit 0`
                };
            },

            'password-expired': (issue, platform) => {
                if (platform === 'windows') {
                    return {
                        language: 'powershell',
                        description: 'Force password reset on next login',
                        requiresReboot: false,
                        estimatedDuration: '2 minutes',
                        content: `# OpenDirectory Auto-Remediation Script
# Issue: Password expired or needs reset
# Device: ${issue.deviceHostname || 'N/A'}
# User: ${issue.details?.username || 'N/A'}
# Generated: ${new Date().toISOString()}

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$username = "${issue.details?.username || '$env:USERNAME'}"
$LogFile = "C:\\OpenDirectory\\Logs\\password-remediation-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -Append -FilePath $LogFile
    Write-Host "$timestamp - $Message"
}

try {
    New-Item -ItemType Directory -Path "C:\\OpenDirectory\\Logs" -Force | Out-Null

    Write-Log "Starting password remediation for user: $username"

    # Force password change at next logon
    $user = Get-LocalUser -Name $username -ErrorAction Stop
    Set-LocalUser -Name $username -PasswordNeverExpires $false
    $user | Set-LocalUser -AccountExpires (Get-Date).AddDays(1)

    # For AD-joined machines, use AD cmdlets
    if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
        Write-Log "Machine is domain-joined. Setting AD user password to expire..."
        try {
            Set-ADUser -Identity $username -ChangePasswordAtLogon $true
            Write-Log "AD user $username will be required to change password at next logon."
        } catch {
            Write-Log "WARNING: Could not set AD password policy. User may need manual reset: $_"
        }
    } else {
        # Local user - force password change
        net user $username /logonpasswordchg:yes
        Write-Log "Local user $username will be required to change password at next logon."
    }

    Write-Log "Password remediation completed."

} catch {
    Write-Log "ERROR: Password remediation failed: $_"
    exit 1
}`
                    };
                }
                return {
                    language: 'bash',
                    description: 'Force password reset on next login',
                    requiresReboot: false,
                    estimatedDuration: '2 minutes',
                    content: `#!/bin/bash
# OpenDirectory Auto-Remediation Script
# Issue: Password expired or needs reset
# Device: ${issue.deviceHostname || 'N/A'}
# User: ${issue.details?.username || 'N/A'}
# Generated: ${new Date().toISOString()}

set -euo pipefail

USERNAME="${issue.details?.username || '$USER'}"
LOG_DIR="/var/log/opendirectory"
LOG_FILE="$LOG_DIR/password-remediation-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "$LOG_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

if [ "$(id -u)" -ne 0 ]; then
    log "ERROR: This script must be run as root."
    exit 1
fi

log "Starting password remediation for user: $USERNAME"

# Force password change at next login
passwd -e "$USERNAME"
log "User $USERNAME password expired. Will be required to change at next login."

log "Password remediation completed."
exit 0`
                };
            },

            'device-reenroll': (issue, platform) => {
                if (platform === 'windows') {
                    return {
                        language: 'powershell',
                        description: 'Re-enroll device in MDM management',
                        requiresReboot: true,
                        estimatedDuration: '15 minutes',
                        content: `# OpenDirectory Auto-Remediation Script
# Issue: Device needs re-enrollment
# Device: ${issue.deviceHostname || 'N/A'}
# Generated: ${new Date().toISOString()}

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "C:\\OpenDirectory\\Logs\\reenroll-remediation-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -Append -FilePath $LogFile
    Write-Host "$timestamp - $Message"
}

try {
    New-Item -ItemType Directory -Path "C:\\OpenDirectory\\Logs" -Force | Out-Null

    Write-Log "Starting device re-enrollment..."

    # Remove existing MDM enrollment
    Write-Log "Removing existing MDM enrollment..."
    $enrollments = Get-ChildItem "HKLM:\\SOFTWARE\\Microsoft\\Enrollments" -ErrorAction SilentlyContinue
    foreach ($enrollment in $enrollments) {
        $enrollmentPath = $enrollment.PSPath
        $upn = (Get-ItemProperty $enrollmentPath -Name "UPN" -ErrorAction SilentlyContinue).UPN
        if ($upn) {
            Write-Log "Found enrollment for: $upn"
        }
    }

    # Trigger scheduled task for re-enrollment
    Write-Log "Triggering MDM re-enrollment..."

    # Sync device with Azure AD
    dsregcmd /forcerecovery
    Write-Log "Azure AD recovery initiated."

    # Trigger MDM enrollment
    $enrollmentUrl = "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc"
    Write-Log "MDM enrollment URL: $enrollmentUrl"

    # Force Group Policy update
    gpupdate /force
    Write-Log "Group Policy refreshed."

    Write-Log "Device re-enrollment initiated. A reboot may be required."

} catch {
    Write-Log "ERROR: Re-enrollment failed: $_"
    exit 1
}`
                    };
                }
                return {
                    language: 'bash',
                    description: 'Re-enroll device in MDM management',
                    requiresReboot: false,
                    estimatedDuration: '15 minutes',
                    content: `#!/bin/bash
# OpenDirectory Auto-Remediation Script
# Issue: Device needs re-enrollment
# Device: ${issue.deviceHostname || 'N/A'}
# Platform: ${platform}
# Generated: ${new Date().toISOString()}

set -euo pipefail

LOG_DIR="/var/log/opendirectory"
LOG_FILE="$LOG_DIR/reenroll-remediation-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "$LOG_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

if [ "$(id -u)" -ne 0 ]; then
    log "ERROR: This script must be run as root."
    exit 1
fi

log "Starting device re-enrollment for platform: ${platform}..."

if [ "${platform}" = "macos" ]; then
    log "Removing existing MDM profile..."
    # Remove existing MDM profiles
    profiles remove -all -forced 2>/dev/null || true

    log "Triggering MDM re-enrollment..."
    # Trigger DEP enrollment check
    profiles renew -type enrollment

    log "MDM re-enrollment triggered for macOS."
else
    log "For Linux devices, re-enrollment requires reinstalling the management agent."
    log "Please download the latest agent from your MDM portal and run the installer."
fi

log "Re-enrollment script completed."
exit 0`
                };
            },

            'required-app-missing': (issue, platform) => {
                if (platform === 'windows') {
                    return {
                        language: 'powershell',
                        description: 'Install required application via winget or direct download',
                        requiresReboot: false,
                        estimatedDuration: '10 minutes',
                        content: `# OpenDirectory Auto-Remediation Script
# Issue: Required application missing
# Device: ${issue.deviceHostname || 'N/A'}
# Missing App: ${issue.details?.appName || 'N/A'}
# Generated: ${new Date().toISOString()}

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$appName = "${issue.details?.appName || 'Unknown'}"
$appId = "${issue.details?.wingetId || ''}"
$LogFile = "C:\\OpenDirectory\\Logs\\app-install-remediation-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -Append -FilePath $LogFile
    Write-Host "$timestamp - $Message"
}

try {
    New-Item -ItemType Directory -Path "C:\\OpenDirectory\\Logs" -Force | Out-Null

    Write-Log "Starting application installation remediation..."
    Write-Log "Application: $appName"

    # Check if winget is available
    $wingetAvailable = Get-Command winget -ErrorAction SilentlyContinue

    if ($wingetAvailable -and $appId) {
        Write-Log "Installing $appName via winget (ID: $appId)..."
        winget install --id $appId --accept-package-agreements --accept-source-agreements --silent
        Write-Log "$appName installed successfully via winget."
    } else {
        Write-Log "Winget not available or no app ID provided."
        Write-Log "Attempting installation via Company Portal..."

        # Trigger Intune sync to push required apps
        $intuneSync = New-Object -ComObject Shell.Application
        Write-Log "Triggered Intune sync for required app delivery."
        Write-Log "The app should be delivered within the next sync cycle."
    }

    Write-Log "Application installation remediation completed."

} catch {
    Write-Log "ERROR: Application installation failed: $_"
    exit 1
}`
                    };
                }
                if (platform === 'macos') {
                    return {
                        language: 'bash',
                        description: 'Install required application via brew or MDM',
                        requiresReboot: false,
                        estimatedDuration: '10 minutes',
                        content: `#!/bin/bash
# OpenDirectory Auto-Remediation Script
# Issue: Required application missing
# Device: ${issue.deviceHostname || 'N/A'}
# Missing App: ${issue.details?.appName || 'N/A'}
# Generated: ${new Date().toISOString()}

set -euo pipefail

APP_NAME="${issue.details?.appName || 'Unknown'}"
BREW_NAME="${issue.details?.brewName || ''}"
LOG_DIR="/var/log/opendirectory"
LOG_FILE="$LOG_DIR/app-install-remediation-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "$LOG_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "Starting application installation remediation..."
log "Application: $APP_NAME"

# Try brew if available and brew name provided
if command -v brew &>/dev/null && [ -n "$BREW_NAME" ]; then
    log "Installing $APP_NAME via Homebrew..."
    brew install --cask "$BREW_NAME" 2>&1 | tee -a "$LOG_FILE" || \
    brew install "$BREW_NAME" 2>&1 | tee -a "$LOG_FILE"
    log "$APP_NAME installed successfully via Homebrew."
else
    log "Homebrew not available or no brew package name provided."
    log "Triggering MDM sync to push required applications..."
    profiles renew -type configuration
    log "MDM sync triggered. App should be delivered in next sync cycle."
fi

log "Application installation remediation completed."
exit 0`
                    };
                }
                return {
                    language: 'bash',
                    description: 'Install required application via package manager',
                    requiresReboot: false,
                    estimatedDuration: '10 minutes',
                    content: `#!/bin/bash
# OpenDirectory Auto-Remediation Script
# Issue: Required application missing
# Device: ${issue.deviceHostname || 'N/A'}
# Missing App: ${issue.details?.appName || 'N/A'}
# Package: ${issue.details?.packageName || 'N/A'}
# Generated: ${new Date().toISOString()}

set -euo pipefail

APP_NAME="${issue.details?.appName || 'Unknown'}"
PACKAGE_NAME="${issue.details?.packageName || ''}"
LOG_DIR="/var/log/opendirectory"
LOG_FILE="$LOG_DIR/app-install-remediation-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "$LOG_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

if [ "$(id -u)" -ne 0 ]; then
    log "ERROR: This script must be run as root."
    exit 1
fi

log "Starting application installation remediation..."
log "Application: $APP_NAME"

if [ -z "$PACKAGE_NAME" ]; then
    log "ERROR: No package name specified."
    exit 1
fi

if command -v apt-get &>/dev/null; then
    apt-get update -y
    apt-get install -y "$PACKAGE_NAME" 2>&1 | tee -a "$LOG_FILE"
elif command -v dnf &>/dev/null; then
    dnf install -y "$PACKAGE_NAME" 2>&1 | tee -a "$LOG_FILE"
elif command -v yum &>/dev/null; then
    yum install -y "$PACKAGE_NAME" 2>&1 | tee -a "$LOG_FILE"
else
    log "ERROR: No supported package manager found."
    exit 1
fi

log "Application $APP_NAME installed successfully."
exit 0`
                };
            }
        };
    }

    /**
     * Generate a generic script for unknown issue types
     */
    _generateGenericScript(issue, platform) {
        if (platform === 'windows') {
            return `# OpenDirectory Auto-Remediation Script
# Issue: ${issue.title || issue.type}
# Device: ${issue.deviceHostname || 'N/A'}
# Generated: ${new Date().toISOString()}
# NOTE: This is a generic template. Customize for your environment.

#Requires -RunAsAdministrator

Write-Host "Remediation for: ${issue.title || issue.type}"
Write-Host "Device: ${issue.deviceHostname || 'N/A'}"
Write-Host ""
Write-Host "This issue requires manual investigation and remediation."
Write-Host "Issue details: ${issue.description || 'No additional details'}"
Write-Host ""
Write-Host "Please contact IT support if you need assistance."`;
        }

        return `#!/bin/bash
# OpenDirectory Auto-Remediation Script
# Issue: ${issue.title || issue.type}
# Device: ${issue.deviceHostname || 'N/A'}
# Platform: ${platform}
# Generated: ${new Date().toISOString()}
# NOTE: This is a generic template. Customize for your environment.

echo "Remediation for: ${issue.title || issue.type}"
echo "Device: ${issue.deviceHostname || 'N/A'}"
echo ""
echo "This issue requires manual investigation and remediation."
echo "Issue details: ${issue.description || 'No additional details'}"
echo ""
echo "Please contact IT support if you need assistance."`;
    }

    /**
     * List all available script templates
     */
    getAvailableTemplates() {
        return Object.keys(this.templates).map(type => ({
            type,
            platforms: ['windows', 'macos', 'linux'],
            description: this._getTemplateDescription(type)
        }));
    }

    /**
     * Get human-readable description for a template type
     */
    _getTemplateDescription(type) {
        const descriptions = {
            'bitlocker-disabled': 'Enable disk encryption (BitLocker/FileVault/LUKS)',
            'missing-updates': 'Install all pending OS and software updates',
            'firewall-disabled': 'Enable and configure the system firewall',
            'edr-missing': 'Install and configure the EDR/endpoint protection agent',
            'password-expired': 'Force password reset at next login',
            'device-reenroll': 'Re-enroll device in MDM management',
            'required-app-missing': 'Install a required application'
        };
        return descriptions[type] || 'Custom remediation script';
    }
}

module.exports = ScriptGenerator;
