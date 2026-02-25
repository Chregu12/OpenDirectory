const { EventEmitter } = require('events');
const logger = require('../utils/logger');
const AuditLogger = require('../audit/AuditLogger');

class LinuxUpdateService extends EventEmitter {
    constructor() {
        super();
        this.auditLogger = new AuditLogger();
        this.updatePolicies = new Map();
        this.packageManagers = new Map();
        this.updateSchedules = new Map();
    }

    /**
     * Configure Linux update policy for multiple package managers
     */
    async configureUpdatePolicy(deviceId, policy) {
        try {
            logger.info(`Configuring Linux update policy for device: ${deviceId}`);
            
            const updatePolicy = {
                deviceId,
                automaticUpdates: policy.automaticUpdates ?? true,
                securityUpdatesOnly: policy.securityUpdatesOnly ?? false,
                unattendedUpgradesEnabled: policy.unattendedUpgradesEnabled ?? true,
                autoRemoveUnused: policy.autoRemoveUnused ?? true,
                downloadUpgradesOnly: policy.downloadUpgradesOnly ?? false,
                installOnShutdown: policy.installOnShutdown ?? false,
                rebootTime: policy.rebootTime || '02:00',
                updateFrequency: policy.updateFrequency || 'daily',
                maintenanceWindow: policy.maintenanceWindow || { start: '02:00', end: '05:00' },
                allowedOrigins: policy.allowedOrigins || [],
                blockedPackages: policy.blockedPackages || [],
                updateRing: policy.updateRing || 'Production',
                packageManagers: policy.packageManagers || {
                    apt: { enabled: true, autoUpdate: true, autoUpgrade: true },
                    yum: { enabled: true, autoUpdate: true, autoUpgrade: true },
                    dnf: { enabled: true, autoUpdate: true, autoUpgrade: true },
                    snap: { enabled: true, autoRefresh: true },
                    flatpak: { enabled: true, autoUpdate: true }
                },
                kernelUpdates: policy.kernelUpdates ?? true,
                firmwareUpdates: policy.firmwareUpdates ?? true,
                distributionUpgrades: policy.distributionUpgrades ?? false,
                notificationEmail: policy.notificationEmail || null,
                maxLogAge: policy.maxLogAge || 30, // days
                bandwidthLimit: policy.bandwidthLimit || null // KB/s
            };

            this.updatePolicies.set(deviceId, updatePolicy);

            // Generate configuration script based on detected package managers
            const configScript = await this.generateLinuxConfigScript(updatePolicy);

            await this.auditLogger.log('linux_update_policy_configured', {
                deviceId,
                policy: updatePolicy,
                timestamp: new Date().toISOString()
            });

            this.emit('policyConfigured', { deviceId, policy: updatePolicy });

            return {
                success: true,
                policyId: `linux-policy-${deviceId}`,
                script: configScript,
                policy: updatePolicy
            };

        } catch (error) {
            logger.error('Error configuring Linux update policy:', error);
            throw error;
        }
    }

    /**
     * Generate comprehensive Linux update configuration script
     */
    async generateLinuxConfigScript(policy) {
        return `#!/bin/bash
# OpenDirectory Linux Update Configuration Script
# Generated on: ${new Date().toISOString()}
# Device ID: ${policy.deviceId}

set -e

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

log_info() {
    echo -e "\${GREEN}[INFO]\${NC} $1"
}

log_warn() {
    echo -e "\${YELLOW}[WARN]\${NC} $1"
}

log_error() {
    echo -e "\${RED}[ERROR]\${NC} $1"
}

# Detect available package managers
detect_package_managers() {
    log_info "Detecting available package managers..."
    
    AVAILABLE_PMS=""
    
    # Check for APT (Debian/Ubuntu)
    if command -v apt-get >/dev/null 2>&1; then
        AVAILABLE_PMS="\$AVAILABLE_PMS apt"
        log_info "APT detected"
    fi
    
    # Check for YUM (RHEL/CentOS 6-7)
    if command -v yum >/dev/null 2>&1; then
        AVAILABLE_PMS="\$AVAILABLE_PMS yum"
        log_info "YUM detected"
    fi
    
    # Check for DNF (Fedora/RHEL/CentOS 8+)
    if command -v dnf >/dev/null 2>&1; then
        AVAILABLE_PMS="\$AVAILABLE_PMS dnf"
        log_info "DNF detected"
    fi
    
    # Check for Snap
    if command -v snap >/dev/null 2>&1; then
        AVAILABLE_PMS="\$AVAILABLE_PMS snap"
        log_info "Snap detected"
    fi
    
    # Check for Flatpak
    if command -v flatpak >/dev/null 2>&1; then
        AVAILABLE_PMS="\$AVAILABLE_PMS flatpak"
        log_info "Flatpak detected"
    fi
    
    # Check for Zypper (openSUSE)
    if command -v zypper >/dev/null 2>&1; then
        AVAILABLE_PMS="\$AVAILABLE_PMS zypper"
        log_info "Zypper detected"
    fi
    
    # Check for Pacman (Arch Linux)
    if command -v pacman >/dev/null 2>&1; then
        AVAILABLE_PMS="\$AVAILABLE_PMS pacman"
        log_info "Pacman detected"
    fi
    
    echo "\$AVAILABLE_PMS"
}

# Configure APT (Debian/Ubuntu)
configure_apt() {
    if [[ "\$AVAILABLE_PMS" == *"apt"* ]]; then
        log_info "Configuring APT unattended upgrades..."
        
        # Install unattended-upgrades if not present
        apt-get update
        apt-get install -y unattended-upgrades apt-listchanges
        
        # Configure unattended-upgrades
        cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
// OpenDirectory Unattended Upgrades Configuration
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    ${policy.securityUpdatesOnly ? '' : '"\${distro_id}ESMApps:\${distro_codename}-apps-security";'}
    ${policy.securityUpdatesOnly ? '' : '"\${distro_id}:\${distro_codename}-updates";'}
};

Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::Remove-Unused-Dependencies "${policy.autoRemoveUnused}";
Unattended-Upgrade::Remove-New-Unused-Dependencies "${policy.autoRemoveUnused}";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "${policy.autoRemoveUnused}";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "${policy.rebootTime}";
Unattended-Upgrade::InstallOnShutdown "${policy.installOnShutdown}";
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";

${policy.notificationEmail ? `Unattended-Upgrade::Mail "${policy.notificationEmail}";` : ''}
${policy.notificationEmail ? 'Unattended-Upgrade::MailOnlyOnError "false";' : ''}

// Package blacklist
Unattended-Upgrade::Package-Blacklist {
${policy.blockedPackages.map(pkg => `    "${pkg}";`).join('\n')}
};
EOF
        
        # Configure auto-updates
        cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "${policy.automaticUpdates ? '1' : '0'}";
APT::Periodic::Unattended-Upgrade "${policy.unattendedUpgradesEnabled ? '1' : '0'}";
APT::Periodic::Download-Upgradeable-Packages "${policy.downloadUpgradesOnly ? '1' : '0'}";
APT::Periodic::AutocleanInterval "7";
EOF

        # Enable and start unattended-upgrades
        systemctl enable unattended-upgrades
        systemctl start unattended-upgrades
        
        log_info "APT configuration completed"
    fi
}

# Configure YUM (RHEL/CentOS 6-7)
configure_yum() {
    if [[ "\$AVAILABLE_PMS" == *"yum"* ]]; then
        log_info "Configuring YUM automatic updates..."
        
        # Install yum-cron
        yum install -y yum-cron
        
        # Configure yum-cron
        cat > /etc/yum/yum-cron.conf << EOF
[commands]
update_cmd = ${policy.securityUpdatesOnly ? 'security' : 'default'}
update_messages = yes
download_updates = yes
apply_updates = ${policy.automaticUpdates ? 'yes' : 'no'}
random_sleep = 360

[emitters]
system_name = ${policy.deviceId}
${policy.notificationEmail ? `emit_via = email` : 'emit_via = stdio'}
output_width = 80

[email]
${policy.notificationEmail ? `email_from = root@${policy.deviceId}` : ''}
${policy.notificationEmail ? `email_to = ${policy.notificationEmail}` : ''}
${policy.notificationEmail ? 'email_host = localhost' : ''}

[groups]
group_list = None
group_package_types = mandatory, default

[base]
debuglevel = -2
mdpolicy = group:main
exclude = ${policy.blockedPackages.join(' ')}
EOF
        
        # Enable and start yum-cron
        systemctl enable yum-cron
        systemctl start yum-cron
        
        log_info "YUM configuration completed"
    fi
}

# Configure DNF (Fedora/RHEL/CentOS 8+)
configure_dnf() {
    if [[ "\$AVAILABLE_PMS" == *"dnf"* ]]; then
        log_info "Configuring DNF automatic updates..."
        
        # Install dnf-automatic
        dnf install -y dnf-automatic
        
        # Configure dnf-automatic
        cat > /etc/dnf/automatic.conf << EOF
[commands]
upgrade_type = ${policy.securityUpdatesOnly ? 'security' : 'default'}
random_sleep = 300
network_online_timeout = 60
download_updates = yes
apply_updates = ${policy.automaticUpdates ? 'yes' : 'no'}

[emitters]
emit_via = ${policy.notificationEmail ? 'email' : 'stdio'}
system_name = ${policy.deviceId}

[email]
${policy.notificationEmail ? `email_from = root@${policy.deviceId}` : ''}
${policy.notificationEmail ? `email_to = ${policy.notificationEmail}` : ''}
${policy.notificationEmail ? 'email_host = localhost' : ''}

[base]
debuglevel = 1
exclude = ${policy.blockedPackages.join(' ')}
EOF
        
        # Enable and start dnf-automatic
        systemctl enable dnf-automatic.timer
        systemctl start dnf-automatic.timer
        
        log_info "DNF configuration completed"
    fi
}

# Configure Snap
configure_snap() {
    if [[ "\$AVAILABLE_PMS" == *"snap"* ]] && ${policy.packageManagers.snap.enabled}; then
        log_info "Configuring Snap automatic refreshes..."
        
        if ${policy.packageManagers.snap.autoRefresh}; then
            # Configure automatic refresh
            snap set system refresh.timer=${policy.maintenanceWindow.start}
            snap set system refresh.hold=48h
        else
            # Disable automatic refresh
            snap set system refresh.timer=
        fi
        
        log_info "Snap configuration completed"
    fi
}

# Configure Flatpak
configure_flatpak() {
    if [[ "\$AVAILABLE_PMS" == *"flatpak"* ]] && ${policy.packageManagers.flatpak.enabled}; then
        log_info "Configuring Flatpak automatic updates..."
        
        # Create Flatpak update script
        cat > /usr/local/bin/opendirectory-flatpak-update << 'EOF'
#!/bin/bash
# OpenDirectory Flatpak Update Script

if ${policy.packageManagers.flatpak.autoUpdate}; then
    echo "Updating Flatpak applications..."
    flatpak update -y --noninteractive
    flatpak uninstall --unused -y --noninteractive
    echo "Flatpak update completed at $(date)" >> /var/log/opendirectory-flatpak.log
else
    echo "Flatpak automatic updates disabled"
fi
EOF
        
        chmod +x /usr/local/bin/opendirectory-flatpak-update
        
        # Create systemd timer for Flatpak updates
        cat > /etc/systemd/system/opendirectory-flatpak-update.service << EOF
[Unit]
Description=OpenDirectory Flatpak Update
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/opendirectory-flatpak-update
StandardOutput=journal
StandardError=journal
EOF
        
        cat > /etc/systemd/system/opendirectory-flatpak-update.timer << EOF
[Unit]
Description=Run OpenDirectory Flatpak Update Daily
Requires=opendirectory-flatpak-update.service

[Timer]
OnCalendar=${policy.updateFrequency}
Persistent=true

[Install]
WantedBy=timers.target
EOF
        
        systemctl daemon-reload
        systemctl enable opendirectory-flatpak-update.timer
        systemctl start opendirectory-flatpak-update.timer
        
        log_info "Flatpak configuration completed"
    fi
}

# Configure system maintenance
configure_maintenance() {
    log_info "Setting up system maintenance tasks..."
    
    # Create comprehensive maintenance script
    cat > /usr/local/bin/opendirectory-maintenance << 'EOF'
#!/bin/bash
# OpenDirectory Linux System Maintenance

echo "Starting OpenDirectory maintenance at $(date)"

# Update package caches
if command -v apt-get >/dev/null 2>&1; then
    apt-get update
fi

if command -v yum >/dev/null 2>&1; then
    yum check-update || true
fi

if command -v dnf >/dev/null 2>&1; then
    dnf check-update || true
fi

# Clean package caches
if command -v apt-get >/dev/null 2>&1; then
    apt-get autoclean
    apt-get autoremove -y
fi

if command -v yum >/dev/null 2>&1; then
    yum clean all
fi

if command -v dnf >/dev/null 2>&1; then
    dnf clean all
fi

# Update Snap packages
if command -v snap >/dev/null 2>&1 && ${policy.packageManagers.snap.autoRefresh}; then
    snap refresh
fi

# Update Flatpak applications
if command -v flatpak >/dev/null 2>&1 && ${policy.packageManagers.flatpak.autoUpdate}; then
    flatpak update -y --noninteractive
fi

# Generate system inventory
cat > /var/log/opendirectory-system-inventory.json << INVENTORY
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "hostname": "$(hostname)",
    "kernel": "$(uname -r)",
    "distribution": "$(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\\"')",
    "uptime": "$(uptime -p)",
    "lastReboot": "$(who -b | awk '{print \$3, \$4}')",
    "packages": {
        "apt": $(if command -v dpkg >/dev/null 2>&1; then dpkg-query -f='.\n' -W | wc -l; else echo "null"; fi),
        "rpm": $(if command -v rpm >/dev/null 2>&1; then rpm -qa | wc -l; else echo "null"; fi),
        "snap": $(if command -v snap >/dev/null 2>&1; then snap list | tail -n +2 | wc -l; else echo "null"; fi),
        "flatpak": $(if command -v flatpak >/dev/null 2>&1; then flatpak list --app | wc -l; else echo "null"; fi)
    }
}
INVENTORY

echo "OpenDirectory maintenance completed at $(date)"
EOF
    
    chmod +x /usr/local/bin/opendirectory-maintenance
    
    # Create maintenance timer
    cat > /etc/systemd/system/opendirectory-maintenance.service << EOF
[Unit]
Description=OpenDirectory System Maintenance
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/opendirectory-maintenance
StandardOutput=journal
StandardError=journal
EOF
    
    cat > /etc/systemd/system/opendirectory-maintenance.timer << EOF
[Unit]
Description=Run OpenDirectory Maintenance
Requires=opendirectory-maintenance.service

[Timer]
OnCalendar=*-*-* ${policy.maintenanceWindow.start}:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    systemctl daemon-reload
    systemctl enable opendirectory-maintenance.timer
    systemctl start opendirectory-maintenance.timer
}

# Configure update monitoring
configure_monitoring() {
    log_info "Setting up update monitoring..."
    
    cat > /usr/local/bin/opendirectory-update-status << 'EOF'
#!/bin/bash
# OpenDirectory Update Status Monitor

STATUS_FILE="/tmp/opendirectory-update-status.json"

# Get distribution info
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO_NAME="\$PRETTY_NAME"
    DISTRO_VERSION="\$VERSION_ID"
else
    DISTRO_NAME="Unknown"
    DISTRO_VERSION="Unknown"
fi

# Count available updates
UPDATES_AVAILABLE=0
SECURITY_UPDATES=0

if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    UPDATES_AVAILABLE=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo "0")
    SECURITY_UPDATES=$(apt list --upgradable 2>/dev/null | grep -c security || echo "0")
elif command -v dnf >/dev/null 2>&1; then
    UPDATES_AVAILABLE=$(dnf check-update -q | wc -l || echo "0")
    SECURITY_UPDATES=$(dnf check-update --security -q | wc -l || echo "0")
elif command -v yum >/dev/null 2>&1; then
    UPDATES_AVAILABLE=$(yum check-update -q | wc -l || echo "0")
    SECURITY_UPDATES=$(yum check-update --security -q | wc -l || echo "0")
fi

# Generate status JSON
cat > "\$STATUS_FILE" << JSON
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "deviceId": "$(hostname)",
    "platform": "Linux",
    "distribution": "\$DISTRO_NAME",
    "version": "\$DISTRO_VERSION",
    "kernel": "$(uname -r)",
    "uptime": "$(uptime -p)",
    "updates": {
        "available": \$UPDATES_AVAILABLE,
        "security": \$SECURITY_UPDATES,
        "lastCheck": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
    },
    "packageManagers": {
        "apt": $(if command -v apt-get >/dev/null 2>&1; then echo "true"; else echo "false"; fi),
        "yum": $(if command -v yum >/dev/null 2>&1; then echo "true"; else echo "false"; fi),
        "dnf": $(if command -v dnf >/dev/null 2>&1; then echo "true"; else echo "false"; fi),
        "snap": $(if command -v snap >/dev/null 2>&1; then echo "true"; else echo "false"; fi),
        "flatpak": $(if command -v flatpak >/dev/null 2>&1; then echo "true"; else echo "false"; fi)
    },
    "services": {
        "unattendedUpgrades": $(if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then echo "true"; else echo "false"; fi),
        "yumCron": $(if systemctl is-active --quiet yum-cron 2>/dev/null; then echo "true"; else echo "false"; fi),
        "dnfAutomatic": $(if systemctl is-active --quiet dnf-automatic.timer 2>/dev/null; then echo "true"; else echo "false"; fi)
    }
}
JSON

echo "Update status report generated: \$STATUS_FILE"

# Send to OpenDirectory API if configured
if [ -n "\$OPENDIRECTORY_API_URL" ] && [ -n "\$OPENDIRECTORY_API_TOKEN" ]; then
    curl -X POST "\$OPENDIRECTORY_API_URL/v1/compliance/linux-updates" \\
         -H "Content-Type: application/json" \\
         -H "Authorization: Bearer \$OPENDIRECTORY_API_TOKEN" \\
         -d @"\$STATUS_FILE"
fi
EOF
    
    chmod +x /usr/local/bin/opendirectory-update-status
}

# Main configuration execution
log_info "Starting Linux update configuration for device: ${policy.deviceId}"

AVAILABLE_PMS=$(detect_package_managers)

# Create OpenDirectory directories
mkdir -p /var/log/opendirectory
mkdir -p /etc/opendirectory

# Configure each detected package manager
configure_apt
configure_yum
configure_dnf
configure_snap
configure_flatpak
configure_maintenance
configure_monitoring

# Run initial status check
/usr/local/bin/opendirectory-update-status

log_info "Linux update configuration completed successfully"
log_info "Update Ring: ${policy.updateRing}"
log_info "Automatic Updates: ${policy.automaticUpdates}"
log_info "Security Updates Only: ${policy.securityUpdatesOnly}"
log_info "Available Package Managers: \$AVAILABLE_PMS"

exit 0
`;
    }

    /**
     * Check Linux update status
     */
    async checkUpdateStatus(deviceId) {
        try {
            logger.info(`Checking Linux update status for device: ${deviceId}`);

            const statusScript = `#!/bin/bash
# Linux Update Status Check

set -e

# Function to detect package manager and get update info
get_update_status() {
    local updates_available=0
    local security_updates=0
    local package_manager="unknown"
    
    if command -v apt-get >/dev/null 2>&1; then
        package_manager="apt"
        apt-get update -qq 2>/dev/null || true
        updates_available=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || echo "0")
        security_updates=$(apt list --upgradable 2>/dev/null | grep -c "security" || echo "0")
    elif command -v dnf >/dev/null 2>&1; then
        package_manager="dnf"
        updates_available=$(dnf check-update -q 2>/dev/null | wc -l || echo "0")
        security_updates=$(dnf check-update --security -q 2>/dev/null | wc -l || echo "0")
    elif command -v yum >/dev/null 2>&1; then
        package_manager="yum"
        updates_available=$(yum check-update -q 2>/dev/null | wc -l || echo "0")
        security_updates=$(yum check-update --security -q 2>/dev/null | wc -l || echo "0")
    fi
    
    echo "{\\"packageManager\\": \\"$package_manager\\", \\"available\\": $updates_available, \\"security\\": $security_updates}"
}

# Get distribution information
if [ -f /etc/os-release ]; then
    . /etc/os-release
    distro_name="$PRETTY_NAME"
    distro_version="$VERSION_ID"
else
    distro_name="Unknown"
    distro_version="Unknown"
fi

update_info=$(get_update_status)

cat << EOF
{
    "deviceId": "$(hostname)",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "platform": "Linux",
    "distribution": "$distro_name",
    "version": "$distro_version",
    "kernel": "$(uname -r)",
    "uptime": "$(uptime -p)",
    "lastBoot": "$(who -b | awk '{print \$3, \$4}')",
    "updates": $update_info,
    "services": {
        "unattendedUpgrades": $(if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then echo "true"; else echo "false"; fi),
        "yumCron": $(if systemctl is-active --quiet yum-cron 2>/dev/null; then echo "true"; else echo "false"; fi),
        "dnfAutomatic": $(if systemctl is-active --quiet dnf-automatic.timer 2>/dev/null; then echo "true"; else echo "false"; fi)
    },
    "packageCounts": {
        "dpkg": $(if command -v dpkg >/dev/null 2>&1; then dpkg-query -f='.\n' -W | wc -l; else echo "null"; fi),
        "rpm": $(if command -v rpm >/dev/null 2>&1; then rpm -qa | wc -l; else echo "null"; fi),
        "snap": $(if command -v snap >/dev/null 2>&1; then snap list | tail -n +2 | wc -l; else echo "null"; fi),
        "flatpak": $(if command -v flatpak >/dev/null 2>&1; then flatpak list --app | wc -l; else echo "null"; fi)
    }
}
EOF
`;

            return {
                success: true,
                deviceId,
                script: statusScript,
                timestamp: new Date().toISOString()
            };

        } catch (error) {
            logger.error('Error checking Linux update status:', error);
            throw error;
        }
    }

    /**
     * Force Linux update installation
     */
    async forceUpdateInstallation(deviceId, options = {}) {
        try {
            logger.info(`Forcing update installation for Linux device: ${deviceId}`);

            const {
                securityOnly = false,
                packageManagers = ['all'],
                reboot = false
            } = options;

            const installScript = `#!/bin/bash
# OpenDirectory Force Linux Update Installation
# Device ID: ${deviceId}
# Security Only: ${securityOnly}
# Package Managers: ${packageManagers.join(', ')}

set -e

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >&2
}

log_info "Starting forced update installation..."

# APT updates (Debian/Ubuntu)
if ([ "\${packageManagers.includes('all')}" = "true" ] || [ "\${packageManagers.includes('apt')}" = "true" ]) && command -v apt-get >/dev/null 2>&1; then
    log_info "Updating with APT..."
    apt-get update
    ${securityOnly ? 
        'apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" $(apt-get --just-print upgrade | grep "^Inst.*security" | cut -d" " -f2)' :
        'apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"'
    }
    apt-get autoremove -y
    apt-get autoclean
fi

# DNF updates (Fedora/RHEL 8+)
if ([ "\${packageManagers.includes('all')}" = "true" ] || [ "\${packageManagers.includes('dnf')}" = "true" ]) && command -v dnf >/dev/null 2>&1; then
    log_info "Updating with DNF..."
    ${securityOnly ? 'dnf upgrade -y --security' : 'dnf upgrade -y'}
    dnf autoremove -y
    dnf clean all
fi

# YUM updates (RHEL/CentOS 6-7)
if ([ "\${packageManagers.includes('all')}" = "true" ] || [ "\${packageManagers.includes('yum')}" = "true" ]) && command -v yum >/dev/null 2>&1; then
    log_info "Updating with YUM..."
    ${securityOnly ? 'yum update -y --security' : 'yum update -y'}
    yum autoremove -y
    yum clean all
fi

# Snap updates
if ([ "\${packageManagers.includes('all')}" = "true" ] || [ "\${packageManagers.includes('snap')}" = "true" ]) && command -v snap >/dev/null 2>&1; then
    log_info "Updating Snap packages..."
    snap refresh
fi

# Flatpak updates
if ([ "\${packageManagers.includes('all')}" = "true" ] || [ "\${packageManagers.includes('flatpak')}" = "true" ]) && command -v flatpak >/dev/null 2>&1; then
    log_info "Updating Flatpak applications..."
    flatpak update -y --noninteractive
    flatpak uninstall --unused -y --noninteractive
fi

log_info "Update installation completed"

${reboot ? `
log_info "Rebooting system as requested..."
shutdown -r +1 "System reboot scheduled by OpenDirectory after updates"
` : ''}
`;

            await this.auditLogger.log('linux_update_forced', {
                deviceId,
                options,
                timestamp: new Date().toISOString()
            });

            this.emit('updateForced', { deviceId, options });

            return {
                success: true,
                deviceId,
                script: installScript,
                options
            };

        } catch (error) {
            logger.error('Error forcing Linux update installation:', error);
            throw error;
        }
    }

    /**
     * Get Linux compliance report
     */
    async getComplianceReport(deviceIds = []) {
        try {
            const complianceScript = `#!/bin/bash
# Linux Update Compliance Report

REPORT_FILE="/tmp/linux-compliance-report.json"

# Get distribution info
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO_NAME="$PRETTY_NAME"
    DISTRO_VERSION="$VERSION_ID"
else
    DISTRO_NAME="Unknown"
    DISTRO_VERSION="Unknown"
fi

# Get update information based on available package manager
get_compliance_info() {
    local updates_available=0
    local security_updates=0
    local last_update="Unknown"
    
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq 2>/dev/null || true
        updates_available=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || echo "0")
        security_updates=$(apt list --upgradable 2>/dev/null | grep -c "security" || echo "0")
        last_update=$(stat -c %y /var/log/apt/history.log 2>/dev/null | cut -d' ' -f1 || echo "Unknown")
    elif command -v dnf >/dev/null 2>&1; then
        updates_available=$(dnf check-update -q 2>/dev/null | wc -l || echo "0")
        security_updates=$(dnf check-update --security -q 2>/dev/null | wc -l || echo "0")
        last_update=$(rpm -qa --last | head -1 | awk '{print $3}' || echo "Unknown")
    elif command -v yum >/dev/null 2>&1; then
        updates_available=$(yum check-update -q 2>/dev/null | wc -l || echo "0")
        security_updates=$(yum check-update --security -q 2>/dev/null | wc -l || echo "0")
        last_update=$(rpm -qa --last | head -1 | awk '{print $3}' || echo "Unknown")
    fi
    
    echo "{\\"available\\": $updates_available, \\"security\\": $security_updates, \\"lastUpdate\\": \\"$last_update\\"}"
}

compliance_info=$(get_compliance_info)

cat > "$REPORT_FILE" << EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "deviceId": "$(hostname)",
    "platform": "Linux",
    "distribution": "$DISTRO_NAME",
    "version": "$DISTRO_VERSION",
    "kernel": "$(uname -r)",
    "uptime": "$(uptime -p)",
    "compliance": $compliance_info,
    "services": {
        "automaticUpdatesEnabled": $(if systemctl is-enabled --quiet unattended-upgrades 2>/dev/null || systemctl is-enabled --quiet yum-cron 2>/dev/null || systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null; then echo "true"; else echo "false"; fi),
        "maintenanceScheduled": $(if systemctl is-enabled --quiet opendirectory-maintenance.timer 2>/dev/null; then echo "true"; else echo "false"; fi)
    },
    "rebootRequired": $(if [ -f /var/run/reboot-required ]; then echo "true"; else echo "false"; fi)
}
EOF

echo "Compliance report generated: $REPORT_FILE"
cat "$REPORT_FILE"
`;

            return {
                success: true,
                complianceScript,
                timestamp: new Date().toISOString()
            };

        } catch (error) {
            logger.error('Error generating Linux compliance report:', error);
            throw error;
        }
    }
}

module.exports = LinuxUpdateService;