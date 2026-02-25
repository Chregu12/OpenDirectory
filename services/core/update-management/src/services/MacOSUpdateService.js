const { EventEmitter } = require('events');
const logger = require('../utils/logger');
const AuditLogger = require('../audit/AuditLogger');

class MacOSUpdateService extends EventEmitter {
    constructor() {
        super();
        this.auditLogger = new AuditLogger();
        this.updatePolicies = new Map();
        this.deferralSettings = new Map();
        this.maintenanceSchedules = new Map();
    }

    /**
     * Configure macOS Software Update policy
     */
    async configureUpdatePolicy(deviceId, policy) {
        try {
            logger.info(`Configuring macOS update policy for device: ${deviceId}`);
            
            const updatePolicy = {
                deviceId,
                automaticDownload: policy.automaticDownload ?? true,
                automaticInstallOSUpdates: policy.automaticInstallOSUpdates ?? false,
                automaticInstallAppUpdates: policy.automaticInstallAppUpdates ?? true,
                automaticInstallSecurityUpdates: policy.automaticInstallSecurityUpdates ?? true,
                automaticCheckEnabled: policy.automaticCheckEnabled ?? true,
                criticalUpdateInstallDelay: policy.criticalUpdateDelay ?? 0,
                nonCriticalUpdateDelay: policy.nonCriticalUpdateDelay ?? 7,
                majorOSUpdateDelay: policy.majorOSUpdateDelay ?? 90,
                deferralEndDate: policy.deferralEndDate || null,
                allowedUpdates: policy.allowedUpdates || ['security', 'recommended', 'app-store'],
                blockedUpdates: policy.blockedUpdates || [],
                maintenanceWindowStart: policy.maintenanceWindowStart || '02:00',
                maintenanceWindowEnd: policy.maintenanceWindowEnd || '05:00',
                forceRestartDelay: policy.forceRestartDelay || 3600, // seconds
                userDeferralLimit: policy.userDeferralLimit || 3,
                updateRing: policy.updateRing || 'Production',
                catalogURL: policy.catalogURL || null, // Custom software update catalog
                allowPrereleaseInstallation: policy.allowPrereleaseInstallation ?? false,
                requireAdminToInstall: policy.requireAdminToInstall ?? true,
                allowListCheck: policy.allowListCheck ?? true
            };

            this.updatePolicies.set(deviceId, updatePolicy);

            // Generate configuration script for macOS
            const configScript = this.generateMacOSConfigScript(updatePolicy);

            await this.auditLogger.log('macos_update_policy_configured', {
                deviceId,
                policy: updatePolicy,
                timestamp: new Date().toISOString()
            });

            this.emit('policyConfigured', { deviceId, policy: updatePolicy });

            return {
                success: true,
                policyId: `macos-policy-${deviceId}`,
                script: configScript,
                policy: updatePolicy
            };

        } catch (error) {
            logger.error('Error configuring macOS update policy:', error);
            throw error;
        }
    }

    /**
     * Generate macOS configuration script
     */
    generateMacOSConfigScript(policy) {
        return `#!/bin/bash
# OpenDirectory macOS Update Configuration Script
# Generated on: ${new Date().toISOString()}
# Device ID: ${policy.deviceId}

set -e

echo "Configuring macOS Software Update settings..."

# Function to set system preferences
configure_software_update_preferences() {
    echo "Setting Software Update preferences..."
    
    # Enable/disable automatic checks
    sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist AutomaticCheckEnabled -bool ${policy.automaticCheckEnabled}
    
    # Configure automatic downloads
    sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist AutomaticDownload -bool ${policy.automaticDownload}
    
    # Configure automatic installation of system data files and security updates
    sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist ConfigDataInstall -bool ${policy.automaticInstallSecurityUpdates}
    sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist CriticalUpdateInstall -bool ${policy.automaticInstallSecurityUpdates}
    
    # Configure automatic installation of OS updates
    sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist AutomaticallyInstallMacOSUpdates -bool ${policy.automaticInstallOSUpdates}
    
    # Configure App Store automatic updates
    sudo defaults write /Library/Preferences/com.apple.commerce.plist AutoUpdate -bool ${policy.automaticInstallAppUpdates}
    sudo defaults write /Library/Preferences/com.apple.commerce.plist AutoUpdateRestartRequired -bool ${policy.automaticInstallAppUpdates}
    
    ${policy.catalogURL ? `
    # Set custom Software Update catalog URL
    sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist CatalogURL "${policy.catalogURL}"
    ` : `
    # Use default Apple catalog
    sudo defaults delete /Library/Preferences/com.apple.SoftwareUpdate.plist CatalogURL 2>/dev/null || true
    `}
    
    # Configure prerelease installations
    sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist AllowPreReleaseInstallation -bool ${policy.allowPrereleaseInstallation}
    
    # Require admin authorization for software updates
    sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist restrict-software-update-require-admin-to-install -bool ${policy.requireAdminToInstall}
}

# Function to configure deferral policies
configure_deferral_policies() {
    echo "Configuring update deferral policies..."
    
    # Create deferral configuration file
    cat > /tmp/deferral_config.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CriticalUpdateDelay</key>
    <integer>${policy.criticalUpdateInstallDelay}</integer>
    <key>NonCriticalUpdateDelay</key>
    <integer>${policy.nonCriticalUpdateDelay}</integer>
    <key>MajorOSUpdateDelay</key>
    <integer>${policy.majorOSUpdateDelay}</integer>
    <key>ForceRestartDelay</key>
    <integer>${policy.forceRestartDelay}</integer>
    <key>UserDeferralLimit</key>
    <integer>${policy.userDeferralLimit}</integer>
    ${policy.deferralEndDate ? `
    <key>DeferralEndDate</key>
    <string>${policy.deferralEndDate}</string>
    ` : ''}
</dict>
</plist>
EOF
    
    sudo mv /tmp/deferral_config.plist /Library/Preferences/com.opendirectory.update.deferral.plist
    sudo chown root:wheel /Library/Preferences/com.opendirectory.update.deferral.plist
    sudo chmod 644 /Library/Preferences/com.opendirectory.update.deferral.plist
}

# Function to install/update Homebrew management
setup_homebrew_management() {
    echo "Setting up Homebrew management..."
    
    # Check if Homebrew is installed
    if command -v brew >/dev/null 2>&1; then
        echo "Homebrew detected, configuring management..."
        
        # Create Homebrew update script
        cat > /usr/local/bin/opendirectory-brew-update << 'EOF'
#!/bin/bash
# OpenDirectory Homebrew Update Management

BREW_PATH=$(which brew 2>/dev/null)
if [ -z "$BREW_PATH" ]; then
    # Try common Homebrew paths
    for path in /opt/homebrew/bin/brew /usr/local/bin/brew; do
        if [ -x "$path" ]; then
            BREW_PATH="$path"
            break
        fi
    done
fi

if [ -n "$BREW_PATH" ]; then
    echo "Updating Homebrew packages..."
    $BREW_PATH update
    $BREW_PATH upgrade
    $BREW_PATH cleanup
    
    # Generate update report
    $BREW_PATH list --versions > /var/log/opendirectory-brew-inventory.log
    echo "Homebrew update completed at $(date)" >> /var/log/opendirectory-brew-updates.log
else
    echo "Homebrew not found" >> /var/log/opendirectory-brew-updates.log
fi
EOF
        
        sudo chmod +x /usr/local/bin/opendirectory-brew-update
        
        # Create scheduled job for Homebrew updates
        cat > /tmp/com.opendirectory.homebrew.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.opendirectory.homebrew.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/opendirectory-brew-update</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>2</integer>
        <key>Minute</key>
        <integer>30</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/opendirectory-homebrew.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/opendirectory-homebrew-error.log</string>
</dict>
</plist>
EOF
        
        sudo mv /tmp/com.opendirectory.homebrew.plist /Library/LaunchDaemons/
        sudo chown root:wheel /Library/LaunchDaemons/com.opendirectory.homebrew.plist
        sudo chmod 644 /Library/LaunchDaemons/com.opendirectory.homebrew.plist
        sudo launchctl load /Library/LaunchDaemons/com.opendirectory.homebrew.plist
    else
        echo "Homebrew not installed, skipping Homebrew management setup"
    fi
}

# Function to setup Mac App Store CLI management
setup_mas_management() {
    echo "Setting up Mac App Store management..."
    
    # Check if mas-cli is available
    if command -v mas >/dev/null 2>&1; then
        echo "mas-cli detected, configuring App Store updates..."
        
        # Create App Store update script
        cat > /usr/local/bin/opendirectory-mas-update << 'EOF'
#!/bin/bash
# OpenDirectory Mac App Store Update Management

if command -v mas >/dev/null 2>&1; then
    echo "Updating Mac App Store applications..."
    mas upgrade
    
    # Generate installed apps report
    mas list > /var/log/opendirectory-mas-inventory.log
    echo "Mac App Store update completed at $(date)" >> /var/log/opendirectory-mas-updates.log
else
    echo "mas-cli not available" >> /var/log/opendirectory-mas-updates.log
fi
EOF
        
        sudo chmod +x /usr/local/bin/opendirectory-mas-update
    else
        echo "mas-cli not available, App Store updates will use system preferences"
    fi
}

# Function to create maintenance window scheduled task
setup_maintenance_window() {
    echo "Setting up maintenance window..."
    
    cat > /tmp/com.opendirectory.maintenance.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.opendirectory.maintenance</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/bin/opendirectory-maintenance</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>${policy.maintenanceWindowStart.split(':')[0]}</integer>
        <key>Minute</key>
        <integer>${policy.maintenanceWindowStart.split(':')[1]}</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/opendirectory-maintenance.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/opendirectory-maintenance-error.log</string>
</dict>
</plist>
EOF
    
    # Create maintenance script
    cat > /tmp/opendirectory-maintenance << 'EOF'
#!/bin/bash
# OpenDirectory macOS Maintenance Script

echo "Starting OpenDirectory maintenance window at $(date)"

# Check for system updates
echo "Checking for macOS system updates..."
softwareupdate -l

# Install available updates (if auto-install is enabled)
${policy.automaticInstallOSUpdates ? 'softwareupdate -ia' : 'echo "Automatic OS updates disabled"'}

# Update Homebrew packages
if [ -x "/usr/local/bin/opendirectory-brew-update" ]; then
    /usr/local/bin/opendirectory-brew-update
fi

# Update Mac App Store apps
if [ -x "/usr/local/bin/opendirectory-mas-update" ]; then
    /usr/local/bin/opendirectory-mas-update
fi

# Generate system report
system_profiler SPSoftwareDataType SPApplicationsDataType > /var/log/opendirectory-system-profile.log

echo "OpenDirectory maintenance window completed at $(date)"
EOF
    
    sudo mv /tmp/opendirectory-maintenance /usr/local/bin/
    sudo chmod +x /usr/local/bin/opendirectory-maintenance
    
    sudo mv /tmp/com.opendirectory.maintenance.plist /Library/LaunchDaemons/
    sudo chown root:wheel /Library/LaunchDaemons/com.opendirectory.maintenance.plist
    sudo chmod 644 /Library/LaunchDaemons/com.opendirectory.maintenance.plist
    sudo launchctl load /Library/LaunchDaemons/com.opendirectory.maintenance.plist
}

# Function to create update status monitoring
setup_update_monitoring() {
    echo "Setting up update status monitoring..."
    
    cat > /usr/local/bin/opendirectory-update-status << 'EOF'
#!/bin/bash
# OpenDirectory Update Status Monitor

# Generate JSON status report
cat << JSON > /tmp/opendirectory-update-status.json
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "deviceId": "$(hostname)",
    "systemVersion": "$(sw_vers -productVersion)",
    "buildVersion": "$(sw_vers -buildVersion)",
    "lastUpdateCheck": "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist LastUpdatesAvailable 2>/dev/null || echo 'Unknown')",
    "availableUpdates": $(softwareupdate -l 2>&1 | grep -c "restart" || echo "0"),
    "automaticUpdatesEnabled": $(defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist AutomaticCheckEnabled 2>/dev/null || echo "false"),
    "updateRing": "${policy.updateRing}",
    "homebrewPackages": $(if command -v brew >/dev/null 2>&1; then brew list --versions | wc -l | xargs; else echo "0"; fi),
    "masApplications": $(if command -v mas >/dev/null 2>&1; then mas list | wc -l | xargs; else echo "0"; fi)
}
JSON

# Send status to OpenDirectory API (if configured)
if [ -n "$OPENDIRECTORY_API_URL" ]; then
    curl -X POST "$OPENDIRECTORY_API_URL/v1/compliance/macos-updates" \
         -H "Content-Type: application/json" \
         -H "Authorization: Bearer $OPENDIRECTORY_API_TOKEN" \
         -d @/tmp/opendirectory-update-status.json
fi

# Archive the status
cp /tmp/opendirectory-update-status.json "/var/log/opendirectory-status-$(date +%Y%m%d-%H%M%S).json"
EOF
    
    sudo chmod +x /usr/local/bin/opendirectory-update-status
}

# Main configuration execution
echo "Starting macOS update configuration for device: ${policy.deviceId}"

configure_software_update_preferences
configure_deferral_policies
setup_homebrew_management
setup_mas_management
setup_maintenance_window
setup_update_monitoring

# Create log directory
sudo mkdir -p /var/log/opendirectory
sudo chmod 755 /var/log/opendirectory

echo "macOS update configuration completed successfully"
echo "Update Ring: ${policy.updateRing}"
echo "Automatic OS Updates: ${policy.automaticInstallOSUpdates}"
echo "Automatic App Updates: ${policy.automaticInstallAppUpdates}"
echo "Maintenance Window: ${policy.maintenanceWindowStart} - ${policy.maintenanceWindowEnd}"

# Run initial update check
/usr/local/bin/opendirectory-update-status

exit 0
`;
    }

    /**
     * Check macOS update status
     */
    async checkUpdateStatus(deviceId) {
        try {
            logger.info(`Checking macOS update status for device: ${deviceId}`);

            const statusScript = `#!/bin/bash
# macOS Update Status Check

set -e

echo "{"
echo '  "deviceId": "'$(hostname)'",'
echo '  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",'
echo '  "systemVersion": "'$(sw_vers -productVersion)'",'
echo '  "buildVersion": "'$(sw_vers -buildVersion)'",'
echo '  "productName": "'$(sw_vers -productName)'",'

# Check for available system updates
echo '  "systemUpdates": {'
SYSTEM_UPDATES=$(softwareupdate -l 2>&1)
if echo "$SYSTEM_UPDATES" | grep -q "No new software available"; then
    echo '    "available": [],'
    echo '    "count": 0,'
    echo '    "restartRequired": false'
else
    echo '    "available": ['
    # Parse available updates (simplified)
    echo '    ],'
    echo '    "count": '$(echo "$SYSTEM_UPDATES" | grep -c "restart\\|recommended" || echo "0")','
    echo '    "restartRequired": '$(if echo "$SYSTEM_UPDATES" | grep -q "restart"; then echo "true"; else echo "false"; fi)
fi
echo '  },'

# Check Homebrew status
echo '  "homebrew": {'
if command -v brew >/dev/null 2>&1; then
    echo '    "installed": true,'
    echo '    "packages": '$(brew list --versions | wc -l | xargs)','
    echo '    "outdated": '$(brew outdated | wc -l | xargs)
else
    echo '    "installed": false,'
    echo '    "packages": 0,'
    echo '    "outdated": 0'
fi
echo '  },'

# Check Mac App Store status
echo '  "appStore": {'
if command -v mas >/dev/null 2>&1; then
    echo '    "masInstalled": true,'
    echo '    "applications": '$(mas list | wc -l | xargs)','
    echo '    "outdated": '$(mas outdated | wc -l | xargs)
else
    echo '    "masInstalled": false,'
    echo '    "applications": 0,'
    echo '    "outdated": 0'
fi
echo '  },'

# System preferences
echo '  "preferences": {'
echo '    "automaticCheckEnabled": '$(defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist AutomaticCheckEnabled 2>/dev/null || echo "false")','
echo '    "automaticDownload": '$(defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist AutomaticDownload 2>/dev/null || echo "false")','
echo '    "automaticInstallOSUpdates": '$(defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "false")','
echo '    "automaticInstallAppUpdates": '$(defaults read /Library/Preferences/com.apple.commerce.plist AutoUpdate 2>/dev/null || echo "false")
echo '  }'

echo "}"
`;

            return {
                success: true,
                deviceId,
                script: statusScript,
                timestamp: new Date().toISOString()
            };

        } catch (error) {
            logger.error('Error checking macOS update status:', error);
            throw error;
        }
    }

    /**
     * Force macOS update installation
     */
    async forceUpdateInstallation(deviceId, updateTypes = ['system', 'apps']) {
        try {
            logger.info(`Forcing update installation for macOS device: ${deviceId}`);

            const installScript = `#!/bin/bash
# OpenDirectory Force macOS Update Installation
# Device ID: ${deviceId}
# Update Types: ${updateTypes.join(', ')}

set -e

echo "Starting forced update installation..."

${updateTypes.includes('system') ? `
echo "Installing system updates..."
sudo softwareupdate -ia --verbose
` : ''}

${updateTypes.includes('apps') ? `
if command -v mas >/dev/null 2>&1; then
    echo "Installing App Store updates..."
    mas upgrade
else
    echo "mas-cli not available for App Store updates"
fi
` : ''}

${updateTypes.includes('homebrew') ? `
if command -v brew >/dev/null 2>&1; then
    echo "Updating Homebrew packages..."
    brew update && brew upgrade && brew cleanup
else
    echo "Homebrew not available"
fi
` : ''}

echo "Update installation completed"
`;

            await this.auditLogger.log('macos_update_forced', {
                deviceId,
                updateTypes,
                timestamp: new Date().toISOString()
            });

            this.emit('updateForced', { deviceId, updateTypes });

            return {
                success: true,
                deviceId,
                script: installScript,
                updateTypes
            };

        } catch (error) {
            logger.error('Error forcing macOS update installation:', error);
            throw error;
        }
    }

    /**
     * Configure macOS update deferral
     */
    async configureDeferral(deviceId, deferralConfig) {
        try {
            const config = {
                deviceId,
                enabled: deferralConfig.enabled ?? true,
                systemUpdateDelay: deferralConfig.systemUpdateDelay ?? 7,
                securityUpdateDelay: deferralConfig.securityUpdateDelay ?? 0,
                maxDeferrals: deferralConfig.maxDeferrals ?? 3,
                deferralEndDate: deferralConfig.deferralEndDate || null
            };

            this.deferralSettings.set(deviceId, config);

            const deferralScript = `#!/bin/bash
# Configure macOS Update Deferral Settings

# Create deferral configuration
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist DeferralDays -int ${config.systemUpdateDelay}
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist SecurityUpdateDeferralDays -int ${config.securityUpdateDelay}

# Create enforcement script
cat > /usr/local/bin/opendirectory-deferral-check << 'EOF'
#!/bin/bash

MAX_DEFERRALS=${config.maxDeferrals}
DEFERRAL_COUNT_FILE="/var/log/opendirectory-deferral-count"
${config.deferralEndDate ? `DEFERRAL_END_DATE="${config.deferralEndDate}"` : ''}

# Read current deferral count
if [ -f "$DEFERRAL_COUNT_FILE" ]; then
    CURRENT_DEFERRALS=$(cat "$DEFERRAL_COUNT_FILE")
else
    CURRENT_DEFERRALS=0
fi

# Check if maximum deferrals reached
if [ "$CURRENT_DEFERRALS" -ge "$MAX_DEFERRALS" ]; then
    echo "Maximum deferrals reached. Installing updates..."
    softwareupdate -ia
    echo "0" > "$DEFERRAL_COUNT_FILE"
else
    echo "Deferral allowed. Count: $CURRENT_DEFERRALS/$MAX_DEFERRALS"
fi

${config.deferralEndDate ? `
# Check if deferral end date reached
if [ "$(date +%s)" -gt "$(date -j -f "%Y-%m-%d" "$DEFERRAL_END_DATE" +%s)" ]; then
    echo "Deferral end date reached. Installing updates..."
    softwareupdate -ia
    echo "0" > "$DEFERRAL_COUNT_FILE"
fi
` : ''}
EOF

sudo chmod +x /usr/local/bin/opendirectory-deferral-check

echo "macOS update deferral configured successfully"
`;

            await this.auditLogger.log('macos_deferral_configured', {
                deviceId,
                config,
                timestamp: new Date().toISOString()
            });

            return {
                success: true,
                deviceId,
                config,
                script: deferralScript
            };

        } catch (error) {
            logger.error('Error configuring macOS deferral:', error);
            throw error;
        }
    }

    /**
     * Get macOS compliance report
     */
    async getComplianceReport(deviceIds = []) {
        try {
            const complianceScript = `#!/bin/bash
# macOS Update Compliance Report

REPORT_FILE="/tmp/macos-compliance-report.json"

cat > "$REPORT_FILE" << EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "deviceId": "$(hostname)",
    "platform": "macOS",
    "osVersion": "$(sw_vers -productVersion)",
    "buildVersion": "$(sw_vers -buildVersion)",
    "compliance": {
        "systemUpdatesAvailable": $(softwareupdate -l 2>&1 | grep -c "restart\\|recommended" || echo "0"),
        "securityUpdatesAvailable": $(softwareupdate -l 2>&1 | grep -ci "security" || echo "0"),
        "lastUpdateCheck": "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist LastSuccessfulDate 2>/dev/null || echo 'Unknown')",
        "automaticUpdatesEnabled": $(defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist AutomaticCheckEnabled 2>/dev/null || echo "false"),
        "deferralCount": $([ -f "/var/log/opendirectory-deferral-count" ] && cat "/var/log/opendirectory-deferral-count" || echo "0"),
        "homebrewOutdated": $(if command -v brew >/dev/null 2>&1; then brew outdated | wc -l | xargs; else echo "0"; fi),
        "appStoreOutdated": $(if command -v mas >/dev/null 2>&1; then mas outdated | wc -l | xargs; else echo "0"; fi)
    },
    "policies": {
        "updateRing": "$(defaults read /Library/Preferences/com.opendirectory.update.deferral.plist UpdateRing 2>/dev/null || echo 'Unknown')",
        "deferralEnabled": true
    }
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
            logger.error('Error generating macOS compliance report:', error);
            throw error;
        }
    }
}

module.exports = MacOSUpdateService;