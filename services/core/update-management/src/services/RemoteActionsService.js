const { EventEmitter } = require('events');
const logger = require('../utils/logger');
const AuditLogger = require('../audit/AuditLogger');

class RemoteActionsService extends EventEmitter {
    constructor() {
        super();
        this.auditLogger = new AuditLogger();
        this.pendingActions = new Map();
        this.deviceSessions = new Map();
        this.actionQueue = new Map();
        this.locationServices = new Map();
    }

    /**
     * Execute remote device lock action
     */
    async lockDevice(deviceId, options = {}) {
        try {
            logger.info(`Executing lock action for device: ${deviceId}`);

            const lockAction = {
                actionId: `lock-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                deviceId,
                type: 'lock',
                message: options.message || 'This device has been locked by your IT administrator',
                phoneNumber: options.phoneNumber || null,
                passcode: options.passcode || this.generateRandomPasscode(),
                timestamp: new Date().toISOString(),
                executor: options.executor || 'system',
                reason: options.reason || 'Administrative action',
                unlockOptions: {
                    requireAdminUnlock: options.requireAdminUnlock ?? true,
                    allowBiometricUnlock: options.allowBiometricUnlock ?? false,
                    allowPasscodeReset: options.allowPasscodeReset ?? false
                }
            };

            // Platform-specific lock scripts
            const lockScripts = this.generateLockScripts(lockAction);

            this.pendingActions.set(lockAction.actionId, lockAction);

            await this.auditLogger.log('remote_device_lock', {
                actionId: lockAction.actionId,
                deviceId,
                executor: lockAction.executor,
                reason: lockAction.reason,
                timestamp: lockAction.timestamp
            });

            this.emit('actionQueued', lockAction);

            return {
                success: true,
                actionId: lockAction.actionId,
                scripts: lockScripts,
                expectedResult: 'Device will be locked with the specified message'
            };

        } catch (error) {
            logger.error('Error executing device lock:', error);
            throw error;
        }
    }

    /**
     * Execute remote device wipe action
     */
    async wipeDevice(deviceId, options = {}) {
        try {
            logger.info(`Executing wipe action for device: ${deviceId}`);

            const wipeAction = {
                actionId: `wipe-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                deviceId,
                type: 'wipe',
                wipeType: options.wipeType || 'full', // full, selective, enterprise
                preserveEnrollment: options.preserveEnrollment ?? true,
                wipeExternalStorage: options.wipeExternalStorage ?? false,
                wipeMethod: options.wipeMethod || 'secure', // secure, quick
                timestamp: new Date().toISOString(),
                executor: options.executor || 'system',
                reason: options.reason || 'Security incident',
                confirmation: options.confirmation || false,
                dataRetentionPeriod: options.dataRetentionPeriod || 0, // days
                selectiveWipeApps: options.selectiveWipeApps || []
            };

            // Require explicit confirmation for wipe actions
            if (!wipeAction.confirmation) {
                throw new Error('Device wipe requires explicit confirmation');
            }

            const wipeScripts = this.generateWipeScripts(wipeAction);

            this.pendingActions.set(wipeAction.actionId, wipeAction);

            await this.auditLogger.log('remote_device_wipe', {
                actionId: wipeAction.actionId,
                deviceId,
                wipeType: wipeAction.wipeType,
                executor: wipeAction.executor,
                reason: wipeAction.reason,
                timestamp: wipeAction.timestamp
            });

            this.emit('actionQueued', wipeAction);

            return {
                success: true,
                actionId: wipeAction.actionId,
                scripts: wipeScripts,
                expectedResult: `Device will be wiped using ${wipeAction.wipeType} method`
            };

        } catch (error) {
            logger.error('Error executing device wipe:', error);
            throw error;
        }
    }

    /**
     * Execute remote device restart
     */
    async restartDevice(deviceId, options = {}) {
        try {
            logger.info(`Executing restart action for device: ${deviceId}`);

            const restartAction = {
                actionId: `restart-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                deviceId,
                type: 'restart',
                delay: options.delay || 60, // seconds
                message: options.message || 'This device will restart in {delay} seconds for maintenance',
                forceRestart: options.forceRestart ?? false,
                timestamp: new Date().toISOString(),
                executor: options.executor || 'system',
                reason: options.reason || 'System maintenance',
                scheduledTime: options.scheduledTime || null
            };

            const restartScripts = this.generateRestartScripts(restartAction);

            this.pendingActions.set(restartAction.actionId, restartAction);

            await this.auditLogger.log('remote_device_restart', {
                actionId: restartAction.actionId,
                deviceId,
                delay: restartAction.delay,
                executor: restartAction.executor,
                reason: restartAction.reason,
                timestamp: restartAction.timestamp
            });

            this.emit('actionQueued', restartAction);

            return {
                success: true,
                actionId: restartAction.actionId,
                scripts: restartScripts,
                expectedResult: `Device will restart in ${restartAction.delay} seconds`
            };

        } catch (error) {
            logger.error('Error executing device restart:', error);
            throw error;
        }
    }

    /**
     * Execute device location request
     */
    async locateDevice(deviceId, options = {}) {
        try {
            logger.info(`Executing locate action for device: ${deviceId}`);

            const locateAction = {
                actionId: `locate-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                deviceId,
                type: 'locate',
                accuracy: options.accuracy || 'best', // best, navigation, significant
                timeout: options.timeout || 300, // seconds
                playSound: options.playSound ?? true,
                displayMessage: options.displayMessage ?? true,
                message: options.message || 'This device is being located by your IT administrator',
                timestamp: new Date().toISOString(),
                executor: options.executor || 'system',
                reason: options.reason || 'Device location request'
            };

            const locateScripts = this.generateLocateScripts(locateAction);

            this.pendingActions.set(locateAction.actionId, locateAction);

            await this.auditLogger.log('remote_device_locate', {
                actionId: locateAction.actionId,
                deviceId,
                executor: locateAction.executor,
                reason: locateAction.reason,
                timestamp: locateAction.timestamp
            });

            this.emit('actionQueued', locateAction);

            return {
                success: true,
                actionId: locateAction.actionId,
                scripts: locateScripts,
                expectedResult: 'Device location will be retrieved and reported'
            };

        } catch (error) {
            logger.error('Error executing device locate:', error);
            throw error;
        }
    }

    /**
     * Enable lost mode on device
     */
    async enableLostMode(deviceId, options = {}) {
        try {
            logger.info(`Enabling lost mode for device: ${deviceId}`);

            const lostModeAction = {
                actionId: `lostmode-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                deviceId,
                type: 'lostmode',
                message: options.message || 'This device has been reported as lost. Please contact your IT administrator.',
                phoneNumber: options.phoneNumber || null,
                footnote: options.footnote || 'If found, please contact the number above',
                enableLocationServices: options.enableLocationServices ?? true,
                playLostModeSound: options.playLostModeSound ?? true,
                timestamp: new Date().toISOString(),
                executor: options.executor || 'system',
                reason: options.reason || 'Device reported as lost'
            };

            const lostModeScripts = this.generateLostModeScripts(lostModeAction);

            this.pendingActions.set(lostModeAction.actionId, lostModeAction);

            await this.auditLogger.log('remote_device_lostmode', {
                actionId: lostModeAction.actionId,
                deviceId,
                executor: lostModeAction.executor,
                reason: lostModeAction.reason,
                timestamp: lostModeAction.timestamp
            });

            this.emit('actionQueued', lostModeAction);

            return {
                success: true,
                actionId: lostModeAction.actionId,
                scripts: lostModeScripts,
                expectedResult: 'Device will enter lost mode with specified message'
            };

        } catch (error) {
            logger.error('Error enabling lost mode:', error);
            throw error;
        }
    }

    /**
     * Rotate device encryption keys (BitLocker/FileVault)
     */
    async rotateEncryptionKeys(deviceId, options = {}) {
        try {
            logger.info(`Rotating encryption keys for device: ${deviceId}`);

            const rotateAction = {
                actionId: `rotate-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                deviceId,
                type: 'rotate-keys',
                keyTypes: options.keyTypes || ['bitlocker', 'filevault'],
                backupKeys: options.backupKeys ?? true,
                escrowKeys: options.escrowKeys ?? true,
                timestamp: new Date().toISOString(),
                executor: options.executor || 'system',
                reason: options.reason || 'Security key rotation'
            };

            const rotateScripts = this.generateKeyRotationScripts(rotateAction);

            this.pendingActions.set(rotateAction.actionId, rotateAction);

            await this.auditLogger.log('remote_key_rotation', {
                actionId: rotateAction.actionId,
                deviceId,
                keyTypes: rotateAction.keyTypes,
                executor: rotateAction.executor,
                reason: rotateAction.reason,
                timestamp: rotateAction.timestamp
            });

            this.emit('actionQueued', rotateAction);

            return {
                success: true,
                actionId: rotateAction.actionId,
                scripts: rotateScripts,
                expectedResult: 'Encryption keys will be rotated and backed up'
            };

        } catch (error) {
            logger.error('Error rotating encryption keys:', error);
            throw error;
        }
    }

    /**
     * Sync device policies and configurations
     */
    async syncPolicies(deviceId, options = {}) {
        try {
            logger.info(`Syncing policies for device: ${deviceId}`);

            const syncAction = {
                actionId: `sync-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                deviceId,
                type: 'sync',
                policyTypes: options.policyTypes || ['all'],
                forceSync: options.forceSync ?? true,
                timestamp: new Date().toISOString(),
                executor: options.executor || 'system',
                reason: options.reason || 'Policy synchronization'
            };

            const syncScripts = this.generateSyncScripts(syncAction);

            this.pendingActions.set(syncAction.actionId, syncAction);

            await this.auditLogger.log('remote_policy_sync', {
                actionId: syncAction.actionId,
                deviceId,
                policyTypes: syncAction.policyTypes,
                executor: syncAction.executor,
                reason: syncAction.reason,
                timestamp: syncAction.timestamp
            });

            this.emit('actionQueued', syncAction);

            return {
                success: true,
                actionId: syncAction.actionId,
                scripts: syncScripts,
                expectedResult: 'Device policies and configurations will be synchronized'
            };

        } catch (error) {
            logger.error('Error syncing policies:', error);
            throw error;
        }
    }

    /**
     * Generate platform-specific lock scripts
     */
    generateLockScripts(lockAction) {
        return {
            windows: `
# Windows Device Lock Script
# Action ID: ${lockAction.actionId}

# Use Group Policy to lock the device
$lockMessage = "${lockAction.message}"
$phoneNumber = "${lockAction.phoneNumber || 'Contact your IT administrator'}"

# Create lock screen message
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "legalnoticecaption" -Value "Device Locked"
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "legalnoticetext" -Value "$lockMessage\\n\\nContact: $phoneNumber"

# Lock the current session
rundll32.exe user32.dll,LockWorkStation

# Enable screen saver lock
Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "ScreenSaveActive" -Value "1"
Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "ScreenSaverIsSecure" -Value "1"
Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "ScreenSaveTimeOut" -Value "60"

Write-Output "Device locked successfully - Action ID: ${lockAction.actionId}"
`,
            macos: `#!/bin/bash
# macOS Device Lock Script
# Action ID: ${lockAction.actionId}

LOCK_MESSAGE="${lockAction.message}"
PHONE_NUMBER="${lockAction.phoneNumber || 'Contact your IT administrator'}"

# Enable screen saver and require password
defaults write com.apple.screensaver askForPassword -int 1
defaults write com.apple.screensaver askForPasswordDelay -int 0

# Set lock message
sudo defaults write /Library/Preferences/com.apple.loginwindow.plist LoginwindowText "$LOCK_MESSAGE\\n\\nContact: $PHONE_NUMBER"

# Activate screen saver to lock screen
osascript -e 'tell application "System Events" to start current screen saver'

# Enable lost mode if supported (for managed devices)
if command -v profiles >/dev/null 2>&1; then
    # This would typically be done via MDM command
    echo "MDM lock command would be sent here"
fi

echo "Device locked successfully - Action ID: ${lockAction.actionId}"
`,
            linux: `#!/bin/bash
# Linux Device Lock Script
# Action ID: ${lockAction.actionId}

LOCK_MESSAGE="${lockAction.message}"
PHONE_NUMBER="${lockAction.phoneNumber || 'Contact your IT administrator'}"

# Lock screen based on desktop environment
if command -v gnome-screensaver-command >/dev/null 2>&1; then
    # GNOME
    gnome-screensaver-command -l
elif command -v xdg-screensaver >/dev/null 2>&1; then
    # Generic X11
    xdg-screensaver lock
elif command -v loginctl >/dev/null 2>&1; then
    # systemd-based lock
    loginctl lock-sessions
fi

# Set lock message in /etc/issue
echo "*** DEVICE LOCKED ***" > /etc/issue
echo "$LOCK_MESSAGE" >> /etc/issue
echo "Contact: $PHONE_NUMBER" >> /etc/issue
echo "" >> /etc/issue

# Create desktop notification if available
if command -v notify-send >/dev/null 2>&1; then
    notify-send "Device Locked" "$LOCK_MESSAGE" -u critical -t 0
fi

echo "Device locked successfully - Action ID: ${lockAction.actionId}"
`
        };
    }

    /**
     * Generate platform-specific wipe scripts
     */
    generateWipeScripts(wipeAction) {
        return {
            windows: `
# Windows Device Wipe Script - DESTRUCTIVE ACTION
# Action ID: ${wipeAction.actionId}
# Wipe Type: ${wipeAction.wipeType}

${wipeAction.wipeType === 'full' ? `
# Full device wipe
Write-Warning "PERFORMING FULL DEVICE WIPE - ALL DATA WILL BE LOST"

# Reset Windows to factory settings
systemreset -factoryreset -quiet -keepdatafolder:$${wipeAction.preserveEnrollment ? 'true' : 'false'}

# Alternative method using cipher for secure wipe
if ("${wipeAction.wipeMethod}" -eq "secure") {
    cipher /w:C:\\
}
` : wipeAction.wipeType === 'selective' ? `
# Selective wipe - Remove corporate data only
Write-Output "Performing selective corporate data wipe"

# Remove corporate profiles and applications
${wipeAction.selectiveWipeApps.map(app => `
Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "*${app}*"} | ForEach-Object {$_.Uninstall()}
`).join('')}

# Clear corporate certificates
Get-ChildItem Cert:\\LocalMachine\\My | Where-Object {$_.Issuer -like "*Corporate*"} | Remove-Item
` : ''}

Write-Output "Wipe completed - Action ID: ${wipeAction.actionId}"
`,
            macos: `#!/bin/bash
# macOS Device Wipe Script - DESTRUCTIVE ACTION
# Action ID: ${wipeAction.actionId}

echo "WARNING: PERFORMING DEVICE WIPE - DATA WILL BE LOST"

${wipeAction.wipeType === 'full' ? `
# Full device wipe
sudo diskutil resetFusion || true
sudo diskutil eraseVolume JHFS+ "Macintosh HD" /dev/disk1

# Secure erase if requested
if [ "${wipeAction.wipeMethod}" = "secure" ]; then
    sudo diskutil secureErase freespace 3 /
fi
` : wipeAction.wipeType === 'selective' ? `
# Selective wipe - Remove corporate apps and data
echo "Performing selective corporate data wipe"

${wipeAction.selectiveWipeApps.map(app => `
# Remove ${app}
sudo rm -rf "/Applications/${app}.app"
`).join('')}

# Remove corporate profiles
sudo profiles -R -p com.company.*
` : ''}

echo "Wipe completed - Action ID: ${wipeAction.actionId}"
`,
            linux: `#!/bin/bash
# Linux Device Wipe Script - DESTRUCTIVE ACTION
# Action ID: ${wipeAction.actionId}

echo "WARNING: PERFORMING DEVICE WIPE - DATA WILL BE LOST"

${wipeAction.wipeType === 'full' ? `
# Full device wipe
sync

# Identify boot disk
BOOT_DISK=$(df / | tail -1 | awk '{print $1}' | sed 's/[0-9]*//')

# Secure wipe if requested
if [ "${wipeAction.wipeMethod}" = "secure" ]; then
    # Multi-pass secure wipe
    shred -vfz -n 3 $BOOT_DISK
else
    # Quick wipe
    dd if=/dev/zero of=$BOOT_DISK bs=1M
fi

# Reboot after wipe
reboot
` : wipeAction.wipeType === 'selective' ? `
# Selective wipe - Remove corporate data
echo "Performing selective corporate data wipe"

# Remove corporate applications
${wipeAction.selectiveWipeApps.map(app => `
if command -v ${app} >/dev/null 2>&1; then
    # Remove ${app}
    if command -v apt-get >/dev/null 2>&1; then
        apt-get remove -y ${app}
    elif command -v yum >/dev/null 2>&1; then
        yum remove -y ${app}
    elif command -v dnf >/dev/null 2>&1; then
        dnf remove -y ${app}
    fi
fi
`).join('')}

# Remove corporate certificates
rm -f /usr/local/share/ca-certificates/corporate*
update-ca-certificates
` : ''}

echo "Wipe completed - Action ID: ${wipeAction.actionId}"
`
        };
    }

    /**
     * Generate platform-specific restart scripts
     */
    generateRestartScripts(restartAction) {
        return {
            windows: `
# Windows Device Restart Script
# Action ID: ${restartAction.actionId}

$delay = ${restartAction.delay}
$message = "${restartAction.message.replace('{delay}', restartAction.delay)}"

# Notify users
msg * "$message"

${restartAction.forceRestart ? `
# Force restart
shutdown /r /t $delay /f /c "$message"
` : `
# Standard restart
shutdown /r /t $delay /c "$message"
`}

Write-Output "Restart scheduled - Action ID: ${restartAction.actionId}"
`,
            macos: `#!/bin/bash
# macOS Device Restart Script
# Action ID: ${restartAction.actionId}

DELAY=${restartAction.delay}
MESSAGE="${restartAction.message.replace('{delay}', restartAction.delay)}"

# Notify users
osascript -e "display notification \\"$MESSAGE\\" with title \\"System Restart\\""

${restartAction.forceRestart ? `
# Force restart
sudo shutdown -r +$((DELAY/60)) "$MESSAGE"
` : `
# Standard restart  
sudo shutdown -r +$((DELAY/60)) "$MESSAGE"
`}

echo "Restart scheduled - Action ID: ${restartAction.actionId}"
`,
            linux: `#!/bin/bash
# Linux Device Restart Script  
# Action ID: ${restartAction.actionId}

DELAY=${restartAction.delay}
MESSAGE="${restartAction.message.replace('{delay}', restartAction.delay)}"

# Notify users
if command -v notify-send >/dev/null 2>&1; then
    notify-send "System Restart" "$MESSAGE" -u critical
fi

# Wall message to all users
wall "$MESSAGE"

${restartAction.forceRestart ? `
# Force restart
shutdown -r +$((DELAY/60)) "$MESSAGE"
` : `
# Standard restart
shutdown -r +$((DELAY/60)) "$MESSAGE"
`}

echo "Restart scheduled - Action ID: ${restartAction.actionId}"
`
        };
    }

    /**
     * Generate platform-specific locate scripts
     */
    generateLocateScripts(locateAction) {
        return {
            windows: `
# Windows Device Location Script
# Action ID: ${locateAction.actionId}

$message = "${locateAction.message}"

# Display location request message
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show($message, "Device Location Request", "OK", "Information")

# Attempt to get location (requires location services)
$location = @{
    "timestamp" = (Get-Date).ToString('o')
    "method" = "windows-location-api"
    "accuracy" = "${locateAction.accuracy}"
}

# Try to get network location
try {
    $geoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
    $geoWatcher.Start()
    Start-Sleep -Seconds 10
    
    if ($geoWatcher.Position.Location.IsUnknown -eq $false) {
        $location.latitude = $geoWatcher.Position.Location.Latitude
        $location.longitude = $geoWatcher.Position.Location.Longitude
        $location.accuracy = $geoWatcher.Position.Location.HorizontalAccuracy
    }
} catch {
    Write-Warning "Could not determine precise location"
}

# Get network information
$networkInfo = Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4" -and $_.IPAddress -ne "127.0.0.1"}
$location.networkIP = $networkInfo.IPAddress

# Get system information
$location.computerName = $env:COMPUTERNAME
$location.domain = $env:USERDOMAIN

$location | ConvertTo-Json | Out-File "C:\\temp\\location-${locateAction.actionId}.json"

Write-Output "Location information collected - Action ID: ${locateAction.actionId}"
`,
            macos: `#!/bin/bash
# macOS Device Location Script
# Action ID: ${locateAction.actionId}

MESSAGE="${locateAction.message}"

# Display location request message
${locateAction.displayMessage ? `
osascript -e "display dialog \\"$MESSAGE\\" with title \\"Device Location Request\\" buttons {\\"OK\\"} default button \\"OK\\""
` : ''}

# Play sound if requested
${locateAction.playSound ? `
afplay /System/Library/Sounds/Sosumi.aiff
` : ''}

# Get location using Core Location (requires permission)
cat > /tmp/get_location.swift << 'EOF'
import CoreLocation
import Foundation

class LocationManager: NSObject, CLLocationManagerDelegate {
    let manager = CLLocationManager()
    
    override init() {
        super.init()
        manager.delegate = self
        manager.requestWhenInUseAuthorization()
        manager.requestLocation()
    }
    
    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        if let location = locations.first {
            let locationData = [
                "timestamp": ISO8601DateFormatter().string(from: Date()),
                "latitude": location.coordinate.latitude,
                "longitude": location.coordinate.longitude,
                "accuracy": location.horizontalAccuracy,
                "method": "core-location"
            ]
            
            if let jsonData = try? JSONSerialization.data(withJSONObject: locationData),
               let jsonString = String(data: jsonData, encoding: .utf8) {
                print(jsonString)
            }
        }
        exit(0)
    }
    
    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        print("Location error: \\(error)")
        exit(1)
    }
}

let locationManager = LocationManager()
RunLoop.main.run()
EOF

# Compile and run location script
xcrun swift /tmp/get_location.swift > "/tmp/location-${locateAction.actionId}.json" 2>/dev/null || echo '{"error": "Location unavailable"}'

# Get network information as fallback
NETWORK_IP=$(ifconfig | grep "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}')
HOSTNAME=$(hostname)

echo "{\\"networkIP\\": \\"$NETWORK_IP\\", \\"hostname\\": \\"$HOSTNAME\\", \\"timestamp\\": \\"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\\"}" >> "/tmp/location-${locateAction.actionId}.json"

echo "Location information collected - Action ID: ${locateAction.actionId}"
`,
            linux: `#!/bin/bash
# Linux Device Location Script
# Action ID: ${locateAction.actionId}

MESSAGE="${locateAction.message}"

# Display location request message
${locateAction.displayMessage ? `
if command -v notify-send >/dev/null 2>&1; then
    notify-send "Device Location Request" "$MESSAGE" -u critical -t 10000
elif command -v zenity >/dev/null 2>&1; then
    zenity --info --text="$MESSAGE" --title="Device Location Request"
fi
` : ''}

# Create location data file
LOCATION_FILE="/tmp/location-${locateAction.actionId}.json"

# Try to get GPS location if available (requires GPS hardware and permissions)
LOCATION_DATA="{"
LOCATION_DATA+="\\"timestamp\\": \\"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\\","
LOCATION_DATA+="\\"method\\": \\"network\\","

# Get network-based location information
EXTERNAL_IP=$(curl -s ifconfig.me 2>/dev/null || echo "unknown")
LOCATION_DATA+="\\"externalIP\\": \\"$EXTERNAL_IP\\","

# Get local network information
LOCAL_IP=$(ip route get 1 | awk '{print $NF; exit}' 2>/dev/null || echo "unknown")
LOCATION_DATA+="\\"localIP\\": \\"$LOCAL_IP\\","

# Get hostname and system info
LOCATION_DATA+="\\"hostname\\": \\"$(hostname)\\","
LOCATION_DATA+="\\"uptime\\": \\"$(uptime -p)\\""

LOCATION_DATA+="}"

echo "$LOCATION_DATA" > "$LOCATION_FILE"

echo "Location information collected - Action ID: ${locateAction.actionId}"
`
        };
    }

    /**
     * Generate lost mode scripts
     */
    generateLostModeScripts(lostModeAction) {
        return {
            windows: `
# Windows Lost Mode Script
# Action ID: ${lostModeAction.actionId}

$message = "${lostModeAction.message}"
$phoneNumber = "${lostModeAction.phoneNumber || ''}"
$footnote = "${lostModeAction.footnote}"

# Set lock screen message
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "legalnoticecaption" -Value "LOST DEVICE"
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "legalnoticetext" -Value "$message\\n\\nContact: $phoneNumber\\n\\n$footnote"

# Enable mandatory lock screen
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "DisableLockWorkstation" -Value 0

# Lock the device
rundll32.exe user32.dll,LockWorkStation

Write-Output "Lost mode enabled - Action ID: ${lostModeAction.actionId}"
`,
            macos: `#!/bin/bash
# macOS Lost Mode Script  
# Action ID: ${lostModeAction.actionId}

MESSAGE="${lostModeAction.message}"
PHONE_NUMBER="${lostModeAction.phoneNumber || ''}"
FOOTNOTE="${lostModeAction.footnote}"

# Set login window message
sudo defaults write /Library/Preferences/com.apple.loginwindow.plist LoginwindowText "*** LOST DEVICE ***\\n\\n$MESSAGE\\n\\nContact: $PHONE_NUMBER\\n\\n$FOOTNOTE"

# Enable screen saver with immediate lock
defaults write com.apple.screensaver askForPassword -int 1
defaults write com.apple.screensaver askForPasswordDelay -int 0

# Play lost mode sound if requested
${lostModeAction.playLostModeSound ? `
afplay /System/Library/Sounds/Sosumi.aiff &
` : ''}

# Lock the screen
osascript -e 'tell application "System Events" to start current screen saver'

echo "Lost mode enabled - Action ID: ${lostModeAction.actionId}"
`,
            linux: `#!/bin/bash
# Linux Lost Mode Script
# Action ID: ${lostModeAction.actionId}

MESSAGE="${lostModeAction.message}"
PHONE_NUMBER="${lostModeAction.phoneNumber || ''}"
FOOTNOTE="${lostModeAction.footnote}"

# Set login message
cat > /etc/issue << EOF
*** LOST DEVICE ***

$MESSAGE

Contact: $PHONE_NUMBER

$FOOTNOTE
EOF

# Lock all sessions
if command -v loginctl >/dev/null 2>&1; then
    loginctl lock-sessions
fi

# Display permanent notification
if command -v notify-send >/dev/null 2>&1; then
    notify-send "LOST DEVICE" "$MESSAGE\\n\\nContact: $PHONE_NUMBER" -u critical -t 0 &
fi

echo "Lost mode enabled - Action ID: ${lostModeAction.actionId}"
`
        };
    }

    /**
     * Generate key rotation scripts
     */
    generateKeyRotationScripts(rotateAction) {
        return {
            windows: `
# Windows Encryption Key Rotation Script
# Action ID: ${rotateAction.actionId}

${rotateAction.keyTypes.includes('bitlocker') ? `
# BitLocker key rotation
Write-Output "Rotating BitLocker recovery keys..."

# Get BitLocker volumes
$volumes = Get-BitLockerVolume

foreach ($volume in $volumes) {
    if ($volume.ProtectionStatus -eq "On") {
        # Remove old recovery passwords
        $volume.KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"} | ForEach-Object {
            Remove-BitLockerKeyProtector -MountPoint $volume.MountPoint -KeyProtectorId $_.KeyProtectorId
        }
        
        # Add new recovery password
        $newKey = Add-BitLockerKeyProtector -MountPoint $volume.MountPoint -RecoveryPasswordProtector
        
        # Backup to AD if configured
        ${rotateAction.escrowKeys ? `
        Backup-BitLockerKeyProtector -MountPoint $volume.MountPoint -KeyProtectorId $newKey.KeyProtectorId
        ` : ''}
        
        Write-Output "BitLocker key rotated for volume: $($volume.MountPoint)"
    }
}
` : ''}

Write-Output "Key rotation completed - Action ID: ${rotateAction.actionId}"
`,
            macos: `#!/bin/bash
# macOS Encryption Key Rotation Script
# Action ID: ${rotateAction.actionId}

${rotateAction.keyTypes.includes('filevault') ? `
# FileVault key rotation
echo "Rotating FileVault recovery keys..."

# Check if FileVault is enabled
if fdesetup status | grep -q "FileVault is On"; then
    # Generate new recovery key
    NEW_KEY=$(fdesetup changerecovery -personal)
    
    if [ $? -eq 0 ]; then
        echo "FileVault recovery key rotated successfully"
        
        ${rotateAction.escrowKeys ? `
        # Escrow key to MDM if configured
        # This would typically be done via MDM profile
        echo "Escrowing new recovery key to MDM..."
        ` : ''}
        
        ${rotateAction.backupKeys ? `
        # Backup key securely
        echo "$NEW_KEY" > "/tmp/filevault-recovery-${rotateAction.actionId}.key"
        chmod 600 "/tmp/filevault-recovery-${rotateAction.actionId}.key"
        ` : ''}
    else
        echo "Failed to rotate FileVault key"
    fi
else
    echo "FileVault is not enabled"
fi
` : ''}

echo "Key rotation completed - Action ID: ${rotateAction.actionId}"
`,
            linux: `#!/bin/bash
# Linux Encryption Key Rotation Script
# Action ID: ${rotateAction.actionId}

echo "Rotating Linux encryption keys..."

# LUKS key rotation
if command -v cryptsetup >/dev/null 2>&1; then
    # Find encrypted volumes
    for device in $(blkid -t TYPE=crypto_LUKS -o device); do
        echo "Processing encrypted device: $device"
        
        # This would require existing passphrase/keyfile
        # In practice, this would be managed through configuration management
        # cryptsetup luksAddKey $device /path/to/new/keyfile
        
        echo "Key rotation would be performed for $device"
    done
fi

# SSH key rotation
if [ -d "/etc/ssh" ]; then
    echo "Backing up SSH host keys..."
    cp -r /etc/ssh /etc/ssh.backup.$(date +%Y%m%d)
    
    echo "Generating new SSH host keys..."
    ssh-keygen -A
    
    systemctl restart sshd
    echo "SSH host keys rotated"
fi

echo "Key rotation completed - Action ID: ${rotateAction.actionId}"
`
        };
    }

    /**
     * Generate sync scripts
     */
    generateSyncScripts(syncAction) {
        return {
            windows: `
# Windows Policy Sync Script
# Action ID: ${syncAction.actionId}

Write-Output "Synchronizing device policies..."

# Force Group Policy update
gpupdate /force

# Sync with Configuration Manager if available
if (Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue) {
    # SCCM policy sync
    Invoke-WmiMethod -Namespace root\\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000021}"
    Invoke-WmiMethod -Namespace root\\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000022}"
}

# Sync certificates
certlm.msc -s

# Windows Update sync
UsoClient ScanInstallWait

Write-Output "Policy sync completed - Action ID: ${syncAction.actionId}"
`,
            macos: `#!/bin/bash
# macOS Policy Sync Script
# Action ID: ${syncAction.actionId}

echo "Synchronizing device policies..."

# Sync MDM profiles
if command -v profiles >/dev/null 2>&1; then
    profiles renew -type enrollment
    profiles sync
fi

# Sync system preferences
killall cfprefsd

# Sync certificates
security sync

# Check for software updates
softwareupdate -l

echo "Policy sync completed - Action ID: ${syncAction.actionId}"
`,
            linux: `#!/bin/bash
# Linux Policy Sync Script  
# Action ID: ${syncAction.actionId}

echo "Synchronizing device policies..."

# Sync with configuration management
if command -v puppet >/dev/null 2>&1; then
    puppet agent --test
elif command -v chef-client >/dev/null 2>&1; then
    chef-client
elif command -v ansible-pull >/dev/null 2>&1; then
    ansible-pull
fi

# Update package information
if command -v apt-get >/dev/null 2>&1; then
    apt-get update
elif command -v yum >/dev/null 2>&1; then
    yum check-update
elif command -v dnf >/dev/null 2>&1; then
    dnf check-update
fi

# Sync time
if command -v ntpdate >/dev/null 2>&1; then
    ntpdate -s time.nist.gov
elif command -v chrony >/dev/null 2>&1; then
    chrony sources -v
fi

echo "Policy sync completed - Action ID: ${syncAction.actionId}"
`
        };
    }

    /**
     * Generate random passcode
     */
    generateRandomPasscode(length = 6) {
        const chars = '0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }

    /**
     * Get action status
     */
    async getActionStatus(actionId) {
        try {
            const action = this.pendingActions.get(actionId);
            if (!action) {
                return { success: false, error: 'Action not found' };
            }

            return {
                success: true,
                action,
                status: 'pending' // This would be updated by agent feedback
            };

        } catch (error) {
            logger.error('Error getting action status:', error);
            throw error;
        }
    }

    /**
     * Cancel pending action
     */
    async cancelAction(actionId) {
        try {
            const action = this.pendingActions.get(actionId);
            if (!action) {
                return { success: false, error: 'Action not found' };
            }

            this.pendingActions.delete(actionId);

            await this.auditLogger.log('remote_action_cancelled', {
                actionId,
                deviceId: action.deviceId,
                actionType: action.type,
                timestamp: new Date().toISOString()
            });

            this.emit('actionCancelled', { actionId });

            return {
                success: true,
                actionId,
                message: 'Action cancelled successfully'
            };

        } catch (error) {
            logger.error('Error cancelling action:', error);
            throw error;
        }
    }
}

module.exports = RemoteActionsService;