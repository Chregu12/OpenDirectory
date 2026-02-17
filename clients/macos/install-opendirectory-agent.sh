#!/bin/bash
# OpenDirectory macOS Client Installer
# Installs and configures all required agents for OpenDirectory MDM

set -e

# Configuration
SERVER_URL="${1:-https://mdm.opendirectory.local}"
ENROLLMENT_TOKEN="${2:-}"
OD_DIR="/usr/local/opendirectory"

echo "🍎 OpenDirectory macOS Client Installer"
echo "======================================="

# Check if running with sudo
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run with sudo"
   exit 1
fi

# Create OpenDirectory directory
echo "📁 Creating OpenDirectory directory..."
mkdir -p "$OD_DIR"

# Get device information
DEVICE_ID=$(system_profiler SPHardwareDataType | awk '/Hardware UUID:/ {print $3}')
HOSTNAME=$(scutil --get ComputerName)
OS_VERSION=$(sw_vers -productVersion)

echo "📱 Device ID: $DEVICE_ID"
echo "🖥️  Hostname: $HOSTNAME"
echo "💾 macOS Version: $OS_VERSION"

# Install Munki
echo "📦 Installing Munki..."
MUNKI_VERSION="6.2.0.4555"
MUNKI_URL="https://releases.github.com/munki/munki/munkitools-${MUNKI_VERSION}.pkg"
MUNKI_PKG="/tmp/munkitools.pkg"

curl -L -o "$MUNKI_PKG" "$MUNKI_URL"
installer -pkg "$MUNKI_PKG" -target /

# Configure Munki to use OpenDirectory repository
echo "⚙️  Configuring Munki..."
defaults write /Library/Preferences/ManagedInstalls SoftwareRepoURL "$SERVER_URL/munki"
defaults write /Library/Preferences/ManagedInstalls ClientIdentifier "$DEVICE_ID"
defaults write /Library/Preferences/ManagedInstalls AdditionalHttpHeaders -array "X-Device-ID: $DEVICE_ID"

# Simple monitoring setup
echo "⚙️  Setting up device monitoring..."

# Create OpenDirectory CLI tool
echo "🛠️  Creating OpenDirectory CLI..."
cat > "$OD_DIR/opendirectory" << 'EOF'
#!/bin/bash
# OpenDirectory macOS CLI Tool

OD_SERVER="https://mdm.opendirectory.local"
DEVICE_ID=$(system_profiler SPHardwareDataType | awk '/Hardware UUID:/ {print $3}')

case "$1" in
    "compliance")
        echo "🔍 Checking compliance..."
        curl -s -X POST "$OD_SERVER/api/compliance/check" \
            -H "Content-Type: application/json" \
            -d "{\"device_id\":\"$DEVICE_ID\",\"platform\":\"macos\"}" | jq '.'
        ;;
    "patches")
        echo "🔄 Scanning for patches..."
        curl -s -X POST "$OD_SERVER/api/patches/scan" \
            -H "Content-Type: application/json" \
            -d "{\"device_id\":\"$DEVICE_ID\",\"platform\":\"macos\"}" | jq '.'
        ;;
    "apps")
        echo "📱 Available applications..."
        curl -s "$OD_SERVER/api/appstore/catalog?platform=macos" | jq '.'
        ;;
    "install")
        if [[ -z "$2" ]]; then
            echo "Usage: opendirectory install <app-id>"
            exit 1
        fi
        echo "⬇️  Installing application: $2"
        curl -s -X POST "$OD_SERVER/api/appstore/deploy" \
            -H "Content-Type: application/json" \
            -d "{\"appId\":\"$2\",\"deviceIds\":[\"$DEVICE_ID\"],\"schedule\":\"immediate\"}" | jq '.'
        ;;
    "status")
        echo "📊 Device status..."
        echo "Device ID: $DEVICE_ID"
        echo "Server: $OD_SERVER"
        echo "Munki Status: $(defaults read /Library/Preferences/ManagedInstalls SoftwareRepoURL 2>/dev/null || echo 'Not configured')"
        echo "Fleet Status: $(launchctl list | grep com.fleetdm.orbit >/dev/null && echo 'Running' || echo 'Not running')"
        ;;
    *)
        echo "OpenDirectory macOS Client"
        echo "Usage: opendirectory <command>"
        echo ""
        echo "Commands:"
        echo "  compliance  - Check device compliance"
        echo "  patches     - Scan for available patches"
        echo "  apps        - List available applications"
        echo "  install     - Install application by ID"
        echo "  status      - Show device and agent status"
        ;;
esac
EOF

chmod +x "$OD_DIR/opendirectory"
ln -sf "$OD_DIR/opendirectory" /usr/local/bin/opendirectory

# Create LaunchDaemon for periodic compliance checks
echo "⏰ Setting up compliance monitoring..."
cat > /Library/LaunchDaemons/com.opendirectory.compliance.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.opendirectory.compliance</string>
    <key>ProgramArguments</key>
    <array>
        <string>$OD_DIR/opendirectory</string>
        <string>compliance</string>
    </array>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF

launchctl load /Library/LaunchDaemons/com.opendirectory.compliance.plist

# Register device with OpenDirectory
echo "📝 Registering device..."
DEVICE_INFO=$(cat << EOJ
{
    "device_id": "$DEVICE_ID",
    "hostname": "$HOSTNAME",
    "platform": "macos",
    "os_version": "$OS_VERSION",
    "enrollment_token": "$ENROLLMENT_TOKEN",
    "installed_software": []
}
EOJ
)

curl -s -X POST "$SERVER_URL/api/devices/register" \
    -H "Content-Type: application/json" \
    -d "$DEVICE_INFO" > /dev/null && echo "✅ Device registered successfully" || echo "⚠️  Device registration failed"

# Save configuration
cat > "$OD_DIR/config.json" << EOF
{
    "device_id": "$DEVICE_ID",
    "server_url": "$SERVER_URL",
    "registered_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "enrollment_token": "$ENROLLMENT_TOKEN"
}
EOF

# Initial compliance check
echo "🔍 Running initial compliance check..."
sleep 2
"$OD_DIR/opendirectory" compliance

echo ""
echo "✅ OpenDirectory macOS Client installed successfully!"
echo "🔧 Device ID: $DEVICE_ID"
echo "🌐 Server: $SERVER_URL"
echo ""
echo "📋 Available commands:"
echo "   opendirectory compliance   - Check device compliance"
echo "   opendirectory patches      - Scan for patches"
echo "   opendirectory apps         - List available apps"
echo "   opendirectory install <id> - Install application"
echo "   opendirectory status       - Show system status"

# Cleanup
rm -f "$MUNKI_PKG" "$FLEET_PKG"