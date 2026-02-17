#!/bin/bash
# OpenDirectory Linux Client Installer
# Installs and configures all required agents for OpenDirectory MDM

set -e

# Configuration
SERVER_URL="${1:-https://mdm.opendirectory.local}"
ENROLLMENT_TOKEN="${2:-}"
OD_DIR="/opt/opendirectory"

echo "🐧 OpenDirectory Linux Client Installer"
echo "======================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root (use sudo)"
   exit 1
fi

# Detect Linux distribution
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    DISTRO=$ID
    VERSION=$VERSION_ID
else
    echo "❌ Cannot detect Linux distribution"
    exit 1
fi

echo "📋 Detected: $PRETTY_NAME"

# Create OpenDirectory directory
echo "📁 Creating OpenDirectory directory..."
mkdir -p "$OD_DIR"

# Get device information
DEVICE_ID=$(cat /sys/class/dmi/id/product_uuid 2>/dev/null || cat /proc/sys/kernel/random/uuid)
HOSTNAME=$(hostname)
KERNEL_VERSION=$(uname -r)

echo "📱 Device ID: $DEVICE_ID"
echo "🖥️  Hostname: $HOSTNAME" 
echo "🔧 Kernel: $KERNEL_VERSION"

# Install dependencies based on distribution
echo "📦 Installing dependencies..."
case $DISTRO in
    "ubuntu"|"debian")
        apt-get update
        apt-get install -y curl jq systemd cron
        PACKAGE_MANAGER="apt"
        ;;
    "fedora"|"rhel"|"centos"|"rocky"|"almalinux")
        if command -v dnf >/dev/null; then
            dnf install -y curl jq systemd cronie
        else
            yum install -y curl jq systemd cronie
        fi
        PACKAGE_MANAGER="rpm"
        ;;
    "arch"|"manjaro")
        pacman -S --noconfirm curl jq systemd cronie
        PACKAGE_MANAGER="pacman"
        ;;
    "opensuse"|"sles")
        zypper install -y curl jq systemd cron
        PACKAGE_MANAGER="zypper"
        ;;
    *)
        echo "⚠️  Unsupported distribution: $DISTRO"
        echo "📦 Please install: curl, jq, systemd, cron manually"
        ;;
esac

# Simple monitoring setup  
echo "⚙️  Setting up device monitoring..."

# Create OpenDirectory CLI tool
echo "🛠️  Creating OpenDirectory CLI..."
cat > "$OD_DIR/opendirectory" << 'EOF'
#!/bin/bash
# OpenDirectory Linux CLI Tool

OD_SERVER="https://mdm.opendirectory.local"
DEVICE_ID=$(cat /sys/class/dmi/id/product_uuid 2>/dev/null || cat /proc/sys/kernel/random/uuid)

case "$1" in
    "compliance")
        echo "🔍 Checking compliance..."
        curl -s -X POST "$OD_SERVER/api/compliance/check" \
            -H "Content-Type: application/json" \
            -d "{\"device_id\":\"$DEVICE_ID\",\"platform\":\"linux\"}" | jq '.'
        ;;
    "patches")
        echo "🔄 Scanning for patches..."
        curl -s -X POST "$OD_SERVER/api/patches/scan" \
            -H "Content-Type: application/json" \
            -d "{\"device_id\":\"$DEVICE_ID\",\"platform\":\"linux\"}" | jq '.'
        ;;
    "apps")
        echo "📱 Available applications..."
        curl -s "$OD_SERVER/api/appstore/catalog?platform=linux" | jq '.'
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
    "update")
        echo "🔄 Updating system packages..."
        case "$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '\"')" in
            "ubuntu"|"debian")
                apt-get update && apt-get upgrade -y
                ;;
            "fedora"|"rhel"|"centos"|"rocky"|"almalinux")
                if command -v dnf >/dev/null; then
                    dnf update -y
                else
                    yum update -y
                fi
                ;;
            "arch"|"manjaro")
                pacman -Syu --noconfirm
                ;;
            "opensuse"|"sles")
                zypper update -y
                ;;
            *)
                echo "⚠️  Automatic updates not supported for this distribution"
                ;;
        esac
        ;;
    "status")
        echo "📊 Device status..."
        echo "Device ID: $DEVICE_ID"
        echo "Server: $OD_SERVER"
        echo "Fleet Status: $(systemctl is-active orbit 2>/dev/null || echo 'Not running')"
        echo "Munki Status: $(test -f /usr/local/munki/managedsoftwareupdate && echo 'Installed' || echo 'Not installed')"
        echo "Last Check: $(date)"
        ;;
    *)
        echo "OpenDirectory Linux Client"
        echo "Usage: opendirectory <command>"
        echo ""
        echo "Commands:"
        echo "  compliance  - Check device compliance"
        echo "  patches     - Scan for available patches"
        echo "  apps        - List available applications"
        echo "  install     - Install application by ID"
        echo "  update      - Update system packages"
        echo "  status      - Show device and agent status"
        ;;
esac
EOF

chmod +x "$OD_DIR/opendirectory"
ln -sf "$OD_DIR/opendirectory" /usr/local/bin/opendirectory

# Create systemd service for compliance monitoring
echo "⏰ Setting up compliance monitoring..."
cat > /etc/systemd/system/opendirectory-compliance.service << EOF
[Unit]
Description=OpenDirectory Compliance Monitor
After=network.target

[Service]
Type=oneshot
ExecStart=$OD_DIR/opendirectory compliance
User=root

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/opendirectory-compliance.timer << EOF
[Unit]
Description=Run OpenDirectory compliance check every hour
Requires=opendirectory-compliance.service

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable opendirectory-compliance.timer
systemctl start opendirectory-compliance.timer

# Register device with MDM
echo "📝 Registering device..."
DEVICE_INFO=$(cat << EOJ
{
    "device_id": "$DEVICE_ID",
    "hostname": "$HOSTNAME",
    "platform": "linux",
    "os_version": "$PRETTY_NAME",
    "kernel_version": "$KERNEL_VERSION",
    "enrollment_token": "$ENROLLMENT_TOKEN",
    "package_manager": "$PACKAGE_MANAGER",
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
    "enrollment_token": "$ENROLLMENT_TOKEN",
    "distribution": "$DISTRO",
    "version": "$VERSION",
    "package_manager": "$PACKAGE_MANAGER"
}
EOF

# Initial compliance check
echo "🔍 Running initial compliance check..."
sleep 2
"$OD_DIR/opendirectory" compliance

echo ""
echo "✅ OpenDirectory Linux Client installed successfully!"
echo "🔧 Device ID: $DEVICE_ID"
echo "🌐 Server: $SERVER_URL"
echo "📦 Package Manager: $PACKAGE_MANAGER"
echo ""
echo "📋 Available commands:"
echo "   opendirectory compliance   - Check device compliance"
echo "   opendirectory patches      - Scan for patches"
echo "   opendirectory apps         - List available apps"
echo "   opendirectory install <id> - Install application"
echo "   opendirectory update       - Update system packages"
echo "   opendirectory status       - Show system status"

# Cleanup
rm -f "$FLEET_PACKAGE"