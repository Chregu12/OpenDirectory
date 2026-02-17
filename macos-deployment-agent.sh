#!/bin/bash

# OpenDirectory macOS Deployment Agent
# Handles application installation on macOS devices

set -e

OPENDIRECTORY_SERVER="192.168.1.223:30055"
DEPLOYMENT_LOG="/var/log/opendirectory-deployments.log"
DEPLOYMENT_DIR="/opt/opendirectory/deployments"

# Ensure directories exist
sudo mkdir -p /opt/opendirectory/deployments
sudo mkdir -p /var/log

log() {
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [macOS-Agent] $1" | sudo tee -a "$DEPLOYMENT_LOG"
}

# Get system information
get_system_info() {
    local hostname=$(hostname)
    local os_version=$(sw_vers -productVersion)
    local architecture=$(uname -m)
    local uptime=$(uptime | awk '{print $3, $4}')
    
    log "=== System Information ==="
    log "Hostname: $hostname"
    log "macOS Version: $os_version"
    log "Architecture: $architecture"
    log "Uptime: $uptime"
}

# Check if Homebrew is installed
ensure_homebrew() {
    if ! command -v brew &> /dev/null; then
        log "📦 Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        
        # Add Homebrew to PATH
        echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
        eval "$(/opt/homebrew/bin/brew shellenv)"
        
        log "✅ Homebrew installed successfully"
    else
        log "✅ Homebrew already installed"
    fi
}

# Install Google Chrome
install_chrome() {
    log "📦 Starting Google Chrome installation for macOS"
    
    # Download Chrome DMG
    local chrome_dmg="/tmp/googlechrome.dmg"
    log "🔄 Downloading Chrome..."
    curl -L "https://dl.google.com/chrome/mac/stable/GGRO/googlechrome.dmg" -o "$chrome_dmg"
    
    # Mount DMG
    log "📁 Mounting Chrome installer..."
    local mount_point=$(hdiutil attach "$chrome_dmg" | grep -E '/Volumes/' | awk '{print $3}')
    
    # Copy to Applications
    log "📦 Installing Chrome..."
    sudo cp -R "$mount_point/Google Chrome.app" "/Applications/"
    
    # Unmount DMG
    hdiutil detach "$mount_point"
    rm "$chrome_dmg"
    
    # Verify installation
    if [ -d "/Applications/Google Chrome.app" ]; then
        local version=$(/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --version 2>/dev/null | awk '{print $3}')
        log "✅ Chrome installation successful: $version"
        
        # Create deployment record
        create_deployment_record "chrome" "Google Chrome" "$version" "dmg"
        return 0
    else
        log "❌ Chrome installation failed"
        return 1
    fi
}

# Install Visual Studio Code
install_vscode() {
    log "📦 Starting Visual Studio Code installation for macOS"
    
    # Download VS Code
    local vscode_zip="/tmp/vscode.zip"
    log "🔄 Downloading VS Code..."
    curl -L "https://code.visualstudio.com/sha/download?build=stable&os=darwin" -o "$vscode_zip"
    
    # Extract to Applications
    log "📦 Installing VS Code..."
    sudo unzip -q "$vscode_zip" -d "/Applications/"
    rm "$vscode_zip"
    
    # Verify installation
    if [ -d "/Applications/Visual Studio Code.app" ]; then
        local version=$(/Applications/Visual\ Studio\ Code.app/Contents/MacOS/Electron --version 2>/dev/null | head -1)
        log "✅ VS Code installation successful: $version"
        
        # Create deployment record
        create_deployment_record "vscode" "Visual Studio Code" "$version" "zip"
        return 0
    else
        log "❌ VS Code installation failed"
        return 1
    fi
}

# Install Docker Desktop
install_docker_desktop() {
    log "📦 Starting Docker Desktop installation for macOS"
    
    # Determine architecture
    local arch=$(uname -m)
    local docker_dmg="/tmp/docker.dmg"
    
    if [[ "$arch" == "arm64" ]]; then
        log "🔄 Downloading Docker Desktop for Apple Silicon..."
        curl -L "https://desktop.docker.com/mac/main/arm64/Docker.dmg" -o "$docker_dmg"
    else
        log "🔄 Downloading Docker Desktop for Intel..."
        curl -L "https://desktop.docker.com/mac/main/amd64/Docker.dmg" -o "$docker_dmg"
    fi
    
    # Mount DMG
    log "📁 Mounting Docker installer..."
    local mount_point=$(hdiutil attach "$docker_dmg" | grep -E '/Volumes/' | awk '{print $3}')
    
    # Copy to Applications
    log "📦 Installing Docker Desktop..."
    sudo cp -R "$mount_point/Docker.app" "/Applications/"
    
    # Unmount DMG
    hdiutil detach "$mount_point"
    rm "$docker_dmg"
    
    # Verify installation
    if [ -d "/Applications/Docker.app" ]; then
        log "✅ Docker Desktop installation successful"
        log "⚠️  Docker Desktop requires manual startup and configuration"
        
        # Create deployment record
        create_deployment_record "docker-desktop" "Docker Desktop" "latest" "dmg"
        return 0
    else
        log "❌ Docker Desktop installation failed"
        return 1
    fi
}

# Install Homebrew package
install_homebrew_package() {
    local package_name="$1"
    local display_name="$2"
    
    log "📦 Installing $display_name via Homebrew..."
    
    ensure_homebrew
    
    if brew install "$package_name"; then
        local version=$(brew list --versions "$package_name" | awk '{print $2}')
        log "✅ $display_name installation successful: $version"
        
        create_deployment_record "$package_name" "$display_name" "$version" "homebrew"
        return 0
    else
        log "❌ $display_name installation failed"
        return 1
    fi
}

# Install Xcode Command Line Tools
install_xcode_tools() {
    log "📦 Installing Xcode Command Line Tools..."
    
    if xcode-select -p &> /dev/null; then
        log "✅ Xcode Command Line Tools already installed"
        return 0
    fi
    
    # Trigger installation
    xcode-select --install
    
    # Wait for installation to complete
    log "⏳ Waiting for Xcode Command Line Tools installation..."
    while ! xcode-select -p &> /dev/null; do
        sleep 5
    done
    
    local version=$(pkgutil --pkg-info=com.apple.pkg.CLTools_Executables | grep version | awk '{print $2}')
    log "✅ Xcode Command Line Tools installed: $version"
    
    create_deployment_record "xcode-tools" "Xcode Command Line Tools" "$version" "system"
    return 0
}

# Install from Mac App Store
install_from_mas() {
    local app_id="$1"
    local app_name="$2"
    
    log "📦 Installing $app_name from Mac App Store..."
    
    # Install mas-cli if not present
    if ! command -v mas &> /dev/null; then
        ensure_homebrew
        brew install mas
    fi
    
    if mas install "$app_id"; then
        log "✅ $app_name installation successful"
        create_deployment_record "$app_id" "$app_name" "mas" "app-store"
        return 0
    else
        log "❌ $app_name installation failed"
        return 1
    fi
}

# Create deployment record
create_deployment_record() {
    local app_id="$1"
    local app_name="$2"
    local version="$3"
    local method="$4"
    
    local record_file="$DEPLOYMENT_DIR/${app_id}-$(date +%s).json"
    
    cat > "$record_file" << EOF
{
  "app": "$app_id",
  "app_name": "$app_name",
  "version": "$version",
  "status": "installed",
  "deployment_time": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "target_device": "$(hostname)",
  "platform": "macos",
  "deployment_method": "$method",
  "installed_by": "opendirectory-macos-agent"
}
EOF

    # Notify OpenDirectory server
    notify_server "$app_id" "$app_name" "$version" "success"
}

# Notify OpenDirectory server
notify_server() {
    local app_id="$1"
    local app_name="$2"
    local version="$3"
    local status="$4"
    
    local json_data=$(cat << EOF
{
  "device_id": "$(hostname)",
  "app": "$app_id",
  "app_name": "$app_name",
  "status": "$status",
  "version": "$version",
  "platform": "macos"
}
EOF
)
    
    if curl -s -X POST "http://$OPENDIRECTORY_SERVER/api/deployments/status" \
       -H "Content-Type: application/json" \
       -d "$json_data" > /dev/null; then
        log "📡 Deployment notification sent to OpenDirectory server"
    else
        log "⚠️  Failed to notify OpenDirectory server"
    fi
}

# Show system status
show_status() {
    log "=== OpenDirectory macOS Deployment Agent Status ==="
    get_system_info
    
    log "📁 Log Path: $DEPLOYMENT_LOG"
    log "📁 Deployment Path: $DEPLOYMENT_DIR"
    
    log "=== Installed Applications ==="
    
    # Check common applications
    if [ -d "/Applications/Google Chrome.app" ]; then
        local version=$(/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --version 2>/dev/null | awk '{print $3}' || echo "Unknown")
        log "✅ Google Chrome: $version"
    else
        log "❌ Google Chrome: Not installed"
    fi
    
    if [ -d "/Applications/Visual Studio Code.app" ]; then
        log "✅ Visual Studio Code: Installed"
    else
        log "❌ Visual Studio Code: Not installed"
    fi
    
    if [ -d "/Applications/Docker.app" ]; then
        log "✅ Docker Desktop: Installed"
    else
        log "❌ Docker Desktop: Not installed"
    fi
    
    if command -v brew &> /dev/null; then
        local brew_version=$(brew --version | head -1)
        log "✅ Homebrew: $brew_version"
    else
        log "❌ Homebrew: Not installed"
    fi
    
    if xcode-select -p &> /dev/null; then
        log "✅ Xcode Command Line Tools: Installed"
    else
        log "❌ Xcode Command Line Tools: Not installed"
    fi
    
    log "=== Deployment History ==="
    if ls "$DEPLOYMENT_DIR"/*.json &> /dev/null; then
        ls -lt "$DEPLOYMENT_DIR"/*.json | head -5 | while read line; do
            local file=$(echo $line | awk '{print $9}')
            log "📄 $(basename $file)"
        done
    else
        log "No deployment records found"
    fi
}

# Main application installer
install_application() {
    local app_name="$1"
    
    case "$app_name" in
        "chrome")
            install_chrome
            ;;
        "vscode")
            install_vscode
            ;;
        "docker-desktop")
            install_docker_desktop
            ;;
        "xcode-tools")
            install_xcode_tools
            ;;
        "homebrew")
            ensure_homebrew
            create_deployment_record "homebrew" "Homebrew" "$(brew --version | head -1)" "script"
            ;;
        "vlc")
            install_homebrew_package "vlc" "VLC Media Player"
            ;;
        "firefox")
            install_homebrew_package "firefox" "Mozilla Firefox"
            ;;
        "git")
            install_homebrew_package "git" "Git"
            ;;
        "nodejs")
            install_homebrew_package "node" "Node.js"
            ;;
        "python")
            install_homebrew_package "python" "Python 3"
            ;;
        *)
            log "❌ Unknown application: $app_name"
            log "Available applications: chrome, vscode, docker-desktop, xcode-tools, homebrew, vlc, firefox, git, nodejs, python"
            return 1
            ;;
    esac
}

# Main execution
main() {
    local app_name="${1:-status}"
    
    log "OpenDirectory macOS Deployment Agent started"
    log "Application: $app_name"
    
    if [ "$app_name" = "status" ]; then
        show_status
    else
        if install_application "$app_name"; then
            log "✅ Deployment completed successfully!"
            echo ""
            echo "✅ $app_name deployment completed successfully!"
            exit 0
        else
            log "❌ Deployment failed"
            echo "❌ $app_name deployment failed"
            exit 1
        fi
    fi
}

# Run main function with all arguments
main "$@"