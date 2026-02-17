# OpenDirectory Client Installation

Simple installation scripts for all supported operating systems.

## Quick Installation

### Windows 11
```powershell
# Run as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\install-opendirectory-agent.ps1 -ServerUrl "https://mdm.opendirectory.local" -EnrollmentToken "your-token"
```

### macOS
```bash
# Run with sudo
sudo ./install-opendirectory-agent.sh "https://mdm.opendirectory.local" "your-token"
```

### Linux (Ubuntu/Debian/Fedora/RHEL/Arch)
```bash
# Run with sudo
sudo ./install-opendirectory-agent.sh "https://mdm.opendirectory.local" "your-token"
```

## What Gets Installed

### Windows
- Fleet osquery agent for monitoring
- OpenDirectory PowerShell module
- Scheduled compliance checks
- Desktop shortcut for management tools

### macOS  
- Munki for package management
- Fleet agent for monitoring
- OpenDirectory CLI tool
- LaunchDaemon for compliance monitoring

### Linux
- Fleet agent (if available for distro)
- OpenDirectory CLI tool
- Systemd timer for compliance checks
- Distribution-specific package manager integration

## Post-Installation Commands

All platforms get an `opendirectory` command:

```bash
# Check compliance status
opendirectory compliance

# Scan for available patches/updates
opendirectory patches

# List available applications
opendirectory apps

# Install application by ID
opendirectory install chrome

# Show device status
opendirectory status
```

## Configuration

Client configuration is stored in:
- **Windows:** `C:\Program Files\OpenDirectory\device-config.json`
- **macOS:** `/usr/local/opendirectory/config.json`
- **Linux:** `/opt/opendirectory/config.json`

## Enrollment Tokens

Get enrollment tokens from the OpenDirectory MDM dashboard at:
`https://mdm.opendirectory.local/enrollment`

## Troubleshooting

### Connection Issues
```bash
# Test connectivity
curl -k https://mdm.opendirectory.local/api/health

# Check device registration
opendirectory status
```

### Agent Issues
```bash
# Windows - Check services
Get-Service | Where-Object {$_.Name -like "*fleet*" -or $_.Name -like "*orbit*"}

# macOS/Linux - Check systemd services
systemctl status orbit
systemctl status opendirectory-compliance.timer
```