const winston = require('winston');
const fs = require('fs').promises;
const path = require('path');

class PrinterDeployment {
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.simple(),
      transports: [new winston.transports.Console()]
    });
  }

  async generateConfig(platform, printers, settings = {}) {
    switch (platform.toLowerCase()) {
      case 'windows':
        return this.generateWindowsConfig(printers, settings);
      case 'macos':
        return this.generateMacOSConfig(printers, settings);
      case 'linux':
        return this.generateLinuxConfig(printers, settings);
      case 'ios':
        return this.generateiOSConfig(printers, settings);
      case 'android':
        return this.generateAndroidConfig(printers, settings);
      default:
        throw new Error(`Unsupported platform: ${platform}`);
    }
  }

  async generateWindowsConfig(printers, settings) {
    // Generate PowerShell script for Windows printer deployment
    const script = `
# OpenDirectory Printer Deployment Script for Windows
# Generated: ${new Date().toISOString()}

$ErrorActionPreference = "Stop"

function Install-NetworkPrinter {
    param(
        [string]$PrinterName,
        [string]$PrinterIP,
        [string]$PrinterPort,
        [string]$DriverName,
        [string]$Location,
        [string]$Comment,
        [bool]$SetAsDefault = $false,
        [string]$Protocol = "RAW"
    )
    
    try {
        # Create printer port
        $portName = "IP_$PrinterIP"
        
        if ($Protocol -eq "IPP") {
            # Create IPP port
            $port = ([WMICLASS]"Win32_TCPIPPrinterPort").CreateInstance()
            $port.Name = $portName
            $port.Protocol = 2  # IPP
            $port.HostAddress = $PrinterIP
            $port.PortNumber = if ($PrinterPort) { $PrinterPort } else { 631 }
            $port.Queue = "ipp/print"
            $port.SNMPEnabled = $false
            $port.Put() | Out-Null
        } else {
            # Create RAW TCP/IP port
            $port = ([WMICLASS]"Win32_TCPIPPrinterPort").CreateInstance()
            $port.Name = $portName
            $port.Protocol = 1  # RAW
            $port.HostAddress = $PrinterIP
            $port.PortNumber = if ($PrinterPort) { $PrinterPort } else { 9100 }
            $port.SNMPEnabled = $true
            $port.Put() | Out-Null
        }
        
        Write-Host "Created port: $portName"
        
        # Install printer driver if not already installed
        $driver = Get-PrinterDriver -Name $DriverName -ErrorAction SilentlyContinue
        if (-not $driver) {
            # Try to use a generic driver
            $genericDrivers = @(
                "Microsoft IPP Class Driver",
                "Generic / Text Only",
                "Microsoft Print to PDF",
                "Microsoft XPS Document Writer"
            )
            
            $driverInstalled = $false
            foreach ($genericDriver in $genericDrivers) {
                $driver = Get-PrinterDriver -Name $genericDriver -ErrorAction SilentlyContinue
                if ($driver) {
                    $DriverName = $genericDriver
                    $driverInstalled = $true
                    break
                }
            }
            
            if (-not $driverInstalled) {
                Write-Warning "Driver '$DriverName' not found. Using generic driver."
                $DriverName = "Generic / Text Only"
            }
        }
        
        # Add printer
        Add-Printer -Name $PrinterName `
                   -PortName $portName `
                   -DriverName $DriverName `
                   -Location $Location `
                   -Comment $Comment `
                   -Shared $false
        
        Write-Host "Installed printer: $PrinterName"
        
        # Set as default if requested
        if ($SetAsDefault) {
            Set-Printer -Name $PrinterName -Default
            Write-Host "Set as default printer: $PrinterName"
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to install printer $PrinterName : $_"
        return $false
    }
}

# Auto-detect and install IPP printers
function Discover-IPPPrinters {
    param([string]$Subnet = "192.168.1")
    
    Write-Host "Discovering IPP printers on subnet $Subnet..."
    
    $discovered = @()
    
    for ($i = 1; $i -le 254; $i++) {
        $ip = "$Subnet.$i"
        $port = 631
        
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($ip, $port, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne(100, $false)
        
        if ($wait) {
            try {
                $tcp.EndConnect($connect)
                Write-Host "Found IPP service at $ip"
                
                # Try to get printer info via HTTP
                $uri = "http://${ip}:${port}/ipp/print"
                $response = Invoke-WebRequest -Uri $uri -Method Head -TimeoutSec 2 -ErrorAction SilentlyContinue
                
                if ($response.StatusCode -eq 200) {
                    $discovered += @{
                        IP = $ip
                        Port = $port
                        Protocol = "IPP"
                    }
                }
            }
            catch { }
            finally {
                $tcp.Close()
            }
        }
    }
    
    return $discovered
}

# Main deployment
Write-Host "=========================================="
Write-Host "OpenDirectory Printer Deployment"
Write-Host "=========================================="

${this.generateWindowsPrinterCommands(printers, settings)}

# Auto-discovery if enabled
if ($${settings.autoDiscover !== false}) {
    Write-Host ""
    Write-Host "Running auto-discovery..."
    $discovered = Discover-IPPPrinters -Subnet "${settings.subnet || '192.168.1'}"
    
    foreach ($printer in $discovered) {
        $name = "AutoDiscovered_$($printer.IP)"
        if (-not (Get-Printer -Name $name -ErrorAction SilentlyContinue)) {
            Install-NetworkPrinter -PrinterName $name `
                                 -PrinterIP $printer.IP `
                                 -PrinterPort $printer.Port `
                                 -Protocol $printer.Protocol `
                                 -DriverName "Microsoft IPP Class Driver" `
                                 -Location "Auto-discovered" `
                                 -Comment "Auto-discovered IPP printer"
        }
    }
}

Write-Host ""
Write-Host "Deployment completed!"
Write-Host "Installed printers:"
Get-Printer | Where-Object { $_.Name -like "OD_*" -or $_.Name -like "AutoDiscovered_*" } | `
    Format-Table Name, DriverName, PortName, PrinterStatus -AutoSize
`;
    
    return {
      type: 'powershell',
      content: script,
      filename: 'deploy-printers.ps1',
      instructions: 'Run as Administrator: powershell -ExecutionPolicy Bypass -File deploy-printers.ps1'
    };
  }

  generateWindowsPrinterCommands(printers, settings) {
    return printers.map(printer => `
# Printer: ${printer.name}
Install-NetworkPrinter -PrinterName "OD_${printer.name}" \`
                      -PrinterIP "${printer.address}" \`
                      -PrinterPort ${printer.port || 9100} \`
                      -Protocol "${printer.protocol?.toUpperCase() || 'RAW'}" \`
                      -DriverName "${printer.driver || 'Microsoft IPP Class Driver'}" \`
                      -Location "${printer.location || ''}" \`
                      -Comment "${printer.description || ''}" \`
                      -SetAsDefault ${printer.isDefault ? '$true' : '$false'}
`).join('\n');
  }

  async generateMacOSConfig(printers, settings) {
    // Generate shell script for macOS printer deployment
    const script = `#!/bin/bash

# OpenDirectory Printer Deployment Script for macOS
# Generated: ${new Date().toISOString()}

set -e

echo "=========================================="
echo "OpenDirectory Printer Deployment for macOS"
echo "=========================================="

# Function to install printer
install_printer() {
    local name="$1"
    local address="$2"
    local protocol="$3"
    local driver="$4"
    local location="$5"
    local description="$6"
    local is_default="$7"
    
    # Build printer URI
    local uri=""
    case "$protocol" in
        ipp|IPP)
            uri="ipp://$address/ipp/print"
            ;;
        ipps|IPPS)
            uri="ipps://$address/ipp/print"
            ;;
        lpd|LPD)
            uri="lpd://$address"
            ;;
        socket|raw|RAW)
            uri="socket://$address"
            ;;
        *)
            uri="ipp://$address/ipp/print"
            ;;
    esac
    
    echo "Installing printer: $name"
    echo "  URI: $uri"
    
    # Add printer using lpadmin
    if [ -z "$driver" ] || [ "$driver" == "auto" ]; then
        # Use IPP Everywhere (driverless printing)
        lpadmin -p "$name" -E -v "$uri" -m everywhere
    else
        # Use specific driver
        lpadmin -p "$name" -E -v "$uri" -m "$driver"
    fi
    
    # Set location and description
    if [ -n "$location" ]; then
        lpadmin -p "$name" -L "$location"
    fi
    
    if [ -n "$description" ]; then
        lpadmin -p "$name" -D "$description"
    fi
    
    # Enable printer
    cupsenable "$name"
    cupsaccept "$name"
    
    # Set as default if requested
    if [ "$is_default" == "true" ]; then
        lpadmin -d "$name"
        echo "  Set as default printer"
    fi
    
    echo "  Successfully installed"
}

# Function to discover printers via DNS-SD
discover_printers() {
    echo ""
    echo "Discovering printers via DNS-SD/Bonjour..."
    
    # Use dns-sd to browse for IPP printers
    timeout 5 dns-sd -B _ipp._tcp local. 2>/dev/null | while read -r line; do
        if [[ $line == *"Instance"* ]]; then
            printer_name=$(echo "$line" | awk '{print $7}')
            if [ -n "$printer_name" ]; then
                echo "  Found: $printer_name"
                
                # Try to add via AirPrint
                lpadmin -p "Auto_$printer_name" -E -v "dnssd://$printer_name._ipp._tcp.local." -m everywhere 2>/dev/null || true
            fi
        fi
    done || true
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

${this.generateMacOSPrinterCommands(printers)}

# Auto-discovery if enabled
if [ "${settings.autoDiscover !== false ? 'true' : 'false'}" == "true" ]; then
    discover_printers
fi

echo ""
echo "Deployment completed!"
echo "Installed printers:"
lpstat -p | grep "OD_\\|Auto_"
`;
    
    return {
      type: 'bash',
      content: script,
      filename: 'deploy-printers.sh',
      instructions: 'Run as root: sudo bash deploy-printers.sh'
    };
  }

  generateMacOSPrinterCommands(printers) {
    return printers.map(printer => `
# Install ${printer.name}
install_printer "OD_${printer.name}" \\
                "${printer.address}" \\
                "${printer.protocol || 'ipp'}" \\
                "${printer.driver || 'auto'}" \\
                "${printer.location || ''}" \\
                "${printer.description || ''}" \\
                "${printer.isDefault ? 'true' : 'false'}"
`).join('\n');
  }

  async generateLinuxConfig(printers, settings) {
    // Generate shell script for Linux printer deployment
    const script = `#!/bin/bash

# OpenDirectory Printer Deployment Script for Linux
# Generated: ${new Date().toISOString()}

set -e

echo "=========================================="
echo "OpenDirectory Printer Deployment for Linux"
echo "=========================================="

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    DISTRO="unknown"
fi

# Function to install CUPS if not installed
ensure_cups() {
    if ! command -v lpadmin &> /dev/null; then
        echo "CUPS not found. Installing..."
        
        case "$DISTRO" in
            ubuntu|debian)
                apt-get update && apt-get install -y cups cups-client
                ;;
            fedora|rhel|centos)
                dnf install -y cups
                ;;
            arch)
                pacman -S --noconfirm cups
                ;;
            *)
                echo "Please install CUPS manually"
                exit 1
                ;;
        esac
        
        # Start CUPS service
        systemctl enable cups
        systemctl start cups
    fi
}

# Function to install printer
install_printer() {
    local name="$1"
    local uri="$2"
    local driver="$3"
    local location="$4"
    local description="$5"
    
    echo "Installing printer: $name"
    
    # Add printer
    lpadmin -p "$name" -E -v "$uri" -m "${driver:-everywhere}"
    
    # Set options
    [ -n "$location" ] && lpadmin -p "$name" -L "$location"
    [ -n "$description" ] && lpadmin -p "$name" -D "$description"
    
    # Enable and accept jobs
    cupsenable "$name"
    cupsaccept "$name"
    
    echo "  Installed successfully"
}

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Ensure CUPS is installed
ensure_cups

${this.generateLinuxPrinterCommands(printers)}

# Configure firewall if needed
if command -v firewall-cmd &> /dev/null; then
    echo "Configuring firewall..."
    firewall-cmd --permanent --add-service=ipp
    firewall-cmd --permanent --add-service=ipp-client
    firewall-cmd --reload
elif command -v ufw &> /dev/null; then
    echo "Configuring UFW..."
    ufw allow 631/tcp
    ufw allow 5353/udp
fi

echo ""
echo "Deployment completed!"
lpstat -t
`;
    
    return {
      type: 'bash',
      content: script,
      filename: 'deploy-printers-linux.sh',
      instructions: 'Run as root: sudo bash deploy-printers-linux.sh'
    };
  }

  generateLinuxPrinterCommands(printers) {
    return printers.map(printer => {
      const uri = this.buildPrinterURI(printer);
      return `
install_printer "OD_${printer.name}" \\
                "${uri}" \\
                "${printer.driver || 'everywhere'}" \\
                "${printer.location || ''}" \\
                "${printer.description || ''}"
`;
    }).join('\n');
  }

  async generateiOSConfig(printers, settings) {
    // Generate iOS configuration profile
    const profile = {
      PayloadContent: printers.map(printer => ({
        AirPrint: [
          {
            IPAddress: printer.address,
            ResourcePath: `/ipp/print`,
            Port: printer.port || 631,
            ForceTLS: printer.protocol === 'ipps'
          }
        ],
        PayloadDisplayName: `OpenDirectory Printer - ${printer.name}`,
        PayloadIdentifier: `com.opendirectory.printer.${printer.name}`,
        PayloadType: 'com.apple.airprint',
        PayloadUUID: this.generateUUID(),
        PayloadVersion: 1
      })),
      PayloadDisplayName: 'OpenDirectory Printers',
      PayloadIdentifier: 'com.opendirectory.printers',
      PayloadOrganization: settings.organization || 'OpenDirectory',
      PayloadType: 'Configuration',
      PayloadUUID: this.generateUUID(),
      PayloadVersion: 1
    };
    
    return {
      type: 'mobileconfig',
      content: this.plistStringify(profile),
      filename: 'opendirectory-printers.mobileconfig',
      instructions: 'Email or deploy via MDM. Users install by opening the profile.'
    };
  }

  async generateAndroidConfig(printers, settings) {
    // Generate Android printer configuration
    const config = {
      printers: printers.map(printer => ({
        name: printer.name,
        address: printer.address,
        port: printer.port || 631,
        protocol: printer.protocol || 'ipp',
        uri: this.buildPrinterURI(printer),
        description: printer.description,
        location: printer.location,
        capabilities: printer.capabilities || {}
      })),
      settings: {
        autoDiscover: settings.autoDiscover !== false,
        defaultPrinter: printers.find(p => p.isDefault)?.name
      }
    };
    
    // Generate intent URI for printer setup
    const intentUri = printers.map(printer => {
      const uri = this.buildPrinterURI(printer);
      return `intent://print/add?uri=${encodeURIComponent(uri)}&name=${encodeURIComponent(printer.name)}#Intent;scheme=opendirectory;package=com.opendirectory.mdm;end`;
    });
    
    return {
      type: 'json',
      content: JSON.stringify(config, null, 2),
      filename: 'android-printers.json',
      instructions: 'Deploy via MDM or import in OpenDirectory Android app',
      intents: intentUri
    };
  }

  async deployPrinters(targetDevices, printers, platform) {
    const results = [];
    
    for (const device of targetDevices) {
      try {
        const config = await this.generateConfig(platform, printers);
        const deployed = await this.pushToDevice(device, config, platform);
        
        results.push({
          device: device.id,
          status: 'success',
          message: 'Printers deployed successfully'
        });
      } catch (error) {
        results.push({
          device: device.id,
          status: 'failed',
          message: error.message
        });
      }
    }
    
    return results;
  }

  async pushToDevice(device, config, platform) {
    // This would integrate with your MDM system
    // For now, just log the deployment
    this.logger.info(`Deploying printers to device ${device.id} (${platform})`);
    
    // In a real implementation, this would:
    // 1. Connect to device via MDM agent
    // 2. Push configuration
    // 3. Execute installation script
    // 4. Verify installation
    
    return true;
  }

  buildPrinterURI(printer) {
    const { protocol = 'ipp', address, port } = printer;
    
    switch (protocol.toLowerCase()) {
      case 'ipp':
        return `ipp://${address}:${port || 631}/ipp/print`;
      case 'ipps':
        return `ipps://${address}:${port || 631}/ipp/print`;
      case 'lpd':
        return `lpd://${address}/`;
      case 'socket':
      case 'raw':
        return `socket://${address}:${port || 9100}`;
      default:
        return `ipp://${address}:${port || 631}/ipp/print`;
    }
  }

  generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16).toUpperCase();
    });
  }

  plistStringify(obj) {
    // Simple plist generation (would use plist library in production)
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n';
    xml += '<plist version="1.0">\n';
    xml += this.objectToPlist(obj, 1);
    xml += '</plist>\n';
    return xml;
  }

  objectToPlist(obj, indent = 0) {
    const tabs = '\t'.repeat(indent);
    let xml = `${tabs}<dict>\n`;
    
    for (const [key, value] of Object.entries(obj)) {
      xml += `${tabs}\t<key>${key}</key>\n`;
      
      if (Array.isArray(value)) {
        xml += `${tabs}\t<array>\n`;
        value.forEach(item => {
          if (typeof item === 'object') {
            xml += this.objectToPlist(item, indent + 2);
          } else {
            xml += `${tabs}\t\t<string>${item}</string>\n`;
          }
        });
        xml += `${tabs}\t</array>\n`;
      } else if (typeof value === 'object') {
        xml += this.objectToPlist(value, indent + 1);
      } else if (typeof value === 'boolean') {
        xml += `${tabs}\t<${value ? 'true' : 'false'}/>\n`;
      } else if (typeof value === 'number') {
        xml += `${tabs}\t<integer>${value}</integer>\n`;
      } else {
        xml += `${tabs}\t<string>${value}</string>\n`;
      }
    }
    
    xml += `${tabs}</dict>\n`;
    return xml;
  }
}

module.exports = PrinterDeployment;