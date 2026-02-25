const winston = require('winston');
const path = require('path');

/**
 * Printer Policy Management for OpenDirectory
 * Manages printer deployment through Group Policy equivalent
 */
class PrinterPolicyManager {
  constructor() {
    this.policies = new Map();
    this.deployments = new Map();
    
    // OpenDirectory Print Server configuration
    this.printServerConfig = {
      ip: process.env.OPENDIRECTORY_IP || this.getServerIP(),
      hostname: process.env.OPENDIRECTORY_HOSTNAME || 'opendirectory.local',
      port: process.env.PRINT_SERVER_PORT || 631,
      smbPort: 445,
      protocol: 'smb' // Primary protocol for Windows compatibility
    };
    
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: '/var/log/opendirectory/printer-policy.log' })
      ]
    });
  }
  
  /**
   * Create printer deployment policy (like Windows GPO)
   */
  async createPrinterPolicy(policyConfig) {
    try {
      const policy = {
        id: this.generatePolicyId(),
        name: policyConfig.name,
        description: policyConfig.description,
        enabled: true,
        
        // Policy settings
        settings: {
          action: policyConfig.action || 'Update', // Create, Replace, Update, Delete
          
          // Printers to deploy (pointing to OpenDirectory, not actual printer IPs)
          printers: policyConfig.printers?.map(printer => ({
            // CRITICAL: Network path points to OpenDirectory Print Server
            networkPath: `\\\\${this.printServerConfig.ip}\\${printer.shareName}`,
            alternativePaths: {
              hostname: `\\\\${this.printServerConfig.hostname}\\${printer.shareName}`,
              ipp: `ipp://${this.printServerConfig.ip}:631/printers/${printer.shareName}`,
              smb: `smb://${this.printServerConfig.ip}/${printer.shareName}`,
              lpd: `lpd://${this.printServerConfig.ip}/${printer.shareName}`
            },
            
            // Display information
            displayName: printer.displayName,
            location: printer.location,
            comment: printer.comment || 'Managed by OpenDirectory Print Server',
            
            // The actual printer IP (OpenDirectory manages this internally)
            deviceInfo: {
              actualPrinterIP: printer.actualPrinterIP, // e.g., 192.168.1.52
              manufacturer: printer.manufacturer,
              model: printer.model,
              managedBy: 'OpenDirectory Print Server'
            },
            
            // Printer settings
            settings: {
              default: printer.setAsDefault || false,
              shared: false, // Clients shouldn't re-share
              published: printer.publishInAD !== false,
              
              // Print preferences
              color: printer.color || false,
              duplex: printer.duplex || false,
              paperSize: printer.paperSize || 'A4',
              quality: printer.quality || 'Normal',
              
              // Advanced settings
              enableBidiSupport: true,
              renderOnServer: true, // OpenDirectory handles rendering
              directPrintingEnabled: false // Always go through OpenDirectory
            },
            
            // Permissions (enforced by OpenDirectory)
            permissions: {
              allowedUsers: printer.allowedUsers || ['Domain Users'],
              allowedGroups: printer.allowedGroups || ['Domain Users'],
              deniedUsers: printer.deniedUsers || [],
              deniedGroups: printer.deniedGroups || [],
              
              // Permission levels
              print: printer.permissions?.print || ['Domain Users'],
              managePrinter: printer.permissions?.manage || ['Print Operators', 'Domain Admins'],
              manageDocuments: printer.permissions?.manageDocuments || ['Document Owner']
            }
          })),
          
          // Deployment behavior
          deployment: {
            // Connection type
            userConnection: policyConfig.userConnection !== false,
            computerConnection: policyConfig.computerConnection || false,
            
            // Deployment options
            deployImmediately: policyConfig.deployImmediately !== false,
            waitForNetwork: true,
            retryOnError: true,
            maxRetries: 3,
            
            // Removal behavior
            removeOnPolicyRemoval: policyConfig.removeOnPolicyRemoval !== false,
            deletePrintersNotInPolicy: policyConfig.deletePrintersNotInPolicy || false,
            
            // Default printer behavior
            defaultPrinterBehavior: policyConfig.defaultPrinterBehavior || 'SetIfNoDefault'
            // Options: AlwaysSet, SetIfNoDefault, NeverSet, UserChoice
          },
          
          // Platform-specific settings
          platforms: {
            windows: {
              method: 'PrintManagement', // Uses Windows Print Management
              usePointAndPrint: true,
              trustedServers: [this.printServerConfig.ip, this.printServerConfig.hostname],
              packageInstallation: 'Enabled',
              driverInstallation: 'AllowSilent',
              
              // Generate connection command
              connectionScript: `rundll32 printui.dll,PrintUIEntry /in /n "\\\\${this.printServerConfig.ip}\\{printerShare}"`,
              
              // Advanced Windows settings
              printerMappingMode: 'Replace', // Replace, Update, Create
              runInUserContext: true,
              processingOrder: policyConfig.processingOrder || 100
            },
            
            macos: {
              method: 'ConfigurationProfile',
              protocol: 'SMB', // SMB for best compatibility with OpenDirectory
              authenticationRequired: true,
              
              // macOS specific printer options
              showInPrinterList: true,
              allowUserToModify: false,
              
              // Connection command for macOS
              connectionScript: `lpadmin -p "{printerName}" -E -v "smb://${this.printServerConfig.ip}/{printerShare}" -m everywhere`
            },
            
            linux: {
              method: 'CUPS',
              protocol: 'IPP', // IPP for Linux CUPS
              
              // Linux connection command
              connectionScript: `lpadmin -p "{printerName}" -E -v "ipp://${this.printServerConfig.ip}:631/printers/{printerShare}" -m everywhere`
            }
          }
        },
        
        // Policy targeting (like GPO filtering)
        targeting: {
          // Security filtering
          security: {
            users: policyConfig.targetUsers || [],
            groups: policyConfig.targetGroups || ['Domain Users'],
            computers: policyConfig.targetComputers || [],
            computerGroups: policyConfig.targetComputerGroups || []
          },
          
          // WMI-style filtering
          filters: {
            os: policyConfig.osFilter || ['Windows 10', 'Windows 11', 'macOS', 'Linux'],
            architecture: policyConfig.archFilter || ['x64', 'arm64'],
            
            // Network location awareness
            network: {
              subnets: policyConfig.subnets || [],
              sites: policyConfig.sites || [],
              requireDomainNetwork: policyConfig.requireDomainNetwork || false
            },
            
            // Item-level targeting (like GPP)
            itemLevel: {
              computerName: policyConfig.computerNamePattern || null,
              ipRange: policyConfig.ipRange || null,
              organizationalUnit: policyConfig.ou || null,
              ldapQuery: policyConfig.ldapQuery || null,
              
              // Time-based
              timeRange: policyConfig.timeRange || null,
              dayOfWeek: policyConfig.dayOfWeek || null
            }
          },
          
          // Exclusions
          exclude: {
            users: policyConfig.excludeUsers || [],
            groups: policyConfig.excludeGroups || [],
            computers: policyConfig.excludeComputers || [],
            computerGroups: policyConfig.excludeComputerGroups || []
          }
        },
        
        // Policy metadata
        metadata: {
          createdAt: new Date(),
          createdBy: policyConfig.createdBy || 'admin',
          modifiedAt: new Date(),
          modifiedBy: policyConfig.createdBy || 'admin',
          version: 1,
          
          // GPO-style links
          links: {
            domain: policyConfig.linkToDomain || false,
            sites: policyConfig.linkedSites || [],
            ous: policyConfig.linkedOUs || []
          },
          
          // Processing options
          processing: {
            enforced: policyConfig.enforced || false, // Cannot be overridden
            inheritanceBlocked: false,
            priority: policyConfig.priority || 100,
            
            // Loopback processing (for terminal servers, etc.)
            loopbackMode: policyConfig.loopbackMode || 'None', // None, Replace, Merge
            
            // Performance options
            asyncProcessing: true,
            slowLinkThreshold: 500, // ms
            processOnSlowLink: false
          }
        }
      };
      
      // Validate policy
      this.validatePolicy(policy);
      
      // Store policy
      this.policies.set(policy.id, policy);
      
      // Generate deployment packages for each platform
      const deploymentPackages = await this.generateDeploymentPackages(policy);
      
      this.logger.info(`Printer policy created: ${policy.name} with ${policy.settings.printers.length} printers`);
      
      return {
        success: true,
        policyId: policy.id,
        name: policy.name,
        printers: policy.settings.printers.map(p => ({
          name: p.displayName,
          path: p.networkPath
        })),
        deploymentPackages
      };
      
    } catch (error) {
      this.logger.error('Failed to create printer policy:', error);
      throw error;
    }
  }
  
  /**
   * Generate deployment packages for each platform
   */
  async generateDeploymentPackages(policy) {
    const packages = {};
    
    // Windows deployment package (PowerShell)
    packages.windows = this.generateWindowsDeployment(policy);
    
    // macOS deployment package (Configuration Profile)
    packages.macos = this.generateMacOSDeployment(policy);
    
    // Linux deployment package (Shell script)
    packages.linux = this.generateLinuxDeployment(policy);
    
    return packages;
  }
  
  generateWindowsDeployment(policy) {
    const printers = policy.settings.printers;
    
    const script = `
# OpenDirectory Printer Deployment Policy
# Policy: ${policy.name}
# Generated: ${new Date().toISOString()}
# ============================================

$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

# OpenDirectory Print Server Configuration
$PrintServer = "${this.printServerConfig.ip}"
$PrintServerName = "${this.printServerConfig.hostname}"

Write-Host "========================================="
Write-Host "OpenDirectory Printer Deployment"
Write-Host "Policy: ${policy.name}"
Write-Host "Server: $PrintServer"
Write-Host "========================================="

# Function to test print server connectivity
function Test-PrintServer {
    param($Server)
    
    Write-Verbose "Testing connection to print server: $Server"
    
    # Test SMB connectivity
    $smbTest = Test-NetConnection -ComputerName $Server -Port 445 -InformationLevel Quiet
    if (-not $smbTest) {
        throw "Cannot connect to print server on SMB port 445"
    }
    
    # Test if we can access the print share
    try {
        $null = Get-ChildItem "\\\\$Server" -ErrorAction Stop
        Write-Verbose "Successfully connected to print server"
        return $true
    } catch {
        throw "Cannot access print server shares: $_"
    }
}

# Function to remove existing printer connections
function Remove-ExistingPrinters {
    param($PrinterPaths)
    
    $existingPrinters = Get-Printer | Where-Object { $_.Type -eq 'Connection' }
    
    foreach ($printer in $existingPrinters) {
        if ($PrinterPaths -contains $printer.Name) {
            Write-Verbose "Removing existing printer: $($printer.Name)"
            Remove-Printer -Name $printer.Name -ErrorAction SilentlyContinue
        }
    }
}

# Function to add printer connection
function Add-PrinterConnection {
    param(
        [string]$PrinterPath,
        [string]$DisplayName,
        [bool]$SetAsDefault
    )
    
    try {
        Write-Host "Adding printer: $DisplayName"
        Write-Verbose "Printer path: $PrinterPath"
        
        # Add the printer connection
        Add-Printer -ConnectionName $PrinterPath -ErrorAction Stop
        
        # Verify printer was added
        $printer = Get-Printer | Where-Object { $_.Name -eq $PrinterPath }
        if ($null -eq $printer) {
            throw "Printer was not added successfully"
        }
        
        Write-Host "✓ Successfully added: $DisplayName" -ForegroundColor Green
        
        # Set as default if specified
        if ($SetAsDefault) {
            $printer.SetDefaultPrinter()
            Write-Host "✓ Set as default printer" -ForegroundColor Green
        }
        
        return $true
        
    } catch {
        Write-Warning "Failed to add printer $DisplayName : $_"
        return $false
    }
}

# Main deployment logic
try {
    # Test connectivity to OpenDirectory Print Server
    Test-PrintServer -Server $PrintServer
    
    # Policy action: ${policy.settings.action}
    $action = "${policy.settings.action}"
    
    # Build list of printers to deploy
    $printersToAdd = @(
${printers.map(p => `        @{
            Path = "${p.networkPath}"
            DisplayName = "${p.displayName}"
            Location = "${p.location}"
            SetAsDefault = $${p.settings.default.toString()}
            Comment = "${p.comment}"
        }`).join(',\n')}
    )
    
    # Remove existing printers if action is Replace
    if ($action -eq "Replace") {
        Write-Verbose "Policy action is Replace - removing existing printers"
        $printerPaths = $printersToAdd | ForEach-Object { $_.Path }
        Remove-ExistingPrinters -PrinterPaths $printerPaths
    }
    
    # Deploy printers
    $successCount = 0
    $failCount = 0
    
    foreach ($printer in $printersToAdd) {
        $result = Add-PrinterConnection -PrinterPath $printer.Path `
                                       -DisplayName $printer.DisplayName `
                                       -SetAsDefault $printer.SetAsDefault
        
        if ($result) {
            $successCount++
        } else {
            $failCount++
        }
    }
    
    # Summary
    Write-Host ""
    Write-Host "========================================="
    Write-Host "Deployment Summary:" -ForegroundColor Cyan
    Write-Host "  Successful: $successCount printers" -ForegroundColor Green
    if ($failCount -gt 0) {
        Write-Host "  Failed: $failCount printers" -ForegroundColor Yellow
    }
    Write-Host "========================================="
    
    # Report back to OpenDirectory
    $result = @{
        PolicyId = "${policy.id}"
        PolicyName = "${policy.name}"
        Success = $successCount
        Failed = $failCount
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ComputerName = $env:COMPUTERNAME
        UserName = $env:USERNAME
    }
    
    # Send result to OpenDirectory (if online)
    try {
        $json = $result | ConvertTo-Json
        Invoke-RestMethod -Uri "http://$PrintServer:3000/api/policy/report" `
                         -Method POST `
                         -Body $json `
                         -ContentType "application/json" `
                         -ErrorAction SilentlyContinue
    } catch {
        # Silently fail if cannot report back
    }
    
    exit 0
    
} catch {
    Write-Error "Printer deployment failed: $_"
    exit 1
}
`;
    
    return {
      type: 'PowerShell',
      filename: `Deploy-Printers-${policy.id}.ps1`,
      content: script,
      encoding: 'UTF-8',
      execution: 'powershell.exe -ExecutionPolicy Bypass -File'
    };
  }
  
  generateMacOSDeployment(policy) {
    const printers = policy.settings.printers;
    
    const script = `#!/bin/bash
# OpenDirectory Printer Deployment for macOS
# Policy: ${policy.name}
# Generated: ${new Date().toISOString()}
# ============================================

# Configuration
PRINT_SERVER="${this.printServerConfig.ip}"
PRINT_SERVER_NAME="${this.printServerConfig.hostname}"
POLICY_NAME="${policy.name}"

echo "========================================="
echo "OpenDirectory Printer Deployment"
echo "Policy: $POLICY_NAME"
echo "Server: $PRINT_SERVER"
echo "========================================="

# Check if running with admin privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script requires administrator privileges"
   echo "Please run with sudo"
   exit 1
fi

# Function to add printer
add_printer() {
    local printer_name="$1"
    local printer_uri="$2"
    local display_name="$3"
    local location="$4"
    local set_default="$5"
    
    echo "Adding printer: $display_name"
    
    # Remove existing printer if it exists
    lpadmin -x "$printer_name" 2>/dev/null
    
    # Add printer using generic PPD (or specific if available)
    lpadmin -p "$printer_name" -E \\
        -v "$printer_uri" \\
        -D "$display_name" \\
        -L "$location" \\
        -m everywhere \\
        -o printer-is-shared=false
    
    if [ $? -eq 0 ]; then
        echo "✓ Successfully added: $display_name"
        
        # Set as default if specified
        if [ "$set_default" == "true" ]; then
            lpoptions -d "$printer_name"
            echo "✓ Set as default printer"
        fi
        
        return 0
    else
        echo "✗ Failed to add: $display_name"
        return 1
    fi
}

# Deploy printers
SUCCESS_COUNT=0
FAIL_COUNT=0

${printers.map(p => `
# Printer: ${p.displayName}
add_printer \\
    "${p.shareName || p.displayName.replace(/\s+/g, '-')}" \\
    "smb://$PRINT_SERVER/${p.shareName || p.displayName.replace(/\s+/g, '-')}" \\
    "${p.displayName}" \\
    "${p.location}" \\
    "${p.settings.default}"

if [ $? -eq 0 ]; then
    ((SUCCESS_COUNT++))
else
    ((FAIL_COUNT++))
fi
`).join('\n')}

# Summary
echo ""
echo "========================================="
echo "Deployment Summary:"
echo "  Successful: $SUCCESS_COUNT printers"
if [ $FAIL_COUNT -gt 0 ]; then
    echo "  Failed: $FAIL_COUNT printers"
fi
echo "========================================="

# Report back to OpenDirectory
curl -X POST "http://$PRINT_SERVER:3000/api/policy/report" \\
    -H "Content-Type: application/json" \\
    -d "{\\"PolicyId\\":\\"${policy.id}\\",\\"Success\\":$SUCCESS_COUNT,\\"Failed\\":$FAIL_COUNT}" \\
    2>/dev/null

exit 0
`;
    
    return {
      type: 'Shell',
      filename: `deploy-printers-${policy.id}.sh`,
      content: script,
      encoding: 'UTF-8',
      execution: 'bash'
    };
  }
  
  generateLinuxDeployment(policy) {
    const printers = policy.settings.printers;
    
    const script = `#!/bin/bash
# OpenDirectory Printer Deployment for Linux
# Policy: ${policy.name}
# Generated: ${new Date().toISOString()}
# ============================================

# Configuration
PRINT_SERVER="${this.printServerConfig.ip}"
POLICY_NAME="${policy.name}"

echo "========================================="
echo "OpenDirectory Printer Deployment"
echo "Policy: $POLICY_NAME"
echo "Server: $PRINT_SERVER"
echo "========================================="

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Ensure CUPS is installed
if ! command -v lpadmin &> /dev/null; then
    echo "Installing CUPS..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y cups cups-client
    elif command -v yum &> /dev/null; then
        yum install -y cups
    fi
fi

# Function to add printer
add_printer() {
    local printer_name="$1"
    local printer_uri="$2"
    local display_name="$3"
    local location="$4"
    local set_default="$5"
    
    echo "Adding printer: $display_name"
    
    # Remove existing printer if it exists
    lpadmin -x "$printer_name" 2>/dev/null
    
    # Add printer
    lpadmin -p "$printer_name" -E \\
        -v "$printer_uri" \\
        -D "$display_name" \\
        -L "$location" \\
        -m everywhere
    
    if [ $? -eq 0 ]; then
        # Enable and accept jobs
        cupsenable "$printer_name"
        cupsaccept "$printer_name"
        
        echo "✓ Successfully added: $display_name"
        
        # Set as default if specified
        if [ "$set_default" == "true" ]; then
            lpoptions -d "$printer_name"
            echo "✓ Set as default printer"
        fi
        
        return 0
    else
        echo "✗ Failed to add: $display_name"
        return 1
    fi
}

# Deploy printers
SUCCESS_COUNT=0
FAIL_COUNT=0

${printers.map(p => `
# Printer: ${p.displayName}
add_printer \\
    "${p.shareName || p.displayName.replace(/\s+/g, '-')}" \\
    "ipp://$PRINT_SERVER:631/printers/${p.shareName || p.displayName.replace(/\s+/g, '-')}" \\
    "${p.displayName}" \\
    "${p.location}" \\
    "${p.settings.default}"

if [ $? -eq 0 ]; then
    ((SUCCESS_COUNT++))
else
    ((FAIL_COUNT++))
fi
`).join('\n')}

# Summary
echo ""
echo "========================================="
echo "Deployment Summary:"
echo "  Successful: $SUCCESS_COUNT printers"
if [ $FAIL_COUNT -gt 0 ]; then
    echo "  Failed: $FAIL_COUNT printers"
fi
echo "========================================="

exit 0
`;
    
    return {
      type: 'Shell',
      filename: `deploy-printers-${policy.id}.sh`,
      content: script,
      encoding: 'UTF-8',
      execution: 'bash'
    };
  }
  
  validatePolicy(policy) {
    if (!policy.name) {
      throw new Error('Policy name is required');
    }
    
    if (!policy.settings.printers || policy.settings.printers.length === 0) {
      throw new Error('At least one printer must be specified');
    }
    
    // Validate each printer configuration
    for (const printer of policy.settings.printers) {
      if (!printer.shareName && !printer.displayName) {
        throw new Error('Printer must have a share name or display name');
      }
      
      if (!printer.deviceInfo?.actualPrinterIP) {
        throw new Error('Actual printer IP address is required');
      }
    }
  }
  
  generatePolicyId() {
    return `POL-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
  
  getServerIP() {
    const interfaces = require('os').networkInterfaces();
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
          return iface.address;
        }
      }
    }
    return '127.0.0.1';
  }
  
  /**
   * Apply policy to target
   */
  async applyPolicy(policyId, targetInfo) {
    const policy = this.policies.get(policyId);
    if (!policy) {
      throw new Error('Policy not found');
    }
    
    // Check if target matches policy criteria
    if (!this.isTargetEligible(policy, targetInfo)) {
      return {
        success: false,
        reason: 'Target does not match policy criteria'
      };
    }
    
    // Get appropriate deployment package
    const platform = targetInfo.platform.toLowerCase();
    const deployment = await this.generateDeploymentPackages(policy);
    const package = deployment[platform];
    
    if (!package) {
      throw new Error(`No deployment package for platform: ${platform}`);
    }
    
    // Track deployment
    const deploymentId = `DEP-${Date.now()}`;
    this.deployments.set(deploymentId, {
      policyId,
      targetId: targetInfo.id,
      platform,
      status: 'pending',
      startedAt: new Date()
    });
    
    return {
      success: true,
      deploymentId,
      package
    };
  }
  
  isTargetEligible(policy, targetInfo) {
    const targeting = policy.targeting;
    
    // Check security filtering
    if (targeting.security.groups.length > 0) {
      const hasGroup = targeting.security.groups.some(g => 
        targetInfo.groups?.includes(g)
      );
      if (!hasGroup) return false;
    }
    
    // Check OS filter
    if (targeting.filters.os.length > 0) {
      const osMatch = targeting.filters.os.some(os => 
        targetInfo.os?.toLowerCase().includes(os.toLowerCase())
      );
      if (!osMatch) return false;
    }
    
    // Check exclusions
    if (targeting.exclude.groups.some(g => targetInfo.groups?.includes(g))) {
      return false;
    }
    
    return true;
  }
}

module.exports = PrinterPolicyManager;