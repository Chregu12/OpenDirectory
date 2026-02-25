const winston = require('winston');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

/**
 * OpenDirectory Group Policy Engine
 * Complete Windows Group Policy Management replacement
 * Manages all policy types for cross-platform deployment
 */
class GroupPolicyEngine {
  constructor() {
    this.policies = new Map();
    this.policyTemplates = new Map();
    this.deploymentStatus = new Map();
    
    // Policy processing order (like Windows GPO)
    this.processingOrder = {
      computer: [
        'SecuritySettings',
        'SoftwareInstallation',
        'RegistrySettings',
        'NetworkDrives',
        'PowerManagement',
        'Scripts'
      ],
      user: [
        'FolderRedirection',
        'NetworkDrives',
        'DesktopSettings',
        'SoftwareInstallation',
        'PrinterDeployment',
        'Scripts'
      ]
    };
    
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: '/var/log/opendirectory/group-policy.log' })
      ]
    });
  }
  
  /**
   * Create comprehensive Group Policy Object (GPO)
   */
  async createGroupPolicy(config) {
    try {
      const policy = {
        id: this.generatePolicyId(),
        name: config.name,
        description: config.description,
        enabled: config.enabled !== false,
        
        // GPO Version (like Windows)
        version: {
          user: 0,
          computer: 0,
          revision: 1
        },
        
        // Policy Settings by Category
        computerConfiguration: {
          // Software Installation
          softwareInstallation: config.computer?.software || {
            packages: [],
            deploymentMethod: 'Assigned', // Assigned or Published
            installDuringStartup: true,
            uninstallWhenOutOfScope: true,
            upgradeExisting: true
          },
          
          // Windows Settings equivalent
          windowsSettings: {
            // Security Settings
            securitySettings: config.computer?.security || {
              passwordPolicy: {
                minimumLength: 8,
                complexity: true,
                maxAge: 90,
                minAge: 1,
                history: 24,
                reversibleEncryption: false
              },
              accountLockout: {
                threshold: 5,
                duration: 30,
                resetAfter: 30
              },
              auditPolicy: {
                logonEvents: 'Success, Failure',
                objectAccess: 'Failure',
                policyChange: 'Success, Failure',
                privilegeUse: 'Failure',
                systemEvents: 'Success, Failure'
              },
              userRights: {
                allowLogOnLocally: ['Administrators', 'Users'],
                denyLogOnLocally: ['Guest'],
                shutDownSystem: ['Administrators'],
                changeSystemTime: ['Administrators']
              },
              securityOptions: {
                interactiveLogon: {
                  doNotDisplayLastUser: true,
                  requireCtrlAltDel: true,
                  messageTitle: 'OpenDirectory Security Notice',
                  messageText: 'Authorized Users Only'
                },
                networkSecurity: {
                  lanManagerAuth: 'NTLMv2 only',
                  minimumSessionSecurity: 128,
                  requireSigning: true
                }
              },
              firewall: {
                domain: { enabled: true, defaultInbound: 'Block', defaultOutbound: 'Allow' },
                private: { enabled: true, defaultInbound: 'Block', defaultOutbound: 'Allow' },
                public: { enabled: true, defaultInbound: 'Block', defaultOutbound: 'Allow' },
                rules: []
              }
            },
            
            // Registry Settings (Administrative Templates)
            registrySettings: config.computer?.registry || {
              policies: [],
              preferences: []
            },
            
            // Scripts
            scripts: config.computer?.scripts || {
              startup: [],
              shutdown: []
            }
          },
          
          // Administrative Templates
          administrativeTemplates: config.computer?.adminTemplates || {
            system: {
              disableRegistryTools: false,
              disableTaskManager: false,
              disableCMD: false,
              removableStorageAccess: {
                cdDvd: { read: true, write: true },
                floppyDrives: { read: false, write: false },
                removableDisks: { read: true, write: true }
              }
            },
            network: {
              dnsClient: {
                primaryDnsSuffix: 'domain.local',
                searchList: ['domain.local'],
                devolution: true
              },
              lanManager: {
                enableInsecureGuestLogons: false
              }
            },
            windowsComponents: {
              windowsUpdate: {
                configureAutomaticUpdates: 'Enabled',
                scheduledInstallDay: 'Sunday',
                scheduledInstallTime: '03:00',
                noAutoRestart: false
              },
              remoteDesktop: {
                allowRemoteConnections: true,
                requireNLA: true,
                setTimeLimit: true,
                maxIdleTime: 60,
                maxDisconnectionTime: 10
              },
              bitLocker: {
                requireEncryption: true,
                encryptionMethod: 'AES256',
                requireTPM: true
              }
            }
          },
          
          // Preferences (like GPP)
          preferences: config.computer?.preferences || {
            powerManagement: {
              powerPlans: [],
              sleepSettings: {},
              hibernation: {}
            },
            networkShares: {
              drives: []
            },
            environmentVariables: [],
            shortcuts: [],
            files: [],
            folders: [],
            iniFiles: [],
            registry: []
          }
        },
        
        userConfiguration: {
          // Software Installation
          softwareInstallation: config.user?.software || {
            packages: [],
            deploymentMethod: 'Published',
            installOnDemand: true
          },
          
          // Windows Settings
          windowsSettings: {
            // Folder Redirection
            folderRedirection: config.user?.folderRedirection || {
              documents: {
                enabled: false,
                target: '\\\\server\\users\\%USERNAME%\\Documents',
                grantExclusiveRights: true,
                moveContents: true
              },
              desktop: {
                enabled: false,
                target: '\\\\server\\users\\%USERNAME%\\Desktop'
              },
              pictures: {
                enabled: false,
                target: '\\\\server\\users\\%USERNAME%\\Pictures'
              },
              appData: {
                enabled: false,
                target: '\\\\server\\users\\%USERNAME%\\AppData\\Roaming'
              }
            },
            
            // Internet Explorer Maintenance (legacy but included)
            internetExplorer: config.user?.internetExplorer || {
              homePage: 'https://company.local',
              proxySettings: {
                enabled: false,
                server: '',
                exceptions: ''
              },
              security: {
                trustedSites: [],
                restrictedSites: []
              }
            },
            
            // Scripts
            scripts: config.user?.scripts || {
              logon: [],
              logoff: []
            }
          },
          
          // Administrative Templates
          administrativeTemplates: config.user?.adminTemplates || {
            controlPanel: {
              prohibitAccess: false,
              hideSpecifiedItems: [],
              showOnlySpecified: []
            },
            desktop: {
              wallpaper: {
                path: '',
                style: 'Fill' // Fill, Fit, Stretch, Tile, Center
              },
              hideDesktopIcons: false,
              removeRecycleBin: false,
              preventChanges: false,
              screensaver: {
                enabled: true,
                timeout: 600,
                secure: true,
                executable: ''
              }
            },
            startMenu: {
              removeRun: false,
              removeShutdown: false,
              removeNetworkConnections: false,
              removeProgramsAndFeatures: false,
              forceClassicStartMenu: false,
              disableContextMenus: false,
              pinnedPrograms: [],
              prohibitedPrograms: []
            },
            taskbar: {
              lockTaskbar: true,
              hideSystemTray: false,
              disableNotifications: false,
              turnOffNotificationArea: false
            },
            explorer: {
              hideSpecifiedDrives: [],
              noViewOnDrive: [],
              hideFileExtensions: false,
              hideHiddenFiles: false,
              disableRegistryEditing: false,
              disableCommandPrompt: false,
              removeFolderOptions: false
            },
            system: {
              disableTaskManager: false,
              disableChangePassword: false,
              disableLockWorkstation: false,
              disableLogOff: false,
              removableStorage: {
                denyAll: false,
                denyRead: [],
                denyWrite: []
              }
            },
            network: {
              hideNetworkIcon: false,
              prohibitNetworkBridge: false,
              disableFileSharing: false
            }
          },
          
          // Preferences
          preferences: config.user?.preferences || {
            driveMappings: [],
            printers: [],
            shortcuts: [],
            files: [],
            folders: [],
            registry: [],
            environmentVariables: [],
            internetSettings: []
          }
        },
        
        // Policy Scope and Filtering (like Windows GPO)
        scope: {
          // Link locations (where policy applies)
          links: config.scope?.links || {
            domain: false,
            sites: [],
            organizationalUnits: []
          },
          
          // Security Filtering
          securityFiltering: config.scope?.security || {
            applyTo: {
              users: [],
              groups: ['Domain Users'],
              computers: [],
              computerGroups: []
            },
            deny: {
              users: [],
              groups: [],
              computers: [],
              computerGroups: []
            }
          },
          
          // WMI Filtering
          wmiFilter: config.scope?.wmiFilter || {
            enabled: false,
            queries: []
          },
          
          // Advanced options
          options: {
            enforced: config.scope?.enforced || false, // Cannot be blocked
            inheritanceBlocked: false,
            userPolicyLoopback: 'None', // None, Merge, Replace
            
            // Processing options
            disableUserConfiguration: false,
            disableComputerConfiguration: false,
            
            // Performance
            slowLinkDetection: true,
            slowLinkThreshold: 500, // Kbps
            processEvenOnSlowLink: false,
            
            // Targeting
            itemLevelTargeting: config.scope?.targeting || {
              enabled: false,
              rules: []
            }
          }
        },
        
        // Delegation (permissions)
        delegation: config.delegation || {
          owner: 'Domain Admins',
          permissions: [
            { trustee: 'Domain Admins', rights: ['Read', 'Write', 'Create', 'Delete', 'Modify', 'Apply'] },
            { trustee: 'Authenticated Users', rights: ['Read', 'Apply'] }
          ]
        },
        
        // Metadata
        metadata: {
          created: new Date(),
          modified: new Date(),
          createdBy: config.createdBy || 'admin',
          modifiedBy: config.createdBy || 'admin',
          
          // GPO status
          status: {
            computer: 'Enabled',
            user: 'Enabled',
            overall: 'Enabled'
          },
          
          // Backup info
          backup: {
            lastBackup: null,
            backupLocation: null
          },
          
          // Comments and documentation
          comments: config.comments || '',
          changeLog: [{
            date: new Date(),
            user: config.createdBy || 'admin',
            action: 'Created',
            description: 'Initial policy creation'
          }]
        }
      };
      
      // Validate policy
      this.validatePolicy(policy);
      
      // Generate deployment packages for each platform
      const deployments = await this.generateDeploymentPackages(policy);
      
      // Store policy
      this.policies.set(policy.id, policy);
      
      // Save to persistent storage
      await this.savePolicyToStorage(policy);
      
      this.logger.info(`Group Policy created: ${policy.name} (${policy.id})`);
      
      return {
        success: true,
        policyId: policy.id,
        name: policy.name,
        deployments
      };
      
    } catch (error) {
      this.logger.error('Failed to create group policy:', error);
      throw error;
    }
  }
  
  /**
   * Generate platform-specific deployment packages
   */
  async generateDeploymentPackages(policy) {
    const packages = {};
    
    // Windows deployment
    packages.windows = await this.generateWindowsGPO(policy);
    
    // macOS deployment (Configuration Profiles + Scripts)
    packages.macos = await this.generateMacOSProfile(policy);
    
    // Linux deployment (Scripts + Config files)
    packages.linux = await this.generateLinuxPolicy(policy);
    
    return packages;
  }
  
  /**
   * Generate Windows GPO deployment
   */
  async generateWindowsGPO(policy) {
    const scripts = [];
    const registryFiles = [];
    const admxTemplates = [];
    
    // Generate PowerShell script for Computer Configuration
    if (policy.computerConfiguration) {
      const computerScript = await this.generateWindowsComputerScript(policy);
      scripts.push({
        name: 'ComputerConfiguration.ps1',
        content: computerScript,
        type: 'startup'
      });
    }
    
    // Generate PowerShell script for User Configuration
    if (policy.userConfiguration) {
      const userScript = await this.generateWindowsUserScript(policy);
      scripts.push({
        name: 'UserConfiguration.ps1',
        content: userScript,
        type: 'logon'
      });
    }
    
    // Generate Registry files
    const regFile = await this.generateRegistryFile(policy);
    if (regFile) {
      registryFiles.push({
        name: `${policy.id}.reg`,
        content: regFile
      });
    }
    
    // Generate ADMX templates
    const admx = await this.generateADMXTemplate(policy);
    if (admx) {
      admxTemplates.push(admx);
    }
    
    return {
      platform: 'windows',
      scripts,
      registryFiles,
      admxTemplates,
      deployment: {
        method: 'GPO',
        path: `\\\\${process.env.OPENDIRECTORY_IP}\\SYSVOL\\domain.local\\Policies\\{${policy.id}}`
      }
    };
  }
  
  /**
   * Generate macOS Configuration Profile
   */
  async generateMacOSProfile(policy) {
    const profile = {
      PayloadDisplayName: policy.name,
      PayloadIdentifier: `com.opendirectory.policy.${policy.id}`,
      PayloadOrganization: 'OpenDirectory',
      PayloadType: 'Configuration',
      PayloadUUID: policy.id,
      PayloadVersion: 1,
      PayloadContent: []
    };
    
    // Add payloads based on policy settings
    
    // Password policy
    if (policy.computerConfiguration?.windowsSettings?.securitySettings?.passwordPolicy) {
      const pwPolicy = policy.computerConfiguration.windowsSettings.securitySettings.passwordPolicy;
      profile.PayloadContent.push({
        PayloadType: 'com.apple.mobiledevice.passwordpolicy',
        PayloadIdentifier: `com.opendirectory.passwordpolicy.${policy.id}`,
        PayloadUUID: crypto.randomUUID(),
        PayloadVersion: 1,
        minLength: pwPolicy.minimumLength,
        requireAlphanumeric: pwPolicy.complexity,
        maxPINAgeInDays: pwPolicy.maxAge
      });
    }
    
    // Network drives
    if (policy.userConfiguration?.preferences?.driveMappings?.length > 0) {
      for (const drive of policy.userConfiguration.preferences.driveMappings) {
        profile.PayloadContent.push({
          PayloadType: 'com.apple.desktop',
          PayloadIdentifier: `com.opendirectory.drive.${drive.letter}`,
          PayloadUUID: crypto.randomUUID(),
          PayloadVersion: 1,
          mountedVolumes: [{
            url: drive.path.replace(/\\/g, '/').replace('//', 'smb://'),
            mountPoint: `/Volumes/${drive.label || drive.letter}`
          }]
        });
      }
    }
    
    return {
      platform: 'macos',
      profile: profile,
      format: 'mobileconfig',
      deployment: {
        method: 'MDM',
        installCommand: `profiles install -type configuration -path ${policy.id}.mobileconfig`
      }
    };
  }
  
  /**
   * Generate Linux policy deployment
   */
  async generateLinuxPolicy(policy) {
    const scripts = [];
    const configs = [];
    
    // Generate main policy script
    const mainScript = `#!/bin/bash
# OpenDirectory Group Policy for Linux
# Policy: ${policy.name}
# ID: ${policy.id}

POLICY_DIR="/etc/opendirectory/policies"
LOG_FILE="/var/log/opendirectory/policy-${policy.id}.log"

log() {
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"
}

log "Applying policy: ${policy.name}"

# Create policy directory
mkdir -p "\$POLICY_DIR"

${this.generateLinuxSecuritySettings(policy)}
${this.generateLinuxDriveMappings(policy)}
${this.generateLinuxSoftwareInstallation(policy)}
${this.generateLinuxDesktopSettings(policy)}

log "Policy application completed"
exit 0
`;
    
    scripts.push({
      name: `apply-policy-${policy.id}.sh`,
      content: mainScript,
      executable: true
    });
    
    // Generate systemd service for policy enforcement
    const serviceFile = `[Unit]
Description=OpenDirectory Policy ${policy.name}
After=network.target

[Service]
Type=oneshot
ExecStart=/etc/opendirectory/policies/apply-policy-${policy.id}.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`;
    
    configs.push({
      name: `opendirectory-policy-${policy.id}.service`,
      content: serviceFile,
      path: '/etc/systemd/system/'
    });
    
    return {
      platform: 'linux',
      scripts,
      configs,
      deployment: {
        method: 'SystemD',
        enableCommand: `systemctl enable opendirectory-policy-${policy.id}.service`,
        startCommand: `systemctl start opendirectory-policy-${policy.id}.service`
      }
    };
  }
  
  /**
   * Generate Windows Computer Configuration Script
   */
  async generateWindowsComputerScript(policy) {
    const comp = policy.computerConfiguration;
    
    return `# OpenDirectory Group Policy - Computer Configuration
# Policy: ${policy.name}
# Generated: ${new Date().toISOString()}

\$ErrorActionPreference = "Stop"
\$VerbosePreference = "Continue"

# Create event log source
if (-not [System.Diagnostics.EventLog]::SourceExists("OpenDirectory GPO")) {
    New-EventLog -LogName Application -Source "OpenDirectory GPO"
}

Write-EventLog -LogName Application -Source "OpenDirectory GPO" -EventId 1000 -Message "Starting Computer Configuration for ${policy.name}"

# Security Settings
${comp.windowsSettings?.securitySettings ? this.generateWindowsSecuritySettings(comp.windowsSettings.securitySettings) : ''}

# Software Installation
${comp.softwareInstallation?.packages?.length > 0 ? this.generateWindowsSoftwareInstallation(comp.softwareInstallation) : ''}

# Registry Settings
${comp.windowsSettings?.registrySettings ? this.generateWindowsRegistrySettings(comp.windowsSettings.registrySettings) : ''}

# Administrative Templates
${comp.administrativeTemplates ? this.generateWindowsAdminTemplates(comp.administrativeTemplates) : ''}

# Power Management
${comp.preferences?.powerManagement ? this.generateWindowsPowerManagement(comp.preferences.powerManagement) : ''}

# Startup Scripts
${comp.windowsSettings?.scripts?.startup?.length > 0 ? this.generateWindowsScripts(comp.windowsSettings.scripts.startup, 'Startup') : ''}

Write-EventLog -LogName Application -Source "OpenDirectory GPO" -EventId 1001 -Message "Completed Computer Configuration for ${policy.name}"
`;
  }
  
  /**
   * Generate Windows User Configuration Script
   */
  async generateWindowsUserScript(policy) {
    const user = policy.userConfiguration;
    
    return `# OpenDirectory Group Policy - User Configuration
# Policy: ${policy.name}
# Generated: ${new Date().toISOString()}

\$ErrorActionPreference = "Stop"

# Drive Mappings
${user.preferences?.driveMappings?.length > 0 ? this.generateWindowsDriveMappings(user.preferences.driveMappings) : ''}

# Folder Redirection
${user.windowsSettings?.folderRedirection ? this.generateWindowsFolderRedirection(user.windowsSettings.folderRedirection) : ''}

# Desktop Settings
${user.administrativeTemplates?.desktop ? this.generateWindowsDesktopSettings(user.administrativeTemplates.desktop) : ''}

# Printer Deployment
${user.preferences?.printers?.length > 0 ? this.generateWindowsPrinterDeployment(user.preferences.printers) : ''}

# Shortcuts
${user.preferences?.shortcuts?.length > 0 ? this.generateWindowsShortcuts(user.preferences.shortcuts) : ''}

# Environment Variables
${user.preferences?.environmentVariables?.length > 0 ? this.generateWindowsEnvironmentVariables(user.preferences.environmentVariables) : ''}

# Logon Scripts
${user.windowsSettings?.scripts?.logon?.length > 0 ? this.generateWindowsScripts(user.windowsSettings.scripts.logon, 'Logon') : ''}

Write-Host "User configuration completed for ${policy.name}"
`;
  }
  
  generateWindowsDriveMappings(driveMappings) {
    return `
# Network Drive Mappings
Write-Host "Mapping network drives..."

${driveMappings.map(drive => `
# Drive ${drive.letter}
try {
    # Remove existing mapping if action is Replace
    if ("${drive.action}" -eq "Replace") {
        Remove-PSDrive -Name "${drive.letter.replace(':', '')}" -Force -ErrorAction SilentlyContinue
        net use ${drive.letter} /delete /y 2>$null
    }
    
    # Map the drive
    \$credential = \$null
    ${drive.useCredentials ? `
    \$securePassword = ConvertTo-SecureString "${drive.password}" -AsPlainText -Force
    \$credential = New-Object System.Management.Automation.PSCredential("${drive.username}", \$securePassword)
    ` : ''}
    
    New-PSDrive -Name "${drive.letter.replace(':', '')}" `
                -PSProvider FileSystem `
                -Root "${drive.path}" `
                -Persist `
                ${drive.useCredentials ? '-Credential $credential `' : '`'}
                -Scope Global `
                -ErrorAction Stop
    
    # Set label if specified
    ${drive.label ? `(New-Object -ComObject Shell.Application).NameSpace("${drive.letter}\\").Self.Name = "${drive.label}"` : ''}
    
    Write-Host "✓ Mapped ${drive.letter} to ${drive.path}" -ForegroundColor Green
    
} catch {
    Write-Warning "Failed to map drive ${drive.letter}: $_"
    ${drive.reconnect ? 'Set-ItemProperty -Path "HKCU:\\Network\\${drive.letter.replace(":", "")}" -Name "DeferConnection" -Value 1 -ErrorAction SilentlyContinue' : ''}
}
`).join('\n')}
`;
  }
  
  generateWindowsFolderRedirection(folderRedirection) {
    return `
# Folder Redirection
Write-Host "Configuring folder redirection..."

${Object.entries(folderRedirection).map(([folder, config]) => {
  if (!config.enabled) return '';
  
  const folderGuids = {
    documents: '{FDD39AD0-238F-46AF-ADB4-6C85480369C7}',
    desktop: '{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}',
    pictures: '{33E28130-4E1E-4676-835A-98395C3BC3BB}',
    appData: '{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}'
  };
  
  return `
# Redirect ${folder}
try {
    \$folderPath = "${config.target}"
    \$folderPath = \$folderPath.Replace("%USERNAME%", \$env:USERNAME)
    
    # Create target directory if it doesn't exist
    if (!(Test-Path \$folderPath)) {
        New-Item -Path \$folderPath -ItemType Directory -Force
    }
    
    # Set registry for folder redirection
    \$regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
    Set-ItemProperty -Path \$regPath -Name "${folderGuids[folder] || folder}" -Value \$folderPath
    
    ${config.moveContents ? `
    # Move existing contents
    \$source = [Environment]::GetFolderPath("${folder}")
    if (Test-Path \$source) {
        Get-ChildItem \$source -Recurse | Move-Item -Destination \$folderPath -Force
    }
    ` : ''}
    
    ${config.grantExclusiveRights ? `
    # Set exclusive permissions
    \$acl = Get-Acl \$folderPath
    \$acl.SetAccessRuleProtection(\$true, \$false)
    \$permission = "\$env:USERDOMAIN\\\$env:USERNAME","FullControl","ContainerInherit,ObjectInherit","None","Allow"
    \$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule \$permission
    \$acl.SetAccessRule(\$accessRule)
    Set-Acl \$folderPath \$acl
    ` : ''}
    
    Write-Host "✓ Redirected ${folder} to \$folderPath" -ForegroundColor Green
    
} catch {
    Write-Warning "Failed to redirect ${folder}: $_"
}
`;
}).join('\n')}
`;
  }
  
  generateWindowsSecuritySettings(securitySettings) {
    return `
# Security Settings
Write-Host "Applying security settings..."

# Password Policy
secedit /export /cfg "$env:TEMP\\secpol.cfg"
(Get-Content "$env:TEMP\\secpol.cfg") | ForEach-Object {
    \$_ -replace "MinimumPasswordLength = \\d+", "MinimumPasswordLength = ${securitySettings.passwordPolicy?.minimumLength || 8}" `
       -replace "PasswordComplexity = \\d+", "PasswordComplexity = ${securitySettings.passwordPolicy?.complexity ? 1 : 0}" `
       -replace "MaximumPasswordAge = \\d+", "MaximumPasswordAge = ${securitySettings.passwordPolicy?.maxAge || 90}"
} | Set-Content "$env:TEMP\\secpol.cfg"
secedit /configure /db secedit.sdb /cfg "$env:TEMP\\secpol.cfg" /quiet

# Account Lockout Policy
net accounts /lockoutthreshold:${securitySettings.accountLockout?.threshold || 5}
net accounts /lockoutduration:${securitySettings.accountLockout?.duration || 30}
net accounts /lockoutwindow:${securitySettings.accountLockout?.resetAfter || 30}

# Audit Policy
${Object.entries(securitySettings.auditPolicy || {}).map(([category, setting]) => `
auditpol /set /category:"${category}" /success:${setting.includes('Success') ? 'enable' : 'disable'} /failure:${setting.includes('Failure') ? 'enable' : 'disable'}
`).join('\n')}

# Windows Firewall
${securitySettings.firewall ? `
Set-NetFirewallProfile -Profile Domain -Enabled ${securitySettings.firewall.domain?.enabled ? 'True' : 'False'}
Set-NetFirewallProfile -Profile Private -Enabled ${securitySettings.firewall.private?.enabled ? 'True' : 'False'}
Set-NetFirewallProfile -Profile Public -Enabled ${securitySettings.firewall.public?.enabled ? 'True' : 'False'}
` : ''}
`;
  }
  
  generateWindowsSoftwareInstallation(softwareInstallation) {
    return `
# Software Installation
Write-Host "Installing software packages..."

${softwareInstallation.packages.map(pkg => `
# Package: ${pkg.name}
try {
    \$packagePath = "${pkg.path}"
    
    # Check if already installed
    ${pkg.detectionMethod ? `
    if (${pkg.detectionMethod}) {
        Write-Host "${pkg.name} is already installed" -ForegroundColor Yellow
        return
    }
    ` : ''}
    
    Write-Host "Installing ${pkg.name}..."
    
    ${pkg.type === 'msi' ? `
    # MSI Installation
    \$arguments = "/i `"\$packagePath`" /qn /norestart ALLUSERS=1 ${pkg.parameters || ''}"
    Start-Process msiexec.exe -ArgumentList \$arguments -Wait -NoNewWindow
    ` : pkg.type === 'exe' ? `
    # EXE Installation
    Start-Process "\$packagePath" -ArgumentList "${pkg.parameters || '/S'}" -Wait -NoNewWindow
    ` : pkg.type === 'script' ? `
    # Script Installation
    & "\$packagePath" ${pkg.parameters || ''}
    ` : ''}
    
    Write-Host "✓ Installed ${pkg.name}" -ForegroundColor Green
    
} catch {
    Write-Warning "Failed to install ${pkg.name}: $_"
}
`).join('\n')}
`;
  }
  
  generateLinuxSecuritySettings(policy) {
    const security = policy.computerConfiguration?.windowsSettings?.securitySettings;
    if (!security) return '';
    
    return `
# Security Settings for Linux
log "Applying security settings"

# Password Policy
if [ -f /etc/pam.d/common-password ]; then
    # Set minimum password length
    sed -i 's/pam_unix.so.*/pam_unix.so obscure sha512 minlen=${security.passwordPolicy?.minimumLength || 8}/' /etc/pam.d/common-password
    
    # Password complexity
    ${security.passwordPolicy?.complexity ? `
    apt-get install -y libpam-pwquality 2>/dev/null || yum install -y pam_pwquality 2>/dev/null
    echo "password requisite pam_pwquality.so retry=3 minlen=${security.passwordPolicy.minimumLength} ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" >> /etc/pam.d/common-password
    ` : ''}
fi

# Account lockout
if [ -f /etc/pam.d/common-auth ]; then
    echo "auth required pam_tally2.so onerr=fail audit silent deny=${security.accountLockout?.threshold || 5} unlock_time=${(security.accountLockout?.duration || 30) * 60}" >> /etc/pam.d/common-auth
fi

# Firewall (using ufw for Ubuntu/Debian, firewall-cmd for RHEL/CentOS)
if command -v ufw &> /dev/null; then
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
elif command -v firewall-cmd &> /dev/null; then
    systemctl enable firewalld
    systemctl start firewalld
    firewall-cmd --set-default-zone=public
fi
`;
  }
  
  generateLinuxDriveMappings(policy) {
    const drives = policy.userConfiguration?.preferences?.driveMappings;
    if (!drives || drives.length === 0) return '';
    
    return `
# Network Drive Mappings for Linux
log "Mapping network drives"

# Install CIFS utilities if not present
apt-get install -y cifs-utils 2>/dev/null || yum install -y cifs-utils 2>/dev/null

${drives.map(drive => {
  const mountPoint = `/mnt/${drive.label || drive.letter.replace(':', '')}`;
  const sharePath = drive.path.replace(/\\/g, '/');
  
  return `
# Mount ${drive.letter} - ${drive.label || ''}
mkdir -p ${mountPoint}

# Add to fstab for persistent mounting
if ! grep -q "${sharePath}" /etc/fstab; then
    echo "${sharePath} ${mountPoint} cifs ${drive.useCredentials ? `credentials=/etc/samba/credentials-${drive.letter},` : 'guest,'}uid=1000,gid=1000,iocharset=utf8,file_mode=0777,dir_mode=0777,nounix,noserverino 0 0" >> /etc/fstab
fi

${drive.useCredentials ? `
# Create credentials file
cat > /etc/samba/credentials-${drive.letter} << EOF
username=${drive.username}
password=${drive.password}
domain=${drive.domain || 'WORKGROUP'}
EOF
chmod 600 /etc/samba/credentials-${drive.letter}
` : ''}

# Mount the drive
mount ${mountPoint} 2>/dev/null || log "Failed to mount ${mountPoint}"

# Create symbolic link for user
ln -sf ${mountPoint} /home/\$SUDO_USER/$(basename ${mountPoint}) 2>/dev/null
`;
}).join('\n')}
`;
  }
  
  generateLinuxSoftwareInstallation(policy) {
    const packages = policy.computerConfiguration?.softwareInstallation?.packages;
    if (!packages || packages.length === 0) return '';
    
    return `
# Software Installation for Linux
log "Installing software packages"

${packages.map(pkg => {
  if (pkg.platform && !pkg.platform.includes('linux')) return '';
  
  return `
# Install ${pkg.name}
log "Installing ${pkg.name}"

${pkg.type === 'apt' ? `
if command -v apt-get &> /dev/null; then
    apt-get update
    apt-get install -y ${pkg.packageName || pkg.name}
fi
` : pkg.type === 'yum' ? `
if command -v yum &> /dev/null; then
    yum install -y ${pkg.packageName || pkg.name}
fi
` : pkg.type === 'snap' ? `
if command -v snap &> /dev/null; then
    snap install ${pkg.packageName || pkg.name} ${pkg.classic ? '--classic' : ''}
fi
` : pkg.type === 'script' ? `
# Run installation script
if [ -f "${pkg.path}" ]; then
    chmod +x "${pkg.path}"
    "${pkg.path}" ${pkg.parameters || ''}
fi
` : `
# Generic package installation
if command -v apt-get &> /dev/null; then
    apt-get install -y ${pkg.packageName || pkg.name} 2>/dev/null
elif command -v yum &> /dev/null; then
    yum install -y ${pkg.packageName || pkg.name} 2>/dev/null
elif command -v dnf &> /dev/null; then
    dnf install -y ${pkg.packageName || pkg.name} 2>/dev/null
fi
`}
`;
}).join('\n')}
`;
  }
  
  generateLinuxDesktopSettings(policy) {
    const desktop = policy.userConfiguration?.administrativeTemplates?.desktop;
    if (!desktop) return '';
    
    return `
# Desktop Settings for Linux
log "Applying desktop settings"

# For GNOME desktop
if command -v gsettings &> /dev/null; then
    ${desktop.wallpaper?.path ? `
    # Set wallpaper
    gsettings set org.gnome.desktop.background picture-uri "file://${desktop.wallpaper.path}"
    gsettings set org.gnome.desktop.background picture-options "${desktop.wallpaper.style.toLowerCase()}"
    ` : ''}
    
    ${desktop.screensaver ? `
    # Configure screensaver
    gsettings set org.gnome.desktop.screensaver idle-activation-enabled ${desktop.screensaver.enabled}
    gsettings set org.gnome.desktop.session idle-delay ${desktop.screensaver.timeout}
    gsettings set org.gnome.desktop.screensaver lock-enabled ${desktop.screensaver.secure}
    ` : ''}
fi

# For KDE desktop
if command -v kwriteconfig5 &> /dev/null; then
    ${desktop.wallpaper?.path ? `
    # Set wallpaper
    kwriteconfig5 --file kscreenlockerrc --group Greeter --group Wallpaper --group org.kde.image --group General --key Image "${desktop.wallpaper.path}"
    ` : ''}
fi
`;
  }
  
  generateWindowsPowerManagement(powerManagement) {
    return `
# Power Management Settings
Write-Host "Configuring power management..."

${powerManagement.powerPlans?.map(plan => `
# Power Plan: ${plan.name}
powercfg /create "${plan.name}" ${plan.guid ? `/guid ${plan.guid}` : ''}

${plan.settings ? Object.entries(plan.settings).map(([setting, value]) => `
powercfg /change ${setting} ${value}
`).join('\n') : ''}

${plan.setAsActive ? `powercfg /setactive "${plan.name}"` : ''}
`).join('\n')}

${powerManagement.sleepSettings ? `
# Sleep Settings
powercfg /change standby-timeout-ac ${powerManagement.sleepSettings.acTimeout || 0}
powercfg /change standby-timeout-dc ${powerManagement.sleepSettings.dcTimeout || 10}
powercfg /change hibernate-timeout-ac ${powerManagement.sleepSettings.hibernateAcTimeout || 0}
powercfg /change hibernate-timeout-dc ${powerManagement.sleepSettings.hibernateDcTimeout || 30}
` : ''}
`;
  }
  
  generateWindowsDesktopSettings(desktop) {
    return `
# Desktop Settings
Write-Host "Configuring desktop settings..."

${desktop.wallpaper?.path ? `
# Set wallpaper
Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "Wallpaper" -Value "${desktop.wallpaper.path}"
Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "WallpaperStyle" -Value "${
  desktop.wallpaper.style === 'Fill' ? '10' :
  desktop.wallpaper.style === 'Fit' ? '6' :
  desktop.wallpaper.style === 'Stretch' ? '2' :
  desktop.wallpaper.style === 'Tile' ? '0' :
  desktop.wallpaper.style === 'Center' ? '0' : '10'
}"
RUNDLL32.EXE user32.dll, UpdatePerUserSystemParameters
` : ''}

${desktop.screensaver ? `
# Configure screensaver
Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "ScreenSaveActive" -Value "${desktop.screensaver.enabled ? '1' : '0'}"
Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "ScreenSaveTimeOut" -Value "${desktop.screensaver.timeout}"
Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "ScreenSaverIsSecure" -Value "${desktop.screensaver.secure ? '1' : '0'}"
${desktop.screensaver.executable ? `Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "SCRNSAVE.EXE" -Value "${desktop.screensaver.executable}"` : ''}
` : ''}

${desktop.hideDesktopIcons ? `
# Hide desktop icons
Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" -Name "HideIcons" -Value 1
` : ''}
`;
  }
  
  generateWindowsScripts(scripts, type) {
    if (!scripts || scripts.length === 0) return '';
    
    return `
# ${type} Scripts
Write-Host "Executing ${type.toLowerCase()} scripts..."

${scripts.map(script => `
# Script: ${script.name}
try {
    ${script.type === 'PowerShell' ? `
    & "${script.path}" ${script.parameters || ''}
    ` : script.type === 'Batch' ? `
    cmd.exe /c "${script.path}" ${script.parameters || ''}
    ` : script.type === 'VBScript' ? `
    cscript.exe "${script.path}" ${script.parameters || ''}
    ` : `
    # Execute as generic script
    Start-Process "${script.path}" -ArgumentList "${script.parameters || ''}" -Wait -NoNewWindow
    `}
    
    Write-Host "✓ Executed ${script.name}" -ForegroundColor Green
} catch {
    Write-Warning "Failed to execute ${script.name}: $_"
}
`).join('\n')}
`;
  }
  
  generateRegistryFile(policy) {
    const registrySettings = [];
    
    // Collect all registry settings from the policy
    if (policy.computerConfiguration?.windowsSettings?.registrySettings?.policies) {
      registrySettings.push(...policy.computerConfiguration.windowsSettings.registrySettings.policies);
    }
    
    if (policy.userConfiguration?.preferences?.registry) {
      registrySettings.push(...policy.userConfiguration.preferences.registry);
    }
    
    if (registrySettings.length === 0) return null;
    
    let regContent = 'Windows Registry Editor Version 5.00\n\n';
    
    // Group registry settings by key
    const groupedSettings = {};
    for (const setting of registrySettings) {
      if (!groupedSettings[setting.key]) {
        groupedSettings[setting.key] = [];
      }
      groupedSettings[setting.key].push(setting);
    }
    
    // Generate registry content
    for (const [key, settings] of Object.entries(groupedSettings)) {
      regContent += `[${key}]\n`;
      
      for (const setting of settings) {
        if (setting.action === 'Delete') {
          regContent += `"${setting.valueName}"=-\n`;
        } else {
          const value = this.formatRegistryValue(setting.type, setting.value);
          regContent += `"${setting.valueName}"=${value}\n`;
        }
      }
      
      regContent += '\n';
    }
    
    return regContent;
  }
  
  formatRegistryValue(type, value) {
    switch (type) {
      case 'REG_SZ':
        return `"${value}"`;
      case 'REG_DWORD':
        return `dword:${value.toString(16).padStart(8, '0')}`;
      case 'REG_QWORD':
        return `qword:${value.toString(16).padStart(16, '0')}`;
      case 'REG_BINARY':
        return `hex:${value}`;
      case 'REG_MULTI_SZ':
        return `hex(7):${Buffer.from(value.join('\0') + '\0\0', 'utf16le').toString('hex')}`;
      default:
        return `"${value}"`;
    }
  }
  
  validatePolicy(policy) {
    if (!policy.name) {
      throw new Error('Policy name is required');
    }
    
    if (!policy.scope?.securityFiltering?.applyTo) {
      throw new Error('Policy must have security filtering targets');
    }
    
    // Validate at least one configuration is enabled
    const hasComputerConfig = policy.computerConfiguration && 
                             !policy.scope.options.disableComputerConfiguration;
    const hasUserConfig = policy.userConfiguration && 
                         !policy.scope.options.disableUserConfiguration;
    
    if (!hasComputerConfig && !hasUserConfig) {
      throw new Error('Policy must have at least one enabled configuration');
    }
  }
  
  generatePolicyId() {
    return crypto.randomUUID().toUpperCase();
  }
  
  async savePolicyToStorage(policy) {
    try {
      const policyPath = `/var/lib/opendirectory/policies/${policy.id}`;
      await fs.mkdir(policyPath, { recursive: true });
      
      await fs.writeFile(
        `${policyPath}/policy.json`,
        JSON.stringify(policy, null, 2)
      );
      
      this.logger.info(`Policy saved to storage: ${policy.id}`);
    } catch (error) {
      this.logger.error('Failed to save policy to storage:', error);
    }
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
    if (!this.isPolicyApplicable(policy, targetInfo)) {
      return {
        success: false,
        reason: 'Target does not match policy criteria'
      };
    }
    
    // Get deployment package for target platform
    const packages = await this.generateDeploymentPackages(policy);
    const platform = targetInfo.os.toLowerCase().includes('windows') ? 'windows' :
                    targetInfo.os.toLowerCase().includes('mac') ? 'macos' : 'linux';
    
    const deployment = packages[platform];
    
    if (!deployment) {
      throw new Error(`No deployment package for platform: ${platform}`);
    }
    
    return {
      success: true,
      policyId,
      deployment
    };
  }
  
  isPolicyApplicable(policy, targetInfo) {
    const scope = policy.scope;
    
    // Check security filtering
    const security = scope.securityFiltering;
    
    // Check if target is in apply list
    const shouldApply = 
      security.applyTo.users?.includes(targetInfo.userId) ||
      security.applyTo.groups?.some(g => targetInfo.groups?.includes(g)) ||
      security.applyTo.computers?.includes(targetInfo.computerName) ||
      security.applyTo.computerGroups?.some(g => targetInfo.computerGroups?.includes(g));
    
    // Check if target is in deny list
    const shouldDeny = 
      security.deny?.users?.includes(targetInfo.userId) ||
      security.deny?.groups?.some(g => targetInfo.groups?.includes(g)) ||
      security.deny?.computers?.includes(targetInfo.computerName) ||
      security.deny?.computerGroups?.some(g => targetInfo.computerGroups?.includes(g));
    
    if (shouldDeny) return false;
    if (!shouldApply && security.applyTo.groups?.length > 0) return false;
    
    // Check WMI filter
    if (scope.wmiFilter?.enabled && scope.wmiFilter.queries?.length > 0) {
      // Simulate WMI query evaluation
      // In real implementation, would evaluate WMI queries against target
    }
    
    return true;
  }
  
  /**
   * Get all policies
   */
  async getPolicies() {
    return Array.from(this.policies.values()).map(p => ({
      id: p.id,
      name: p.name,
      description: p.description,
      enabled: p.enabled,
      scope: p.scope,
      created: p.metadata.created,
      modified: p.metadata.modified
    }));
  }
}

module.exports = GroupPolicyEngine;