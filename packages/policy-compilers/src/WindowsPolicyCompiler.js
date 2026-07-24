'use strict';
// =============================================================================
// Windows Policy Compiler → GPO XML / Registry Preferences XML / Security Templates
// =============================================================================
const { uuid, now } = require('./helpers');
const { logInfo } = require('./logger');

function compileWindows(policy) {
  const artifacts = [];
  const s = policy.settings || {};
  const machineRegistryEntries = [];
  const userRegistryEntries = [];
  const securitySettings = [];

  // ── Password Policy ────────────────────────────────────────────────────
  if (s.password) {
    const p = s.password;
    securitySettings.push({
      section: 'System Access',
      entries: [
        p.minLength      !== undefined ? `MinimumPasswordLength = ${p.minLength}` : null,
        p.maxAgeDays     !== undefined ? `MaximumPasswordAge = ${p.maxAgeDays}` : null,
        p.historyLength  !== undefined ? `PasswordHistorySize = ${p.historyLength}` : null,
        p.complexity     !== undefined ? `PasswordComplexity = ${p.complexity ? 1 : 0}` : null,
        p.lockoutThreshold !== undefined ? `LockoutBadCount = ${p.lockoutThreshold}` : null,
        p.lockoutDuration  !== undefined ? `LockoutDuration = ${p.lockoutDuration}` : null,
      ].filter(Boolean),
    });
  }

  // ── Screen Lock ────────────────────────────────────────────────────────
  if (s.screenLock) {
    const sl = s.screenLock;
    if (sl.enabled) {
      if (sl.timeoutMinutes !== undefined) {
        userRegistryEntries.push({
          hive: 'HKEY_CURRENT_USER',
          key:  'Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop',
          name: 'ScreenSaveTimeOut', type: 'REG_SZ',
          value: String(sl.timeoutMinutes * 60),
        });
        userRegistryEntries.push({
          hive: 'HKEY_CURRENT_USER',
          key:  'Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop',
          name: 'ScreenSaveActive', type: 'REG_SZ', value: '1',
        });
      }
      if (sl.requirePassword) {
        userRegistryEntries.push({
          hive: 'HKEY_CURRENT_USER',
          key:  'Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop',
          name: 'ScreenSaverIsSecure', type: 'REG_SZ', value: '1',
        });
      }
    }
    if (sl.inactivityLockMinutes !== undefined) {
      machineRegistryEntries.push({
        hive: 'HKEY_LOCAL_MACHINE',
        key:  'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
        name: 'InactivityTimeoutSecs', type: 'DWORD',
        value: String(sl.inactivityLockMinutes * 60),
      });
    }
  }

  // ── Firewall ───────────────────────────────────────────────────────────
  if (s.firewall) {
    const fw = s.firewall;
    for (const profile of ['DomainProfile', 'StandardProfile']) {
      machineRegistryEntries.push({
        hive: 'HKEY_LOCAL_MACHINE',
        key:  `SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\${profile}`,
        name: 'EnableFirewall', type: 'DWORD', value: fw.enabled ? '1' : '0',
      });
      if (fw.defaultDeny) {
        machineRegistryEntries.push({
          hive: 'HKEY_LOCAL_MACHINE',
          key:  `SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\${profile}`,
          name: 'DefaultInboundAction', type: 'DWORD', value: '1',
        });
      }
    }
  }

  // ── Audit ──────────────────────────────────────────────────────────────
  if (s.audit?.enabled) {
    securitySettings.push({
      section: 'Event Audit',
      entries: [
        'AuditSystemEvents = 3', 'AuditLogonEvents = 3', 'AuditObjectAccess = 3',
        'AuditPrivilegeUse = 2', 'AuditPolicyChange = 3', 'AuditAccountManage = 3',
        'AuditProcessTracking = 0', 'AuditDSAccess = 0', 'AuditAccountLogon = 3',
      ],
    });
  }

  // ── Encryption / BitLocker ─────────────────────────────────────────────
  if (s.encryption?.requireBitLocker) {
    machineRegistryEntries.push({
      hive: 'HKEY_LOCAL_MACHINE', key: 'SOFTWARE\\Policies\\Microsoft\\FVE',
      name: 'EnableBDEWithNoTPM', type: 'DWORD', value: '1',
    });
    machineRegistryEntries.push({
      hive: 'HKEY_LOCAL_MACHINE', key: 'SOFTWARE\\Policies\\Microsoft\\FVE',
      name: 'ActiveDirectoryBackup', type: 'DWORD', value: '1',
    });
  }

  // ── Browser / Edge ─────────────────────────────────────────────────────
  if (s.browser) {
    const b = s.browser;
    if (b.homepage) {
      userRegistryEntries.push({
        hive: 'HKEY_CURRENT_USER', key: 'Software\\Policies\\Microsoft\\Edge',
        name: 'HomepageLocation', type: 'REG_SZ', value: b.homepage,
      });
      userRegistryEntries.push({
        hive: 'HKEY_CURRENT_USER', key: 'Software\\Policies\\Microsoft\\Edge',
        name: 'HomepageIsNewTabPage', type: 'DWORD', value: '0',
      });
    }
    if (b.defaultSearchEngine) {
      userRegistryEntries.push({
        hive: 'HKEY_CURRENT_USER', key: 'Software\\Policies\\Microsoft\\Edge',
        name: 'DefaultSearchProviderName', type: 'REG_SZ', value: b.defaultSearchEngine,
      });
    }
  }

  // ── Generate GPO Registry Preferences XML ──────────────────────────────
  const makeRegistryXml = (entries) => `<?xml version="1.0" encoding="UTF-8"?>
<RegistrySettings clsid="{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}">
${entries.map(e => `  <Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}"
           name="${e.name}" status="${e.name}" image="1"
           changed="${now()}"
           uid="{${uuid(policy.id + e.key + e.name)}}">
    <Properties action="U"
      hive="${e.hive}"
      key="${e.key}"
      name="${e.name}"
      type="${e.type}"
      value="${e.value}"/>
  </Registry>`).join('\n')}
</RegistrySettings>`;

  if (machineRegistryEntries.length > 0) {
    artifacts.push({
      type: 'gpo_registry_xml', filename: 'Machine-Registry.xml',
      sysvol_path: 'Machine/Preferences/Registry/Registry.xml',
      content: makeRegistryXml(machineRegistryEntries),
      description: 'GPO Registry Preferences (HKLM)',
    });
  }
  if (userRegistryEntries.length > 0) {
    artifacts.push({
      type: 'gpo_registry_xml', filename: 'User-Registry.xml',
      sysvol_path: 'User/Preferences/Registry/Registry.xml',
      content: makeRegistryXml(userRegistryEntries),
      description: 'GPO Registry Preferences (HKCU)',
    });
  }

  // ── Security Template (secedit) ────────────────────────────────────────
  if (securitySettings.length > 0) {
    const merged = {};
    for (const sec of securitySettings) {
      if (!merged[sec.section]) merged[sec.section] = [];
      merged[sec.section].push(...sec.entries);
    }
    let inf = '[Unicode]\nUnicode=yes\n[Version]\nsignature="$CHICAGO$"\nRevision=1\n';
    for (const [section, entries] of Object.entries(merged)) {
      inf += `\n[${section}]\n${entries.join('\n')}\n`;
    }
    artifacts.push({
      type: 'security_template',
      filename: `${policy.name.replace(/\s+/g, '-')}-security.inf`,
      sysvol_path: 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf',
      content: inf,
      description: 'Security Template (Passwort, Lockout, Audit)',
      apply_command: `secedit /configure /db "%TEMP%\\secedit.sdb" /cfg "${policy.name.replace(/\s+/g, '-')}-security.inf" /overwrite`,
    });
  }

  // ── PowerShell Logon Script ────────────────────────────────────────────
  const psLines = [
    `# OpenDirectory Policy: ${policy.name}`,
    `# Version: ${policy.version || '1.0'} | Generated: ${new Date().toISOString()}`,
    '',
  ];

  if (s.updates?.automatic !== undefined) {
    psLines.push('# Windows Update Policy');
    psLines.push(`Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" -Name "AUOptions" -Value ${s.updates.automatic ? 4 : 1} -ErrorAction SilentlyContinue`);
    psLines.push('');
  }

  // ── Winget Auto-Update Policy ──────────────────────────────────────────
  if (s.wingetAutoUpdate?.enabled) {
    const wau = s.wingetAutoUpdate;
    const regKey = 'SOFTWARE\\Policies\\OpenDirectory\\WingetAutoUpdate';

    machineRegistryEntries.push(
      { hive: 'HKEY_LOCAL_MACHINE', key: regKey, name: 'Enabled', type: 'DWORD', value: '1' },
      { hive: 'HKEY_LOCAL_MACHINE', key: regKey, name: 'UpdateMode', type: 'REG_SZ', value: wau.updateMode || 'blacklist' },
      { hive: 'HKEY_LOCAL_MACHINE', key: regKey, name: 'UpdateInterval', type: 'REG_SZ', value: wau.schedule?.interval || 'Daily' },
      { hive: 'HKEY_LOCAL_MACHINE', key: regKey, name: 'UpdateTime', type: 'REG_SZ', value: wau.schedule?.time || '06:00' },
      { hive: 'HKEY_LOCAL_MACHINE', key: regKey, name: 'NotificationLevel', type: 'REG_SZ', value: wau.notifications || 'Full' },
      { hive: 'HKEY_LOCAL_MACHINE', key: regKey, name: 'UserContext', type: 'DWORD', value: wau.userContext ? '1' : '0' }
    );

    psLines.push('# Winget Auto-Update Policy (OpenDirectory)');
    psLines.push('$WAURegPath = "HKLM:\\SOFTWARE\\Policies\\OpenDirectory\\WingetAutoUpdate"');
    psLines.push('if (!(Test-Path $WAURegPath)) { New-Item -Path $WAURegPath -Force | Out-Null }');
    psLines.push(`Set-ItemProperty -Path $WAURegPath -Name "Enabled" -Value 1 -Type DWord`);
    psLines.push(`Set-ItemProperty -Path $WAURegPath -Name "UpdateMode" -Value "${wau.updateMode || 'blacklist'}" -Type String`);
    psLines.push(`Set-ItemProperty -Path $WAURegPath -Name "UpdateInterval" -Value "${wau.schedule?.interval || 'Daily'}" -Type String`);
    psLines.push(`Set-ItemProperty -Path $WAURegPath -Name "UpdateTime" -Value "${wau.schedule?.time || '06:00'}" -Type String`);

    if (wau.updateMode === 'whitelist' && wau.whitelist?.length) {
      const apps = wau.whitelist.map(id => `"${id}"`).join(', ');
      psLines.push('$WAUConfigPath = "C:\\OpenDirectory\\Config"');
      psLines.push('if (!(Test-Path $WAUConfigPath)) { New-Item -Path $WAUConfigPath -ItemType Directory -Force | Out-Null }');
      psLines.push(`@(${apps}) | Out-File -FilePath "$WAUConfigPath\\winget-whitelist.txt" -Force`);
    }
    if (wau.updateMode === 'blacklist' && wau.blacklist?.length) {
      const apps = wau.blacklist.map(id => `"${id}"`).join(', ');
      psLines.push('$WAUConfigPath = "C:\\OpenDirectory\\Config"');
      psLines.push('if (!(Test-Path $WAUConfigPath)) { New-Item -Path $WAUConfigPath -ItemType Directory -Force | Out-Null }');
      psLines.push(`@(${apps}) | Out-File -FilePath "$WAUConfigPath\\winget-blacklist.txt" -Force`);
    }
    psLines.push('');
  }

  if (psLines.length > 3) {
    const psName = `${policy.name.replace(/\s+/g, '-')}-policy.ps1`;
    artifacts.push({
      type: 'powershell_script', filename: psName,
      content: psLines.join('\n'),
      sysvol_path: `Machine/Scripts/Startup/${psName}`,
      description: 'PowerShell Startup-Script',
    });
    artifacts.push({
      type: 'scripts_ini', filename: 'scripts.ini',
      sysvol_path: 'Machine/Scripts/scripts.ini',
      content: `[Startup]\r\n0CmdLine=${psName}\r\n0Parameters=\r\n`,
      description: 'Scripts.ini — Windows Scripts CSE Startup-Eintrag',
    });
  }

  // GPT.INI
  if (artifacts.some(a => a.sysvol_path && a.type !== 'gpt_ini')) {
    artifacts.push({
      type: 'gpt_ini', filename: 'GPT.INI', sysvol_path: 'GPT.INI',
      content: `[General]\r\nVersion=65537\r\nDisplayName=Version 1\r\n`,
      description: 'GPO Metadata',
    });
  }

  return artifacts;
}

// =============================================================================
// WindowsPolicyCompiler (class) → RSoP → Windows-native policy payload
// -----------------------------------------------------------------------------
// Unlike compileWindows() above (which turns an authored policy.settings tree
// into deployable GPO SYSVOL artifacts — Registry.xml / GptTmpl.inf / a
// PowerShell logon script — this compiler consumes the *merged* result of
// RSOPEngine.calculateRSOP() (flattened, conflict-resolved settings across
// every applicable policy) and produces a structured, inspectable summary of
// the effective Windows configuration (registry entries, firewall rules,
// password/audit policy, scripts, software installs, Windows Update and
// BitLocker settings). It is used by policy-service's RSoP/compile API to
// answer "what would apply to this device", not to write files to SYSVOL.
// Both compilers live here so the two related-but-distinct transformations
// stay in one shared kernel instead of drifting as independent copies.
// =============================================================================
class WindowsPolicyCompiler {
  /**
   * Compile the full RSoP result into a Windows-native payload.
   *
   * @param {object} rsopResult - Output from RSOPEngine.calculateRSOP()
   * @returns {object} Windows-formatted policy payload
   */
  compile(rsopResult) {
    const { settings, sources, appliedPolicies } = rsopResult;

    logInfo('Compiling RSoP for Windows', {
      settingCount: Object.keys(settings).length,
      policyCount: appliedPolicies.length
    });

    return {
      platform: 'windows',
      compiledAt: new Date().toISOString(),
      registrySettings: this.compileRegistry(settings),
      firewallRules: this.compileFirewall(settings),
      passwordPolicy: this.compilePasswordPolicy(settings),
      auditPolicy: this.compileAuditPolicy(settings),
      scripts: this.compileScripts(settings),
      softwareInstallation: this.compileSoftware(settings),
      windowsUpdate: this.compileWindowsUpdate(settings),
      encryption: this.compileEncryption(settings),
      sources
    };
  }

  /**
   * Convert policy settings into Windows Registry entries.
   */
  compileRegistry(settings) {
    const entries = [];

    // Password policy registry keys
    if (settings['password.minLength'] !== undefined) {
      entries.push({
        hive: 'HKLM',
        path: 'SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters',
        name: 'MinimumPasswordLength',
        type: 'REG_DWORD',
        value: Number(settings['password.minLength'])
      });
    }

    if (settings['password.complexity'] !== undefined) {
      entries.push({
        hive: 'HKLM',
        path: 'SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters',
        name: 'PasswordComplexity',
        type: 'REG_DWORD',
        value: settings['password.complexity'] ? 1 : 0
      });
    }

    if (settings['password.maxAge'] !== undefined) {
      entries.push({
        hive: 'HKLM',
        path: 'SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters',
        name: 'MaximumPasswordAge',
        type: 'REG_DWORD',
        value: Number(settings['password.maxAge'])
      });
    }

    if (settings['password.history'] !== undefined) {
      entries.push({
        hive: 'HKLM',
        path: 'SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters',
        name: 'PasswordHistorySize',
        type: 'REG_DWORD',
        value: Number(settings['password.history'])
      });
    }

    // Lockout policy
    if (settings['lockout.threshold'] !== undefined) {
      entries.push({
        hive: 'HKLM',
        path: 'SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters',
        name: 'LockoutThreshold',
        type: 'REG_DWORD',
        value: Number(settings['lockout.threshold'])
      });
    }

    if (settings['lockout.duration'] !== undefined) {
      entries.push({
        hive: 'HKLM',
        path: 'SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters',
        name: 'LockoutDuration',
        type: 'REG_DWORD',
        value: Number(settings['lockout.duration'])
      });
    }

    if (settings['lockout.window'] !== undefined) {
      entries.push({
        hive: 'HKLM',
        path: 'SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters',
        name: 'LockoutObservationWindow',
        type: 'REG_DWORD',
        value: Number(settings['lockout.window'])
      });
    }

    // Screen lock
    if (settings['screenLock.timeout'] !== undefined) {
      entries.push({
        hive: 'HKCU',
        path: 'Control Panel\\Desktop',
        name: 'ScreenSaveTimeOut',
        type: 'REG_SZ',
        value: String(Number(settings['screenLock.timeout']) * 60)
      });
      entries.push({
        hive: 'HKCU',
        path: 'Control Panel\\Desktop',
        name: 'ScreenSaverIsSecure',
        type: 'REG_SZ',
        value: '1'
      });
    }

    // Windows Defender
    if (settings['antivirus.enabled'] !== undefined) {
      entries.push({
        hive: 'HKLM',
        path: 'SOFTWARE\\Policies\\Microsoft\\Windows Defender',
        name: 'DisableAntiSpyware',
        type: 'REG_DWORD',
        value: settings['antivirus.enabled'] ? 0 : 1
      });
    }

    if (settings['antivirus.realTimeProtection'] !== undefined) {
      entries.push({
        hive: 'HKLM',
        path: 'SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection',
        name: 'DisableRealtimeMonitoring',
        type: 'REG_DWORD',
        value: settings['antivirus.realTimeProtection'] ? 0 : 1
      });
    }

    // SMB signing
    if (settings['network.smbSigning'] !== undefined) {
      entries.push({
        hive: 'HKLM',
        path: 'SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters',
        name: 'RequireSecuritySignature',
        type: 'REG_DWORD',
        value: settings['network.smbSigning'] ? 1 : 0
      });
    }

    // Remote Desktop
    if (settings['remoteDesktop.enabled'] !== undefined) {
      entries.push({
        hive: 'HKLM',
        path: 'SYSTEM\\CurrentControlSet\\Control\\Terminal Server',
        name: 'fDenyTSConnections',
        type: 'REG_DWORD',
        value: settings['remoteDesktop.enabled'] ? 0 : 1
      });
    }

    // NLA for RDP
    if (settings['remoteDesktop.nla'] !== undefined) {
      entries.push({
        hive: 'HKLM',
        path: 'SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp',
        name: 'UserAuthentication',
        type: 'REG_DWORD',
        value: settings['remoteDesktop.nla'] ? 1 : 0
      });
    }

    // Custom registry settings (pass-through)
    for (const [key, value] of Object.entries(settings)) {
      if (key.startsWith('registry.')) {
        const regPath = key.replace('registry.', '').replace(/\./g, '\\');
        const lastBackslash = regPath.lastIndexOf('\\');
        if (lastBackslash > 0) {
          entries.push({
            hive: 'HKLM',
            path: regPath.substring(0, lastBackslash),
            name: regPath.substring(lastBackslash + 1),
            type: typeof value === 'number' ? 'REG_DWORD' : 'REG_SZ',
            value
          });
        }
      }
    }

    return entries;
  }

  /**
   * Compile firewall rules for Windows Firewall with Advanced Security.
   */
  compileFirewall(settings) {
    const rules = {
      enabled: settings['firewall.enabled'] !== undefined ? settings['firewall.enabled'] : true,
      defaultInbound: settings['firewall.defaultInbound'] || 'block',
      defaultOutbound: settings['firewall.defaultOutbound'] || 'allow',
      profiles: {
        domain: { enabled: true },
        private: { enabled: true },
        public: { enabled: true }
      },
      rules: []
    };

    // Process any firewall rule settings
    const ruleEntries = {};
    for (const [key, value] of Object.entries(settings)) {
      if (key.startsWith('firewall.rules.')) {
        const parts = key.replace('firewall.rules.', '').split('.');
        const ruleId = parts[0];
        const prop = parts.slice(1).join('.');
        if (!ruleEntries[ruleId]) ruleEntries[ruleId] = {};
        ruleEntries[ruleId][prop] = value;
      }
    }

    for (const [id, rule] of Object.entries(ruleEntries)) {
      rules.rules.push({
        id,
        name: rule.name || id,
        direction: rule.direction || 'inbound',
        action: rule.action || 'allow',
        protocol: rule.protocol || 'tcp',
        localPort: rule.localPort,
        remotePort: rule.remotePort,
        remoteAddress: rule.remoteAddress,
        program: rule.program,
        enabled: rule.enabled !== undefined ? rule.enabled : true
      });
    }

    return rules;
  }

  /**
   * Compile password policy into Windows Security Policy format.
   */
  compilePasswordPolicy(settings) {
    return {
      enforcePasswordHistory: settings['password.history'] || 24,
      maximumPasswordAge: settings['password.maxAge'] || 90,
      minimumPasswordAge: settings['password.minAge'] || 1,
      minimumPasswordLength: settings['password.minLength'] || 12,
      passwordMustMeetComplexityRequirements: settings['password.complexity'] !== false,
      storePaswordsUsingReversibleEncryption: false,
      accountLockoutDuration: settings['lockout.duration'] || 30,
      accountLockoutThreshold: settings['lockout.threshold'] || 5,
      resetAccountLockoutCounterAfter: settings['lockout.window'] || 30
    };
  }

  /**
   * Compile audit policy settings.
   */
  compileAuditPolicy(settings) {
    return {
      auditAccountLogonEvents: settings['audit.accountLogon'] || 'success,failure',
      auditAccountManagement: settings['audit.accountManagement'] || 'success,failure',
      auditDirectoryServiceAccess: settings['audit.dsAccess'] || 'success',
      auditLogonEvents: settings['audit.logon'] || 'success,failure',
      auditObjectAccess: settings['audit.objectAccess'] || 'failure',
      auditPolicyChange: settings['audit.policyChange'] || 'success,failure',
      auditPrivilegeUse: settings['audit.privilegeUse'] || 'failure',
      auditProcessTracking: settings['audit.processTracking'] || 'no_auditing',
      auditSystemEvents: settings['audit.systemEvents'] || 'success,failure'
    };
  }

  /**
   * Compile startup/logon scripts.
   */
  compileScripts(settings) {
    const scripts = { startup: [], shutdown: [], logon: [], logoff: [] };

    for (const [key, value] of Object.entries(settings)) {
      if (key.startsWith('scripts.startup.')) scripts.startup.push(value);
      if (key.startsWith('scripts.shutdown.')) scripts.shutdown.push(value);
      if (key.startsWith('scripts.logon.')) scripts.logon.push(value);
      if (key.startsWith('scripts.logoff.')) scripts.logoff.push(value);
    }

    return scripts;
  }

  /**
   * Compile software installation directives.
   */
  compileSoftware(settings) {
    const packages = [];

    const softwareEntries = {};
    for (const [key, value] of Object.entries(settings)) {
      if (key.startsWith('software.')) {
        const parts = key.replace('software.', '').split('.');
        const pkgId = parts[0];
        const prop = parts.slice(1).join('.');
        if (!softwareEntries[pkgId]) softwareEntries[pkgId] = {};
        softwareEntries[pkgId][prop] = value;
      }
    }

    for (const [id, pkg] of Object.entries(softwareEntries)) {
      packages.push({
        id,
        name: pkg.name || id,
        version: pkg.version,
        source: pkg.source || 'winget',
        action: pkg.action || 'install',
        arguments: pkg.arguments,
        required: pkg.required !== false
      });
    }

    return { packages };
  }

  /**
   * Compile Windows Update settings.
   */
  compileWindowsUpdate(settings) {
    return {
      autoInstall: settings['updates.autoInstall'] !== false,
      maxDeferDays: settings['updates.maxDeferDays'] || 7,
      activeHoursStart: settings['updates.activeHoursStart'] || 8,
      activeHoursEnd: settings['updates.activeHoursEnd'] || 17,
      scheduledInstallDay: settings['updates.scheduledDay'] || 0,
      scheduledInstallTime: settings['updates.scheduledTime'] || 3,
      autoReboot: settings['updates.autoReboot'] !== undefined ? settings['updates.autoReboot'] : false
    };
  }

  /**
   * Compile BitLocker encryption settings.
   */
  compileEncryption(settings) {
    return {
      bitlocker: {
        required: settings['encryption.required'] !== false,
        algorithm: settings['encryption.algorithm'] || 'AES-256',
        requireTPM: settings['encryption.requireTPM'] !== false,
        allowUSBKey: settings['encryption.allowUSBKey'] || false,
        encryptionMethod: settings['encryption.method'] || 'XtsAes256',
        recoveryPasswordRequired: settings['encryption.recoveryPassword'] !== false,
        recoveryKeyRequired: settings['encryption.recoveryKey'] !== false
      }
    };
  }
}

module.exports = { compileWindows, WindowsPolicyCompiler };
