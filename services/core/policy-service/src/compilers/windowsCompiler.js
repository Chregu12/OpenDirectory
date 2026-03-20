'use strict';

const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

/**
 * Compiles merged RSoP results into Windows-native policy formats.
 * Produces registry settings, firewall rules, password/audit policies,
 * startup/logon scripts, and software installation directives.
 */
class WindowsPolicyCompiler {
  /**
   * Compile the full RSoP result into a Windows-native payload.
   *
   * @param {object} rsopResult - Output from RSOPEngine.calculateRSOP()
   * @returns {object} Windows-formatted policy payload
   */
  compile(rsopResult) {
    const { settings, sources, appliedPolicies } = rsopResult;

    logger.info('Compiling RSoP for Windows', {
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

module.exports = { WindowsPolicyCompiler };
