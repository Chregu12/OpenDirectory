'use strict';
// =============================================================================
// Windows Policy Compiler → GPO XML / Registry Preferences XML / Security Templates
// =============================================================================
const { uuid, now } = require('./helpers');

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

module.exports = { compileWindows };
