'use strict';
// =============================================================================
// OpenDirectory — Cross-Platform Policy Compiler
// Transforms intent-based YAML/JSON policies into OS-specific artifacts:
//   Windows → GPO XML (SYSVOL/Registry.pol compatible), Logon-Scripts
//   Linux   → sysctl, sshd_config, PAM, sudoers, systemd units
//   macOS   → .mobileconfig Configuration Profiles (MDM-deployable)
// =============================================================================

const crypto = require('crypto');

// ── Policy Schema (Intent) ─────────────────────────────────────────────────────
// {
//   id, name, description, version, targets: { groups, ous, platforms },
//   settings: {
//     password?: { minLength, complexity, maxAgeDays, historyLength, lockoutThreshold },
//     screenLock?: { enabled, timeoutMinutes, requirePassword },
//     firewall?: { enabled, defaultDeny, allowedPorts },
//     ssh?: { enabled, permitRootLogin, passwordAuth, port, allowGroups },
//     updates?: { automatic, rebootAllowed, maintenanceWindow },
//     audit?: { enabled, logLogin, logFileAccess, logNetworkConn },
//     software?: { blockedApps, requiredApps },
//     encryption?: { diskEncryption, requireFileVault, requireBitLocker },
//     browser?: { homepage, defaultSearchEngine, blockedExtensions },
//   }
// }

// ── Helpers ───────────────────────────────────────────────────────────────────
function uuid(seed) {
  const h = crypto.createHash('md5').update(seed || Math.random().toString()).digest('hex');
  return `${h.slice(0,8)}-${h.slice(8,12)}-4${h.slice(13,16)}-${['8','9','a','b'][parseInt(h[16],16)&3]}${h.slice(17,20)}-${h.slice(20,32)}`.toUpperCase();
}

const now = () => new Date().toISOString().slice(0, 19).replace('T', ' ');

// ═══════════════════════════════════════════════════════════════════════════════
// WINDOWS COMPILER → GPO XML / Registry Preferences XML
// ═══════════════════════════════════════════════════════════════════════════════
function compileWindows(policy) {
  const artifacts = [];
  const s = policy.settings || {};
  const machineRegistryEntries = []; // HKEY_LOCAL_MACHINE → Machine/Preferences/Registry/Registry.xml
  const userRegistryEntries    = []; // HKEY_CURRENT_USER  → User/Preferences/Registry/Registry.xml
  const securitySettings = [];

  // ── Password Policy ────────────────────────────────────────────────────────
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

  // ── Screen Lock ────────────────────────────────────────────────────────────
  if (s.screenLock) {
    const sl = s.screenLock;
    if (sl.enabled) {
      if (sl.timeoutMinutes !== undefined) {
        userRegistryEntries.push({
          hive: 'HKEY_CURRENT_USER',
          key:  'Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop',
          name: 'ScreenSaveTimeOut',
          type: 'REG_SZ',
          value: String(sl.timeoutMinutes * 60),
        });
        userRegistryEntries.push({
          hive: 'HKEY_CURRENT_USER',
          key:  'Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop',
          name: 'ScreenSaveActive',
          type: 'REG_SZ',
          value: '1',
        });
      }
      if (sl.requirePassword) {
        userRegistryEntries.push({
          hive: 'HKEY_CURRENT_USER',
          key:  'Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop',
          name: 'ScreenSaverIsSecure',
          type: 'REG_SZ',
          value: '1',
        });
      }
    }
    if (sl.inactivityLockMinutes !== undefined) {
      // InactivityTimeoutSecs is a registry key, not a secedit setting
      machineRegistryEntries.push({
        hive: 'HKEY_LOCAL_MACHINE',
        key:  'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
        name: 'InactivityTimeoutSecs',
        type: 'DWORD',
        value: String(sl.inactivityLockMinutes * 60),
      });
    }
  }

  // ── Firewall ───────────────────────────────────────────────────────────────
  if (s.firewall) {
    const fw = s.firewall;
    // Domain-joined machines use DomainProfile; StandardProfile is the fallback.
    // Both must be set for policy to take effect on corporate endpoints.
    for (const profile of ['DomainProfile', 'StandardProfile']) {
      machineRegistryEntries.push({
        hive: 'HKEY_LOCAL_MACHINE',
        key:  `SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\${profile}`,
        name: 'EnableFirewall',
        type: 'DWORD',
        value: fw.enabled ? '1' : '0',
      });
      if (fw.defaultDeny) {
        machineRegistryEntries.push({
          hive: 'HKEY_LOCAL_MACHINE',
          key:  `SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\${profile}`,
          name: 'DefaultInboundAction',
          type: 'DWORD',
          value: '1', // Block
        });
      }
    }
  }

  // ── Audit ──────────────────────────────────────────────────────────────────
  if (s.audit?.enabled) {
    securitySettings.push({
      section: 'Event Audit',
      entries: [
        'AuditSystemEvents = 3',
        'AuditLogonEvents = 3',
        'AuditObjectAccess = 3',
        'AuditPrivilegeUse = 2',
        'AuditPolicyChange = 3',
        'AuditAccountManage = 3',
        'AuditProcessTracking = 0',
        'AuditDSAccess = 0',
        'AuditAccountLogon = 3',
      ],
    });
  }

  // ── Encryption / BitLocker ─────────────────────────────────────────────────
  if (s.encryption?.requireBitLocker) {
    machineRegistryEntries.push({
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'SOFTWARE\\Policies\\Microsoft\\FVE',
      name: 'EnableBDEWithNoTPM',
      type: 'DWORD',
      value: '1',
    });
    machineRegistryEntries.push({
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'SOFTWARE\\Policies\\Microsoft\\FVE',
      name: 'ActiveDirectoryBackup',
      type: 'DWORD',
      value: '1',
    });
  }

  // ── Browser / Edge ─────────────────────────────────────────────────────────
  if (s.browser) {
    const b = s.browser;
    if (b.homepage) {
      userRegistryEntries.push({
        hive: 'HKEY_CURRENT_USER',
        key:  'Software\\Policies\\Microsoft\\Edge',
        name: 'HomepageLocation',
        type: 'REG_SZ',
        value: b.homepage,
      });
      userRegistryEntries.push({
        hive: 'HKEY_CURRENT_USER',
        key:  'Software\\Policies\\Microsoft\\Edge',
        name: 'HomepageIsNewTabPage',
        type: 'DWORD',
        value: '0',
      });
    }
    if (b.defaultSearchEngine) {
      userRegistryEntries.push({
        hive: 'HKEY_CURRENT_USER',
        key:  'Software\\Policies\\Microsoft\\Edge',
        name: 'DefaultSearchProviderName',
        type: 'REG_SZ',
        value: b.defaultSearchEngine,
      });
    }
  }

  // ── Generate GPO Registry Preferences XML (HKLM → Machine/, HKCU → User/) ─
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
      type: 'gpo_registry_xml',
      filename: 'Machine-Registry.xml',
      sysvol_path: 'Machine/Preferences/Registry/Registry.xml',
      content: makeRegistryXml(machineRegistryEntries),
      description: 'GPO Registry Preferences (HKLM) — SYSVOL/Policies/{GPO-GUID}/Machine/Preferences/Registry/',
    });
  }

  if (userRegistryEntries.length > 0) {
    artifacts.push({
      type: 'gpo_registry_xml',
      filename: 'User-Registry.xml',
      sysvol_path: 'User/Preferences/Registry/Registry.xml',
      content: makeRegistryXml(userRegistryEntries),
      description: 'GPO Registry Preferences (HKCU) — SYSVOL/Policies/{GPO-GUID}/User/Preferences/Registry/',
    });
  }

  // GPT.INI is added after PS script generation (see below) so psLines is in scope.

  // ── Security Template (secedit) ────────────────────────────────────────────
  if (securitySettings.length > 0) {
    // Merge entries with the same section name to avoid duplicate [Section] headers
    const merged = {};
    for (const s of securitySettings) {
      if (!merged[s.section]) merged[s.section] = [];
      merged[s.section].push(...s.entries);
    }
    let inf = '[Unicode]\nUnicode=yes\n[Version]\nsignature="$CHICAGO$"\nRevision=1\n';
    for (const [section, entries] of Object.entries(merged)) {
      inf += `\n[${section}]\n${entries.join('\n')}\n`;
    }
    artifacts.push({
      type: 'security_template',
      filename: `${policy.name.replace(/\s+/g,'-')}-security.inf`,
      sysvol_path: 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf',
      content: inf,
      description: 'Security Template (Passwort, Lockout, Audit) — SYSVOL/Policies/{GPO-GUID}/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf',
      apply_command: `secedit /configure /db "%TEMP%\\secedit.sdb" /cfg "${policy.name.replace(/\s+/g,'-')}-security.inf" /overwrite`,
    });
  }

  // ── PowerShell Logon Script ────────────────────────────────────────────────
  const psLines = [
    `# OpenDirectory Policy: ${policy.name}`,
    `# Version: ${policy.version || '1.0'} | Generated: ${new Date().toISOString()}`,
    `# Targets: ${(policy.targets?.groups || []).join(', ') || 'All Users'}`,
    '',
  ];

  if (s.updates?.automatic !== undefined) {
    psLines.push('# Windows Update Policy');
    psLines.push(`Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" -Name "AUOptions" -Value ${s.updates.automatic ? 4 : 1} -ErrorAction SilentlyContinue`);
    psLines.push('');
  }

  if (psLines.length > 4) {
    const psName = `${policy.name.replace(/\s+/g,'-')}-policy.ps1`;
    artifacts.push({
      type: 'powershell_script',
      filename: psName,
      content: psLines.join('\n'),
      description: 'PowerShell Startup-Script — SYSVOL/Policies/{GPO-GUID}/Machine/Scripts/Startup/',
      sysvol_path: `Machine/Scripts/Startup/${psName}`,
    });
    // scripts.ini — tells the Scripts CSE to run this PS at machine Startup
    artifacts.push({
      type: 'scripts_ini',
      filename: 'scripts.ini',
      sysvol_path: 'Machine/Scripts/scripts.ini',
      content: `[Startup]\r\n0CmdLine=${psName}\r\n0Parameters=\r\n`,
      description: 'Scripts.ini — Windows Scripts CSE Startup-Eintrag (GPO Scripting CSE)',
    });
  }

  // GPT.INI — required for ANY GPO content; deploySambaGPO writes it with Version=65537.
  // Check AFTER all artifacts so psLines and all registry arrays are populated.
  if (artifacts.some(a => a.sysvol_path && a.type !== 'gpt_ini')) {
    artifacts.push({
      type: 'gpt_ini',
      filename: 'GPT.INI',
      sysvol_path: 'GPT.INI',
      content: `[General]\r\nVersion=65537\r\nDisplayName=Version 1\r\n`,
      description: 'GPO Metadata — kopieren nach SYSVOL/Policies/{GPO-GUID}/GPT.INI',
    });
  }

  return artifacts;
}

// ═══════════════════════════════════════════════════════════════════════════════
// LINUX COMPILER → Shell Configs + systemd units
// ═══════════════════════════════════════════════════════════════════════════════
function compileLinux(policy) {
  const artifacts = [];
  const s = policy.settings || {};

  // ── sysctl.conf ───────────────────────────────────────────────────────────
  const sysctlLines = [
    `# OpenDirectory Policy: ${policy.name}`,
    `# Generated: ${new Date().toISOString()}`,
    '',
  ];

  if (s.firewall?.enabled || s.audit?.logNetworkConn) {
    sysctlLines.push('# Network hardening');
    sysctlLines.push('net.ipv4.tcp_syncookies = 1');
    sysctlLines.push('net.ipv4.conf.all.rp_filter = 1');
    sysctlLines.push('net.ipv4.conf.default.rp_filter = 1');
    sysctlLines.push('net.ipv4.conf.all.accept_redirects = 0');
    sysctlLines.push('net.ipv4.conf.default.accept_redirects = 0');
    sysctlLines.push('net.ipv4.icmp_echo_ignore_broadcasts = 1');
    sysctlLines.push('');
  }

  if (s.audit?.enabled) {
    sysctlLines.push('# Kernel hardening');
    sysctlLines.push('kernel.dmesg_restrict = 1');
    sysctlLines.push('kernel.kptr_restrict = 2');
    sysctlLines.push('fs.suid_dumpable = 0');
    sysctlLines.push('');
  }

  if (sysctlLines.length > 3) {
    artifacts.push({
      type: 'sysctl',
      filename: '99-od-policy.conf',
      install_path: '/etc/sysctl.d/99-od-policy.conf',
      content: sysctlLines.join('\n'),
      description: 'Kernel Parameter',
      apply_command: 'sysctl -p /etc/sysctl.d/99-od-policy.conf',
    });
  }

  // ── sshd_config ───────────────────────────────────────────────────────────
  if (s.ssh) {
    const ssh = s.ssh;
    const sshdLines = [
      `# OpenDirectory Policy: ${policy.name} — SSH Configuration`,
      `# Generated: ${new Date().toISOString()}`,
      '',
    ];
    if (ssh.port          !== undefined) sshdLines.push(`Port ${ssh.port}`);
    if (ssh.permitRootLogin !== undefined) sshdLines.push(`PermitRootLogin ${ssh.permitRootLogin ? 'yes' : 'no'}`);
    if (ssh.passwordAuth  !== undefined) sshdLines.push(`PasswordAuthentication ${ssh.passwordAuth ? 'yes' : 'no'}`);
    if (ssh.allowGroups)  sshdLines.push(`AllowGroups ${ssh.allowGroups.join(' ')}`);
    sshdLines.push('Protocol 2');
    sshdLines.push('X11Forwarding no');
    sshdLines.push('MaxAuthTries 3');
    sshdLines.push('LoginGraceTime 30');
    sshdLines.push('ClientAliveInterval 300');
    sshdLines.push('ClientAliveCountMax 2');
    if (!ssh.passwordAuth) {
      sshdLines.push('PubkeyAuthentication yes');
    }
    artifacts.push({
      type: 'sshd_config',
      filename: 'sshd_config.d_od-policy.conf',
      install_path: '/etc/ssh/sshd_config.d/99-od-policy.conf',
      content: sshdLines.join('\n'),
      description: 'SSH Server Konfiguration',
      apply_command: 'systemctl reload sshd',
    });
  }

  // ── PAM Password Quality ──────────────────────────────────────────────────
  if (s.password) {
    const p = s.password;
    const pamLines = [
      `# OpenDirectory Policy: ${policy.name} — PAM Password Quality`,
      `# /etc/security/pwquality.conf.d/od-policy.conf (Drop-in)`,
      '',
    ];
    if (p.minLength      !== undefined) pamLines.push(`minlen = ${p.minLength}`);
    if (p.complexity)                    pamLines.push('dcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1');
    pamLines.push('maxrepeat = 3');
    if (p.historyLength  !== undefined)  pamLines.push(`# enforce_for_root`);
    artifacts.push({
      type: 'pam_pwquality',
      filename: 'od-pwquality.conf',
      install_path: '/etc/security/pwquality.conf.d/od-policy.conf',
      content: pamLines.join('\n'),
      description: 'PAM Passwort-Qualitäts-Richtlinie (Drop-in — überschreibt nicht /etc/security/pwquality.conf)',
      apply_command: 'mkdir -p /etc/security/pwquality.conf.d && cp od-pwquality.conf /etc/security/pwquality.conf.d/od-policy.conf',
    });

    if (p.lockoutThreshold !== undefined) {
      artifacts.push({
        type: 'pam_faillock',
        filename: 'faillock.conf',
        install_path: '/etc/security/faillock.conf',
        content: [
          `# OpenDirectory Policy: ${policy.name} — PAM faillock`,
          `deny = ${p.lockoutThreshold}`,
          `unlock_time = ${(p.lockoutDuration || 30) * 60}`,
          'audit',
          'silent',
        ].join('\n'),
        description: 'PAM Account Lockout (faillock.conf)',
      });

      // faillock.conf alone is not enough — pam_faillock.so must be active in PAM stack.
      // Generate a PAM drop-in that activates faillock for both Debian and RHEL families.
      const pamFaillockContent = [
        `# OpenDirectory Policy: ${policy.name} — pam_faillock activation`,
        '# Drop-in: enables pam_faillock for account lockout',
        '# Debian/Ubuntu: sourced via @include in /etc/pam.d/common-auth',
        '# RHEL/CentOS:   sourced via @include in /etc/pam.d/system-auth',
        '',
        'auth     required  pam_faillock.so preauth silent',
        'auth     required  pam_faillock.so authfail',
        'account  required  pam_faillock.so',
      ].join('\n');

      artifacts.push({
        type: 'pam_config',
        filename: 'od-faillock-pam',
        install_path: '/etc/pam.d/od-faillock',
        content: pamFaillockContent,
        description: 'PAM faillock Drop-in — aktiviert pam_faillock.so im PAM-Stack',
        apply_command: [
          'cp od-faillock-pam /etc/pam.d/od-faillock',
          // Debian/Ubuntu: add @include if not present
          'if [ -f /etc/pam.d/common-auth ] && ! grep -q od-faillock /etc/pam.d/common-auth; then',
          '  echo "@include od-faillock" >> /etc/pam.d/common-auth',
          'fi',
          // RHEL/CentOS: add @include if not present
          'if [ -f /etc/pam.d/system-auth ] && ! grep -q od-faillock /etc/pam.d/system-auth; then',
          '  echo "@include od-faillock" >> /etc/pam.d/system-auth',
          'fi',
        ].join('\n'),
      });
    }
  }

  // ── sudoers ───────────────────────────────────────────────────────────────
  if (s.sudo) {
    const sudo = s.sudo;
    const sudoLines = [
      `# OpenDirectory Policy: ${policy.name} — sudoers`,
      `# Generated: ${new Date().toISOString()}`,
      '',
      'Defaults requiretty',
      'Defaults !visiblepw',
      'Defaults use_pty',
      '',
    ];
    if (sudo.adminGroups) {
      for (const grp of sudo.adminGroups) {
        sudoLines.push(`%${grp} ALL=(ALL:ALL) ALL`);
      }
    }
    artifacts.push({
      type: 'sudoers',
      filename: '99-od-policy',
      install_path: '/etc/sudoers.d/99-od-policy',
      content: sudoLines.join('\n'),
      description: 'sudo Rechte',
      apply_command: 'chmod 440 /etc/sudoers.d/99-od-policy && visudo -cf /etc/sudoers.d/99-od-policy',
    });
  }

  // ── auditd rules ──────────────────────────────────────────────────────────
  if (s.audit?.enabled) {
    const auditLines = [
      `# OpenDirectory Policy: ${policy.name} — auditd rules`,
      '-D',
      '-b 8192',
      '-f 1',
      '',
      '# Auth events',
      '-w /etc/passwd -p wa -k identity',
      '-w /etc/group -p wa -k identity',
      '-w /etc/shadow -p wa -k identity',
      '-w /etc/sudoers -p wa -k sudo',
      '',
      '# Login events',
      '-w /var/log/wtmp -p wa -k logins',
      '-w /var/log/btmp -p wa -k logins',
      '-w /var/run/utmp -p wa -k session',
      '',
    ];
    if (s.audit.logFileAccess) {
      auditLines.push('# File access');
      auditLines.push('-a always,exit -F arch=b64 -S open -F exit=-EACCES -k access');
      auditLines.push('-a always,exit -F arch=b64 -S open -F exit=-EPERM -k access');
    }
    artifacts.push({
      type: 'auditd_rules',
      filename: '99-od-policy.rules',
      install_path: '/etc/audit/rules.d/99-od-policy.rules',
      content: auditLines.join('\n'),
      description: 'Linux Audit Rules',
      apply_command: 'augenrules --load && systemctl reload auditd',
    });
  }

  // ── systemd screen lock (for desktop) ────────────────────────────────────
  if (s.screenLock?.enabled && s.screenLock.timeoutMinutes) {
    const sl = s.screenLock;
    // inactivityLockMinutes hat Vorrang vor timeoutMinutes wenn gesetzt
    const idleSecs = (sl.inactivityLockMinutes || sl.timeoutMinutes) * 60;
    const gsdLines = [
      `# OpenDirectory Policy: ${policy.name} — GNOME Screen Lock`,
      '# /etc/dconf/db/local.d/00-od-policy',
      '[org/gnome/desktop/screensaver]',
      'lock-enabled=true',
      `idle-activation-enabled=true`,
      '',
      '[org/gnome/desktop/session]',
      `idle-delay=uint32 ${idleSecs}`,
    ];
    const lockScript = [
      '#!/bin/bash',
      `# OpenDirectory Policy: ${policy.name} — Screen Lock`,
      'mkdir -p /etc/dconf/db/local.d/locks',
      `cat > /etc/dconf/db/local.d/00-od-policy << 'EOF'`,
      ...gsdLines,
      'EOF',
      '',
      `cat > /etc/dconf/db/local.d/locks/00-od-policy << 'EOF'`,
      '/org/gnome/desktop/screensaver/lock-enabled',
      '/org/gnome/desktop/session/idle-delay',
      'EOF',
      '',
      'dconf update',
      'echo "Screen lock policy applied"',
    ];
    artifacts.push({
      type: 'shell_script',
      filename: `${policy.name.replace(/\s+/g,'-')}-screenlock.sh`,
      install_path: `/etc/opendirectory/${policy.name.replace(/\s+/g,'-')}-screenlock.sh`,
      content: lockScript.join('\n'),
      description: 'GNOME Screen Lock via dconf',
      apply_command: `bash /etc/opendirectory/${policy.name.replace(/\s+/g,'-')}-screenlock.sh`,
    });
  }

  // ── Browser: Firefox + Chrome Enterprise Policies (Linux) ─────────────────
  if (s.browser) {
    const b = s.browser;

    // Firefox: /etc/firefox/policies/policies.json (enterprise policy)
    const ffPolicies = {};
    if (b.homepage) {
      ffPolicies.Homepage = { URL: b.homepage, Locked: true, StartPage: 'homepage' };
      ffPolicies.NewTabPage = b.homepage;
    }
    if (b.defaultSearchEngine) {
      ffPolicies.SearchEngines = { Default: b.defaultSearchEngine, PreventInstalls: false };
    }
    if (Object.keys(ffPolicies).length > 0) {
      artifacts.push({
        type: 'json_config',
        filename: 'firefox-policies.json',
        install_path: '/etc/firefox/policies/policies.json',
        content: JSON.stringify({ policies: ffPolicies }, null, 2),
        description: 'Firefox Enterprise Policy (Startseite, Suchmaschine)',
        apply_command: 'mkdir -p /etc/firefox/policies && cp firefox-policies.json /etc/firefox/policies/policies.json',
      });
    }

    // Chrome / Chromium: /etc/opt/chrome/policies/managed/od-policy.json
    const chromePolicies = {};
    if (b.homepage) {
      chromePolicies.HomepageLocation       = b.homepage;
      chromePolicies.HomepageIsNewTabPage   = false;
      chromePolicies.NewTabPageLocation     = b.homepage;
      chromePolicies.RestoreOnStartup       = 4;                  // 4 = open specific pages
      chromePolicies.RestoreOnStartupURLs   = [b.homepage];
    }
    if (b.defaultSearchEngine) {
      chromePolicies.DefaultSearchProviderName    = b.defaultSearchEngine;
      chromePolicies.DefaultSearchProviderEnabled = true;
    }
    if (Object.keys(chromePolicies).length > 0) {
      const chromeContent = JSON.stringify(chromePolicies, null, 2);
      artifacts.push({
        type: 'json_config',
        filename: 'chrome-od-policy.json',
        install_path: '/etc/opt/chrome/policies/managed/od-policy.json',
        content: chromeContent,
        description: 'Google Chrome Enterprise Policy (Startseite, Suchmaschine)',
        apply_command: 'mkdir -p /etc/opt/chrome/policies/managed && cp chrome-od-policy.json /etc/opt/chrome/policies/managed/od-policy.json',
      });
      // Chromium uses a different path
      artifacts.push({
        type: 'json_config',
        filename: 'chromium-od-policy.json',
        install_path: '/etc/chromium/policies/managed/od-policy.json',
        content: chromeContent,
        description: 'Chromium Enterprise Policy (Startseite, Suchmaschine)',
        apply_command: 'mkdir -p /etc/chromium/policies/managed && cp chromium-od-policy.json /etc/chromium/policies/managed/od-policy.json',
      });
    }
  }

  // ── Deployment Script ─────────────────────────────────────────────────────
  const deployScript = [
    '#!/bin/bash',
    `# OpenDirectory Policy Deployment: ${policy.name}`,
    `# Version: ${policy.version || '1.0'} | Generated: ${new Date().toISOString()}`,
    `# Targets: ${(policy.targets?.groups || []).join(', ') || 'All'}`,
    '',
    'set -euo pipefail',
    'POLICY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
    'cd "$POLICY_DIR"   # apply_commands use relative paths — must run from artifact dir',
    '',
    'echo "Applying policy: ' + policy.name + '"',
    '',
  ];

  for (const artifact of artifacts) {
    if (artifact.install_path && artifact.filename) {
      const dir = artifact.install_path.substring(0, artifact.install_path.lastIndexOf('/'));
      deployScript.push(`# ${artifact.description}`);
      if (dir) deployScript.push(`mkdir -p "${dir}"`);
      deployScript.push(`cp "$POLICY_DIR/${artifact.filename}" "${artifact.install_path}"`);
      if (artifact.apply_command) deployScript.push(artifact.apply_command);
      deployScript.push('');
    }
  }

  // ── Systemd Enforcement: path unit + service ──────────────────────────────
  // Watches the actual install_paths of this policy's artifacts for drift detection.
  const activeFiles = artifacts
    .filter(a => a.install_path && a.type !== 'systemd_path' && a.type !== 'systemd_service' && a.type !== 'manifest' && a.type !== 'deploy_script')
    .map(a => a.install_path);

  if (activeFiles.length > 0 || artifacts.length > 0) {
    const pathUnitLines = [
      '[Unit]',
      `Description=OpenDirectory Policy Enforcement: ${policy.name}`,
      '',
      '[Path]',
      ...(activeFiles.length > 0 ? activeFiles : ['/etc/ssh/sshd_config']).map(f => `PathModified=${f}`),
      'Unit=od-enforce.service',
      '',
      '[Install]',
      'WantedBy=multi-user.target',
    ];

    artifacts.push({
      type: 'systemd_path',
      filename: 'od-enforce.path',
      content: pathUnitLines.join('\n'),
      description: 'systemd path unit — überwacht Policy-Dateien und stellt sie bei Änderung wieder her',
      install_path: '/etc/systemd/system/od-enforce.path',
      apply_command: 'systemctl daemon-reload && systemctl enable --now od-enforce.path 2>/dev/null || true',
    });

    artifacts.push({
      type: 'systemd_service',
      filename: 'od-enforce.service',
      content: [
        '[Unit]',
        `Description=OpenDirectory Policy Re-Apply: ${policy.name}`,
        'After=network.target',
        '',
        '[Service]',
        'Type=oneshot',
        'ExecStart=/usr/local/bin/od-agent',
        'StandardOutput=journal',
        'StandardError=journal',
      ].join('\n'),
      description: 'systemd service unit — wird von od-enforce.path bei Dateiänderung getriggert',
      install_path: '/etc/systemd/system/od-enforce.service',
    });
  }

  // ── Hash Manifest (SHA256 pro Artifact für Drift Detection) ───────────────
  const { createHash } = require('crypto');
  const manifest = {};
  for (const a of artifacts) {
    if (a.install_path && a.content) {
      manifest[a.install_path] = createHash('sha256').update(a.content).digest('hex');
    }
  }
  if (Object.keys(manifest).length > 0) {
    artifacts.push({
      type: 'manifest',
      filename: 'od-manifest.json',
      content: JSON.stringify(manifest, null, 2),
      description: 'SHA256-Hashes der Policy-Dateien — Drift Detection im od-agent',
      install_path: '/etc/opendirectory/od-manifest.json',
    });
  }

  // ── Deploy Script: auch systemd units + manifest installieren ─────────────
  deployScript.push('# Systemd enforcement units installieren');
  deployScript.push('cp "$POLICY_DIR/od-enforce.path"   /etc/systemd/system/ 2>/dev/null || true');
  deployScript.push('cp "$POLICY_DIR/od-enforce.service" /etc/systemd/system/ 2>/dev/null || true');
  deployScript.push('cp "$POLICY_DIR/od-manifest.json"  /etc/opendirectory/   2>/dev/null || true');
  deployScript.push('systemctl daemon-reload && systemctl enable --now od-enforce.path 2>/dev/null || true');
  deployScript.push('');
  deployScript.push('echo "Policy applied successfully!"');

  artifacts.push({
    type: 'deploy_script',
    filename: 'deploy.sh',
    content: deployScript.join('\n'),
    description: 'Deployment-Script (Ansible: copy + script task, oder direkt ausführen)',
  });

  return artifacts;
}

// ═══════════════════════════════════════════════════════════════════════════════
// macOS COMPILER → .mobileconfig Configuration Profiles
// ═══════════════════════════════════════════════════════════════════════════════
function compileMacOS(policy) {
  const artifacts = [];
  const s = policy.settings || {};
  const policyFilename = policy.name.replace(/\s+/g, '-');
  const profileId = `local.opendirectory.${policy.id || policy.name.toLowerCase().replace(/\s+/g,'-')}`;
  const payloads = [];

  // ── Password Policy ────────────────────────────────────────────────────────
  if (s.password) {
    const p = s.password;
    const payload = {
      'PayloadType': 'com.apple.mobiledevice.passwordpolicy',
      'PayloadIdentifier': `${profileId}.password`,
      'PayloadUUID': uuid(policy.id + 'password'),
      'PayloadVersion': 1,
      'PayloadDisplayName': 'Password Policy',
    };
    if (p.minLength      !== undefined) payload['minLength']           = p.minLength;
    if (p.complexity)                   payload['requireAlphanumeric'] = true;
    if (p.maxAgeDays     !== undefined) payload['maxPINAgeInDays']     = p.maxAgeDays;
    if (p.historyLength  !== undefined) payload['pinHistory']          = p.historyLength;
    if (p.lockoutThreshold !== undefined) payload['maxFailedAttempts'] = p.lockoutThreshold;
    payloads.push(payload);
  }

  // ── Screen Lock / Passcode ────────────────────────────────────────────────
  if (s.screenLock?.enabled) {
    const sl = s.screenLock;
    // inactivityLockMinutes hat Vorrang (konsistent mit Windows/Linux)
    const idleSecs = ((sl.inactivityLockMinutes || sl.timeoutMinutes) || 5) * 60;
    const payload = {
      'PayloadType': 'com.apple.screensaver',
      'PayloadIdentifier': `${profileId}.screensaver`,
      'PayloadUUID': uuid(policy.id + 'screensaver'),
      'PayloadVersion': 1,
      'PayloadDisplayName': 'Screen Saver',
      'idleTime': idleSecs,
      'loginWindowModuleList': ['com.apple.loginwindow.LoginWindowController'],
    };
    if (sl.requirePassword) {
      payload['askForPassword']      = true;
      payload['askForPasswordDelay'] = 0;
    }
    payloads.push(payload);
  }

  // ── Firewall ───────────────────────────────────────────────────────────────
  if (s.firewall) {
    payloads.push({
      'PayloadType': 'com.apple.security.firewall',
      'PayloadIdentifier': `${profileId}.firewall`,
      'PayloadUUID': uuid(policy.id + 'firewall'),
      'PayloadVersion': 1,
      'PayloadDisplayName': 'Firewall',
      'EnableFirewall':       s.firewall.enabled ? true : false,
      'BlockAllIncoming':     s.firewall.defaultDeny ? true : false,
      'EnableStealthMode':    s.firewall.stealth ? true : false,
    });
  }

  // ── FileVault ──────────────────────────────────────────────────────────────
  if (s.encryption?.requireFileVault) {
    payloads.push({
      'PayloadType': 'com.apple.MCX.FileVault2',
      'PayloadIdentifier': `${profileId}.filevault`,
      'PayloadUUID': uuid(policy.id + 'filevault'),
      'PayloadVersion': 1,
      'PayloadDisplayName': 'FileVault 2',
      'Enable': 'On',
      'Defer': true,
      'UserEntersMissingInfo': false,
      'UseRecoveryKey': true,
      'ShowRecoveryKey': false,
    });
  }

  // ── Restrictions ──────────────────────────────────────────────────────────
  const restrictions = {
    'PayloadType': 'com.apple.applicationaccess',
    'PayloadIdentifier': `${profileId}.restrictions`,
    'PayloadUUID': uuid(policy.id + 'restrictions'),
    'PayloadVersion': 1,
    'PayloadDisplayName': 'Restrictions',
  };
  let hasRestrictions = false;

  if (s.software?.blockedApps) {
    restrictions['blacklistedAppBundleIDs'] = s.software.blockedApps;
    hasRestrictions = true;
  }
  if (s.updates?.automatic === false) {
    restrictions['forceAutomaticDateAndTime'] = false;
    hasRestrictions = true;
  }
  if (hasRestrictions) payloads.push(restrictions);

  // ── Browser (Safari / Chrome via Managed Preferences) ─────────────────────
  if (s.browser?.homepage) {
    payloads.push({
      'PayloadType': 'com.apple.Safari.policy',
      'PayloadIdentifier': `${profileId}.safari`,
      'PayloadUUID': uuid(policy.id + 'safari'),
      'PayloadVersion': 1,
      'PayloadDisplayName': 'Safari Policy',
      'HomePage': s.browser.homepage,
      'NewWindowBehavior': 0,
    });
  }

  // ── Audit (OpenBSM) ────────────────────────────────────────────────────────
  if (s.audit?.enabled) {
    const auditScript = [
      '#!/bin/bash',
      `# OpenDirectory Policy: ${policy.name} — macOS Audit (OpenBSM)`,
      '# Run as root via LaunchDaemon or MDM script',
      '',
      '# Enable audit classes',
      'sed -i "" "s/^flags:/flags:lo,aa,ad,fd,fm,^-fw,^-fc/" /etc/security/audit_control 2>/dev/null || true',
      'audit -s',
      '',
      '# Ensure audit log rotation',
      'launchctl kickstart system/com.apple.auditd 2>/dev/null || true',
    ];
    artifacts.push({
      type: 'shell_script',
      filename: 'macos-audit.sh',
      content: auditScript.join('\n'),
      description: 'macOS OpenBSM Audit Aktivierung',
    });
  }

  // ── Generate .mobileconfig ────────────────────────────────────────────────
  if (payloads.length > 0) {
    // plist XML generation (simplified, no binary plist)
    const plistPayloads = payloads.map(p => {
      const entries = Object.entries(p).map(([k, v]) => {
        if (typeof v === 'boolean') return `\t\t<key>${k}</key>\n\t\t<${v}/>`;
        if (typeof v === 'number')  return `\t\t<key>${k}</key>\n\t\t<integer>${v}</integer>`;
        if (typeof v === 'string')  return `\t\t<key>${k}</key>\n\t\t<string>${v}</string>`;
        if (Array.isArray(v)) {
          const items = v.map(i => `\t\t\t<string>${i}</string>`).join('\n');
          return `\t\t<key>${k}</key>\n\t\t<array>\n${items}\n\t\t</array>`;
        }
        return '';
      }).filter(Boolean).join('\n');
      return `\t<dict>\n${entries}\n\t</dict>`;
    }).join('\n');

    const mobileconfig = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>PayloadDisplayName</key>
\t<string>${policy.name}</string>
\t<key>PayloadDescription</key>
\t<string>${policy.description || 'OpenDirectory Managed Policy'}</string>
\t<key>PayloadIdentifier</key>
\t<string>${profileId}</string>
\t<key>PayloadOrganization</key>
\t<string>OpenDirectory</string>
\t<key>PayloadRemovalDisallowed</key>
\t<true/>
\t<key>PayloadScope</key>
\t<string>System</string>
\t<key>PayloadType</key>
\t<string>Configuration</string>
\t<key>PayloadUUID</key>
\t<string>${uuid(policy.id || policy.name)}</string>
\t<key>PayloadVersion</key>
\t<integer>1</integer>
\t<key>PayloadContent</key>
\t<array>
${plistPayloads}
\t</array>
</dict>
</plist>`;

    artifacts.push({
      type: 'mobileconfig',
      filename: `${policyFilename}.mobileconfig`,
      install_path: `/Library/OpenDirectory/${policyFilename}.mobileconfig`,
      content: mobileconfig,
      description: 'macOS Configuration Profile — per MDM deployen oder: sudo profiles -I -F <file>',
      // profiles install -path is the current syntax (macOS 13+); -I -F deprecated
      apply_command: `mkdir -p /Library/OpenDirectory && cp "${policyFilename}.mobileconfig" /Library/OpenDirectory/ && profiles install -path "/Library/OpenDirectory/${policyFilename}.mobileconfig"`,
    });
  }

  // ── LaunchDaemon für Script-Execution ─────────────────────────────────────
  const launchDaemon = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>Label</key>
\t<string>${profileId}.enforcement</string>
\t<key>ProgramArguments</key>
\t<array>
\t\t<string>/bin/bash</string>
\t\t<string>/Library/OpenDirectory/Policies/${policy.name.replace(/\s+/g,'-')}-enforce.sh</string>
\t</array>
\t<key>RunAtLoad</key>
\t<true/>
\t<key>StartInterval</key>
\t<integer>3600</integer>
\t<key>StandardOutPath</key>
\t<string>/var/log/od-policy-${policy.name.replace(/\s+/g,'-')}.log</string>
\t<key>StandardErrorPath</key>
\t<string>/var/log/od-policy-${policy.name.replace(/\s+/g,'-')}.err</string>
</dict>
</plist>`;

  // ── Enforcement Shell Script (referenced by LaunchDaemon) ─────────────────
  const policyDir = '/Library/OpenDirectory/Policies';
  const enforceScript = [
    '#!/bin/bash',
    `# OpenDirectory Policy Enforcement: ${policy.name}`,
    `# Stündlich von LaunchDaemon ${profileId}.enforcement ausgeführt`,
    '',
    `POLICY_DIR="${policyDir}"`,
    `PROFILE="/Library/OpenDirectory/${policyFilename}.mobileconfig"`,
    '',
    '# Prüfe ob das Profil noch installiert ist',
    `if ! profiles -C -v 2>/dev/null | grep -q "${profileId}"; then`,
    '  # Profil nicht vorhanden — re-installieren',
    '  if [ -f "$PROFILE" ]; then',
    '    profiles install -path "$PROFILE" 2>/dev/null && echo "$(date): Profile re-installed" >> /var/log/od-enforce.log',
    '  fi',
    'fi',
    '',
    '# Heartbeat an OpenDirectory Portal',
    `DEVICE_ID=$(cat /Library/OpenDirectory/device-id 2>/dev/null)`,
    `PORTAL=$(cat /Library/OpenDirectory/portal-url 2>/dev/null)`,
    'if [ -n "$DEVICE_ID" ] && [ -n "$PORTAL" ]; then',
    '  OD_TOKEN=$(cat /Library/OpenDirectory/od-token 2>/dev/null)',
    '  curl -sk -X POST "$PORTAL/api/client/heartbeat" \\',
    '    -H "X-OD-Token: $OD_TOKEN" -H "Content-Type: application/json" \\',
    '    -d "{\"device_id\":\"$DEVICE_ID\",\"platform\":\"macos\",\"os_version\":\"$(sw_vers -productVersion)\"}" >/dev/null 2>&1 || true',
    'fi',
  ];

  artifacts.push({
    type: 'shell_script',
    filename: `${policyFilename}-enforce.sh`,
    install_path: `${policyDir}/${policyFilename}-enforce.sh`,
    content: enforceScript.join('\n'),
    description: 'macOS Policy Enforcement Script — stündlich von LaunchDaemon ausgeführt, prüft ob Profile noch installiert ist',
    apply_command: `mkdir -p "${policyDir}" && cp "${policyFilename}-enforce.sh" "${policyDir}/" && chmod +x "${policyDir}/${policyFilename}-enforce.sh"`,
  });

  artifacts.push({
    type: 'launchdaemon',
    filename: `${profileId}.enforcement.plist`,
    install_path: `/Library/LaunchDaemons/${profileId}.enforcement.plist`,
    content: launchDaemon,
    description: 'LaunchDaemon — startet Enforcement-Script bei Boot und stündlich',
    // launchctl bootstrap system is the current syntax (macOS 13+); load -w deprecated
    apply_command: `launchctl unload /Library/LaunchDaemons/${profileId}.enforcement.plist 2>/dev/null; launchctl bootstrap system /Library/LaunchDaemons/${profileId}.enforcement.plist`,
  });

  return artifacts;
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN COMPILER
// ═══════════════════════════════════════════════════════════════════════════════
function compile(policy) {
  const platforms = policy.targets?.platforms || ['windows', 'linux', 'macos'];
  const result = {
    policy_id: policy.id,
    policy_name: policy.name,
    version: policy.version || '1.0',
    compiled_at: new Date().toISOString(),
    artifacts: {},
  };

  if (platforms.includes('windows') || platforms.includes('all')) {
    result.artifacts.windows = compileWindows(policy);
  }
  if (platforms.includes('linux') || platforms.includes('all')) {
    result.artifacts.linux = compileLinux(policy);
  }
  if (platforms.includes('macos') || platforms.includes('all')) {
    result.artifacts.macos = compileMacOS(policy);
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// NETWORK DRIVES COMPILER
// Windows  → GPO Drives.xml (SYSVOL/Policies/{GPO}/User/Preferences/Drives/)
// Linux    → /etc/fstab entries + systemd.mount + autofs (per-user via pam_mount)
// macOS    → LaunchAgent plist per share + optional .mobileconfig
// ═══════════════════════════════════════════════════════════════════════════════
function compileNetworkDrives(policy) {
  const raw    = (policy.settings || {}).networkDrives || [];
  // Überspringe Einträge die noch nicht aufgelöst wurden (nur _shareId, kein server/share)
  const drives = raw.filter(d => d.server && d.share);
  if (!drives.length) return { windows: [], linux: [], macos: [] };

  // ── Windows: GPO Drives.xml ────────────────────────────────────────────────
  const driveElems = drives.map(d => {
    const uid = `{${uuid(policy.id + d.letter + d.server + d.share)}}`;
    const uncPath = d.type === 'nfs'
      ? `\\\\${d.server}\\${d.share}` // NFS via DFS or SMB gateway
      : `\\\\${d.server}\\${d.share}`;
    return `  <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}"
         name="${d.letter}:"
         status="${d.letter}:"
         image="2"
         changed="${now()}"
         uid="${uid}">
    <Properties
      action="U"
      thisDrive="SHOW"
      allDrives="NOCHANGE"
      userName=""
      path="${uncPath}"
      label="${d.label || d.share}"
      persistent="${d.reconnect !== false ? 1 : 0}"
      useLetter="1"
      letter="${d.letter}"/>
  </Drive>`;
  });

  const drivesXml = `<?xml version="1.0" encoding="UTF-8"?>
<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">
${driveElems.join('\n')}
</Drives>`;

  // ── Linux: fstab + systemd.mount + autofs + pam_mount ─────────────────────
  const fstabLines = [
    `# OpenDirectory Network Drives — ${policy.name}`,
    `# Generated: ${new Date().toISOString()}`,
    `# Add to /etc/fstab or use the systemd.mount units`,
    '',
  ];
  const sysctemUnits = [];
  const pamMountEntries = [];

  for (const d of drives) {
    const mp = d.mountPoint || `/mnt/${d.share.replace(/[^a-z0-9]/gi, '-').toLowerCase()}`;
    if (d.type === 'smb' || !d.type) {
      fstabLines.push(`//${d.server}/${d.share}  ${mp}  cifs  credentials=/etc/od-creds/${d.share}.cred,uid=%i,gid=%i,iocharset=utf8,vers=3.0,seal,_netdev,x-systemd.automount  0  0`);
      // pam_mount for per-user mounting at login
      pamMountEntries.push(`  <volume type="cifs" server="${d.server}" share="${d.share}" mountpoint="${mp}" options="uid=%(USER),vers=3.0"/>`);
    } else if (d.type === 'nfs') {
      fstabLines.push(`${d.server}:/${d.share}  ${mp}  nfs4  rw,async,_netdev,x-systemd.automount  0  0`);
    }

    // Systemd .mount unit
    const unitName = mp.replace(/\//g, '-').replace(/^-/, '') + '.mount';
    const autoName = mp.replace(/\//g, '-').replace(/^-/, '') + '.automount';
    const what = d.type === 'nfs' ? `${d.server}:/${d.share}` : `//${d.server}/${d.share}`;
    const type = d.type === 'nfs' ? 'nfs4' : 'cifs';
    const opts = d.type === 'nfs'
      ? 'rw,async'
      : `credentials=/etc/od-creds/${d.share}.cred,uid=1000,vers=3.0,seal`;

    sysctemUnits.push({
      filename: unitName,
      content: `[Unit]\nDescription=OD Network Drive: ${d.label || d.share}\nAfter=network-online.target\nWants=network-online.target\n\n[Mount]\nWhat=${what}\nWhere=${mp}\nType=${type}\nOptions=${opts}\n\n[Install]\nWantedBy=multi-user.target`,
    });
    sysctemUnits.push({
      filename: autoName,
      content: `[Unit]\nDescription=OD Automount: ${d.label || d.share}\n\n[Automount]\nWhere=${mp}\nTimeoutIdleSec=300\n\n[Install]\nWantedBy=multi-user.target`,
    });
  }

  // pam_mount.conf.xml snippet
  const pamMountXml = `<!-- OpenDirectory — pam_mount network drives (add to /etc/security/pam_mount.conf.xml) -->
<!-- Mounts drives at user login, unmounts at logout -->
${pamMountEntries.join('\n')}`;

  // Deployment script
  const deployLines = [
    '#!/bin/bash',
    `# OpenDirectory Network Drives Deployment: ${policy.name}`,
    'set -euo pipefail',
    '',
    '# Create credential files',
    'mkdir -p /etc/od-creds',
    'chmod 700 /etc/od-creds',
    '',
  ];
  for (const d of drives) {
    const mp = d.mountPoint || `/mnt/${d.share.replace(/[^a-z0-9]/gi, '-').toLowerCase()}`;
    deployLines.push(`mkdir -p "${mp}"`);
    if (d.type !== 'nfs') {
      deployLines.push(`# Create credential file for ${d.share}:`);
      deployLines.push(`cat > /etc/od-creds/${d.share}.cred << 'EOF'`);
      deployLines.push(`username=<NAS_USERNAME>`);
      deployLines.push(`password=<NAS_PASSWORD>`);
      deployLines.push(`domain=<AD_DOMAIN>`);
      deployLines.push('EOF');
      deployLines.push(`chmod 600 /etc/od-creds/${d.share}.cred`);
    }
  }
  for (const u of sysctemUnits) {
    deployLines.push(`cp "${u.filename}" /etc/systemd/system/`);
  }
  deployLines.push('systemctl daemon-reload');
  for (const u of sysctemUnits.filter(u => u.filename.endsWith('.automount'))) {
    deployLines.push(`systemctl enable --now "${u.filename}"`);
  }
  deployLines.push('echo "Network drives configured!"');

  const linuxArtifacts = [
    { type: 'fstab_snippet', filename: 'od-drives-fstab.txt', content: fstabLines.join('\n'),
      description: 'fstab Einträge — anhängen an /etc/fstab' },
    { type: 'pam_mount', filename: 'od-pam_mount.xml', content: pamMountXml,
      description: 'pam_mount — Laufwerke beim Benutzer-Login mounten' },
    ...sysctemUnits.map(u => ({
      type: 'systemd_unit', filename: u.filename, content: u.content,
      install_path: `/etc/systemd/system/${u.filename}`,
      description: `systemd ${u.filename.endsWith('.automount') ? 'Automount' : 'Mount'} Unit`,
      apply_command: `systemctl enable --now ${u.filename}`,
    })),
    { type: 'deploy_script', filename: 'deploy-drives.sh', content: deployLines.join('\n'),
      description: 'Deployment Script — als root ausführen oder per Ansible' },
  ];

  // ── macOS: LaunchAgent per drive ───────────────────────────────────────────
  const macArtifacts = [];
  const macMountScript = [
    '#!/bin/bash',
    `# OpenDirectory Network Drives — macOS: ${policy.name}`,
    `# Mounts network drives at login`,
    '',
  ];

  for (const d of drives) {
    const schema = d.type === 'nfs' ? 'nfs' : 'smb';
    const url = d.type === 'nfs'
      ? `nfs://${d.server}/${d.share}`
      : `smb://${d.server}/${d.share}`;
    const label = `local.opendirectory.mount.${d.share.toLowerCase().replace(/[^a-z0-9]/g, '-')}`;
    const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>Label</key>
\t<string>${label}</string>
\t<key>ProgramArguments</key>
\t<array>
\t\t<string>/usr/bin/osascript</string>
\t\t<string>-e</string>
\t\t<string>mount volume "${url}"</string>
\t</array>
\t<key>RunAtLoad</key>
\t<true/>
\t<key>StartInterval</key>
\t<integer>3600</integer>
</dict>
</plist>`;
    macArtifacts.push({
      type: 'launchagent',
      filename: `${label}.plist`,
      install_path: `/Library/LaunchAgents/${label}.plist`,
      content: plist,
      description: `Auto-Mount «${d.label || d.share}» (${url}) bei jedem Login`,
      apply_command: `launchctl load -w /Library/LaunchAgents/${label}.plist`,
    });
    macMountScript.push(`open "${url}" 2>/dev/null || osascript -e 'mount volume "${url}"'`);
  }
  macMountScript.push('echo "Network drives mounted!"');
  macArtifacts.push({
    type: 'shell_script',
    filename: 'mount-drives.sh',
    content: macMountScript.join('\n'),
    description: 'Sofortiges Mounten aller Netzlaufwerke',
  });

  return {
    windows: [
      { type: 'gpo_drives_xml', filename: 'Drives.xml',
        sysvol_path: `User/Preferences/Drives/Drives.xml`,
        content: drivesXml,
        description: `GPO Drive Mapping → in SYSVOL Policy-Verzeichnis ablegen\n${drives.map(d => `  ${d.letter}: → \\\\${d.server}\\${d.share}`).join('\n')}` },
    ],
    linux: linuxArtifacts,
    macos: macArtifacts,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRINTERS COMPILER
// Windows → GPO Printers.xml (User/Preferences/Printers/)
// Linux   → CUPS lpadmin deployment script
// macOS   → .mobileconfig com.apple.mcx.printing payload
// ═══════════════════════════════════════════════════════════════════════════════
function compilePrinters(policy) {
  const raw      = (policy.settings || {}).printers || [];
  // Überspringe Einträge die noch nicht aufgelöst wurden (nur _printerId, kein ipAddress)
  const printers = raw.filter(p => p.ipAddress);
  if (!printers.length) return { windows: [], linux: [], macos: [] };

  // ── Windows: GPO Printers.xml ──────────────────────────────────────────────
  const sharedPrinterElems = printers.map(p => {
    const uid = `{${uuid(policy.id + p.name + (p.shareName || p.ipAddress))}}`;
    const path = p.shareName || `\\\\${p.ipAddress}\\${p.name}`;
    return `  <SharedPrinter clsid="{9A5E9697-9095-436d-A0EE-4D128FDFBCE5}"
    name="${path}"
    status="${path}"
    image="1"
    changed="${now()}"
    uid="${uid}">
    <Properties
      action="R"
      comment="${p.location || ''}"
      path="${path}"
      location="${p.location || ''}"
      default="${p.default ? 1 : 0}"
      skipLocal="0"
      deleteAll="0"
      persistent="0"
      portName=""/>
  </SharedPrinter>`;
  });

  // If using TCP/IP port printers (direct IP without share):
  const tcpPrinterElems = printers
    .filter(p => p.ipAddress && !p.shareName)
    .map(p => {
      const uid = `{${uuid(policy.id + p.name + 'tcp')}}`;
      const protocol = p.protocol === 'ipp' ? 'ipp' : p.protocol === 'lpd' ? 'lpd' : 'socket';
      const uri = protocol === 'ipp'
        ? `http://${p.ipAddress}/ipp/print`
        : protocol === 'lpd' ? `${p.ipAddress}` : `${p.ipAddress}:9100`;

      return `  <TCPIPPrinter clsid="{B3A41F4B-B9C5-472e-8FDB-2B7C80B91B35}"
    name="${p.name}"
    status="${p.name}"
    image="1"
    changed="${now()}"
    uid="${uid}">
    <Properties
      action="C"
      comment="${p.location || ''}"
      ipAddress="${p.ipAddress}"
      localName="${p.name}"
      path="${uri}"
      location="${p.location || ''}"
      default="${p.default ? 1 : 0}"
      skipLocal="0"
      deleteAll="0"
      port="9100"
      protocol="${p.protocol === 'ipp' ? 2 : 1}"
      printer:name="${p.name}"
      driverName="${p.driver || 'Generic / Text Only'}"/>
  </TCPIPPrinter>`;
    });

  const printersXml = `<?xml version="1.0" encoding="UTF-8"?>
<Printers clsid="{1F577D12-3D1B-471f-A009-7EFDA8955ED6}">
${sharedPrinterElems.join('\n')}
${tcpPrinterElems.join('\n')}
</Printers>`;

  // ── Linux: CUPS lpadmin script ─────────────────────────────────────────────
  const cupsLines = [
    '#!/bin/bash',
    `# OpenDirectory Printer Deployment: ${policy.name}`,
    `# Generated: ${new Date().toISOString()}`,
    'set -euo pipefail',
    '',
    '# Ensure CUPS is installed',
    'command -v cupsd >/dev/null || apt-get install -y cups cups-client 2>/dev/null || yum install -y cups 2>/dev/null',
    'systemctl enable cups --now',
    '',
  ];

  for (const p of printers) {
    const protocol = p.protocol || 'ipp';
    let uri;
    if (p.protocol === 'ipp' || !p.protocol) {
      uri = `ipp://${p.ipAddress}/ipp/print`;
    } else if (p.protocol === 'lpd') {
      uri = `lpd://${p.ipAddress}`;
    } else if (p.protocol === 'socket') {
      uri = `socket://${p.ipAddress}:9100`;
    } else {
      uri = `ipp://${p.ipAddress}/ipp/print`;
    }

    cupsLines.push(`# Printer: ${p.name}`);
    cupsLines.push(`# Remove if exists, then add fresh`);
    cupsLines.push(`lpadmin -x "${p.name}" 2>/dev/null || true`);
    cupsLines.push(`lpadmin -p "${p.name}" -v "${uri}" -m everywhere -E -L "${p.location || ''}" -D "${p.label || p.name}"`);
    if (p.default) cupsLines.push(`lpoptions -d "${p.name}"`);
    cupsLines.push('');
  }
  cupsLines.push('echo "Printers configured in CUPS!"');
  cupsLines.push('lpstat -p');

  // ── macOS: .mobileconfig com.apple.mcx.printing ────────────────────────────
  const macPrinterPayload = {
    'PayloadType': 'com.apple.mcx.printing',
    'PayloadIdentifier': `local.opendirectory.${policy.id || 'policy'}.printing`,
    'PayloadUUID': uuid(policy.id + 'printing'),
    'PayloadVersion': 1,
    'PayloadDisplayName': 'Printer Configuration',
    'lockdownPrint': false,
    'PrinterLock': false,
    'printers': Object.fromEntries(printers.map(p => {
      const uri = p.protocol === 'ipp' || !p.protocol
        ? `ipp://${p.ipAddress}/ipp/print`
        : p.protocol === 'lpd'
        ? `lpd://${p.ipAddress}`
        : `socket://${p.ipAddress}:9100`;
      return [p.name, {
        'device-uri': uri,
        'printer-is-shared': false,
        'printer-info': p.label || p.name,
        'printer-location': p.location || '',
        'ppd-name': p.driver || 'AirPrint',
        'printer-is-default': !!p.default,
      }];
    })),
  };

  const macPrintersEntries = printers.map(p => {
    const uri = p.protocol === 'ipp' || !p.protocol
      ? `ipp://${p.ipAddress}/ipp/print`
      : `socket://${p.ipAddress}:9100`;
    return `\t\t\t<key>${p.name}</key>
\t\t\t<dict>
\t\t\t\t<key>device-uri</key>
\t\t\t\t<string>${uri}</string>
\t\t\t\t<key>printer-info</key>
\t\t\t\t<string>${p.label || p.name}</string>
\t\t\t\t<key>printer-location</key>
\t\t\t\t<string>${p.location || ''}</string>
\t\t\t\t<key>ppd-name</key>
\t\t\t\t<string>${p.driver || 'everywhere'}</string>
\t\t\t\t<key>printer-is-default</key>
\t\t\t\t<${!!p.default}/>
\t\t\t</dict>`;
  }).join('\n');

  const macMobileconfig = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>PayloadDisplayName</key>
\t<string>${policy.name} — Printers</string>
\t<key>PayloadIdentifier</key>
\t<string>local.opendirectory.${policy.id || 'policy'}.printers</string>
\t<key>PayloadUUID</key>
\t<string>${uuid(policy.id + 'printers-profile')}</string>
\t<key>PayloadVersion</key>
\t<integer>1</integer>
\t<key>PayloadType</key>
\t<string>Configuration</string>
\t<key>PayloadScope</key>
\t<string>System</string>
\t<key>PayloadContent</key>
\t<array>
\t\t<dict>
\t\t\t<key>PayloadType</key>
\t\t\t<string>com.apple.mcx.printing</string>
\t\t\t<key>PayloadIdentifier</key>
\t\t\t<string>local.opendirectory.${policy.id || 'policy'}.printing</string>
\t\t\t<key>PayloadUUID</key>
\t\t\t<string>${uuid(policy.id + 'printing')}</string>
\t\t\t<key>PayloadVersion</key>
\t\t\t<integer>1</integer>
\t\t\t<key>lockdownPrint</key>
\t\t\t<false/>
\t\t\t<key>printers</key>
\t\t\t<dict>
${macPrintersEntries}
\t\t\t</dict>
\t\t</dict>
\t</array>
</dict>
</plist>`;

  // macOS fallback: lpadmin script (for non-MDM environments)
  const macLpadminLines = [
    '#!/bin/bash',
    `# OpenDirectory Printers (macOS lpadmin): ${policy.name}`,
    '',
  ];
  for (const p of printers) {
    const uri = p.protocol === 'ipp' || !p.protocol
      ? `ipp://${p.ipAddress}/ipp/print`
      : `socket://${p.ipAddress}:9100`;
    macLpadminLines.push(`lpadmin -x "${p.name}" 2>/dev/null || true`);
    macLpadminLines.push(`lpadmin -p "${p.name}" -v "${uri}" -m everywhere -E -L "${p.location || ''}"`);
    if (p.default) macLpadminLines.push(`lpoptions -d "${p.name}"`);
  }
  macLpadminLines.push('echo "Printers configured!"');

  return {
    windows: [
      { type: 'gpo_printers_xml', filename: 'Printers.xml',
        sysvol_path: 'User/Preferences/Printers/Printers.xml',
        content: printersXml,
        description: `GPO Printer Deployment → SYSVOL ablegen\n${printers.map(p => `  ${p.name} (${p.ipAddress})`).join('\n')}` },
    ],
    linux: [
      { type: 'cups_script', filename: 'deploy-printers-cups.sh', content: cupsLines.join('\n'),
        description: 'CUPS Drucker-Konfiguration — als root ausführen',
        apply_command: 'bash deploy-printers-cups.sh' },
    ],
    macos: [
      { type: 'mobileconfig', filename: `${policy.name.replace(/\s+/g,'-')}-printers.mobileconfig`,
        content: macMobileconfig,
        description: 'macOS Printing Configuration Profile (MDM oder: sudo profiles -I -F <file>)',
        apply_command: `sudo profiles -I -F "${policy.name.replace(/\s+/g,'-')}-printers.mobileconfig"` },
      { type: 'shell_script', filename: 'install-printers-macos.sh', content: macLpadminLines.join('\n'),
        description: 'Alternativ ohne MDM: lpadmin (macOS Fallback)',
        apply_command: 'sudo bash install-printers-macos.sh' },
    ],
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLOUD STORAGE COMPILER
// OneDrive  → Windows: GPO Registry + KFM, macOS: plist config, Linux: onedrive-client
// iCloud    → macOS: mobileconfig restrictions, Windows: registry (iCloud for Windows)
// Google Drive → Windows: registry, macOS: config plist, Linux: rclone
// Generic   → rclone (Linux/macOS), WinFsp (Windows)
// ═══════════════════════════════════════════════════════════════════════════════
function compileCloudStorage(policy) {
  const cloud = (policy.settings || {}).cloudStorage || {};
  const winArtifacts = [];
  const linuxArtifacts = [];
  const macArtifacts = [];

  // ── OneDrive ────────────────────────────────────────────────────────────────
  if (cloud.oneDrive?.enabled) {
    const od = cloud.oneDrive;
    const odRegEntries = [];

    // Tenant ID (auto sign-in)
    if (od.tenantId) {
      odRegEntries.push({ hive:'HKEY_LOCAL_MACHINE', key:'SOFTWARE\\Policies\\Microsoft\\OneDrive', name:'KFMSilentOptIn', type:'REG_SZ', value: od.tenantId });
      odRegEntries.push({ hive:'HKEY_LOCAL_MACHINE', key:'SOFTWARE\\Policies\\Microsoft\\OneDrive', name:'SilentAccountConfig', type:'DWORD', value:'1' });
    }
    // Known Folder Move (Desktop, Documents, Pictures → OneDrive)
    if (od.knownFolderMove) {
      odRegEntries.push({ hive:'HKEY_LOCAL_MACHINE', key:'SOFTWARE\\Policies\\Microsoft\\OneDrive', name:'KFMSilentOptIn', type:'REG_SZ', value: od.tenantId || '<TENANT_ID>' });
      odRegEntries.push({ hive:'HKEY_LOCAL_MACHINE', key:'SOFTWARE\\Policies\\Microsoft\\OneDrive', name:'KFMSilentOptInWithNotification', type:'DWORD', value:'1' });
    }
    // Prevent unlink
    if (od.preventUnlink) {
      odRegEntries.push({ hive:'HKEY_LOCAL_MACHINE', key:'SOFTWARE\\Policies\\Microsoft\\OneDrive', name:'DisablePersonalSync', type:'DWORD', value:'0' });
      odRegEntries.push({ hive:'HKEY_LOCAL_MACHINE', key:'SOFTWARE\\Policies\\Microsoft\\OneDrive', name:'PreventNetworkTrafficPreUserSignIn', type:'DWORD', value:'0' });
    }
    // Files On-Demand
    if (od.filesOnDemand !== false) {
      odRegEntries.push({ hive:'HKEY_LOCAL_MACHINE', key:'SOFTWARE\\Policies\\Microsoft\\OneDrive', name:'FilesOnDemandEnabled', type:'DWORD', value:'1' });
    }

    if (odRegEntries.length) {
      const odXml = `<?xml version="1.0" encoding="UTF-8"?>
<RegistrySettings clsid="{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}">
${odRegEntries.map(e => `  <Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}"
           name="${e.name}" changed="${now()}" uid="{${uuid('od'+e.name)}}">
    <Properties action="U" hive="${e.hive}" key="${e.key}" name="${e.name}" type="${e.type}" value="${e.value}"/>
  </Registry>`).join('\n')}
</RegistrySettings>`;
      winArtifacts.push({
        type: 'gpo_registry_xml', filename: 'OneDrive-Registry.xml',
        sysvol_path: 'Machine/Preferences/Registry/OneDrive-Registry.xml',
        content: odXml,
        description: `OneDrive GPO Konfiguration${od.knownFolderMove ? ' + Known Folder Move (Desktop/Dokumente/Bilder → OneDrive)' : ''}${od.tenantId ? '\nTenant ID: ' + od.tenantId : ''}`,
      });
    }

    // Linux: onedrive client (abraunegg/onedrive)
    const odLinuxScript = [
      '#!/bin/bash',
      `# OpenDirectory — OneDrive Client (Linux): ${policy.name}`,
      '# Basiert auf: https://github.com/abraunegg/onedrive',
      '',
      '# 1. Installieren',
      'if command -v apt-get &>/dev/null; then',
      '  apt-get install -y onedrive 2>/dev/null || {',
      '    # PPA für aktuelle Version',
      '    apt-get install -y software-properties-common',
      '    add-apt-repository -y ppa:yann1ck/onedrive',
      '    apt-get update && apt-get install -y onedrive',
      '  }',
      'elif command -v dnf &>/dev/null; then',
      '  dnf install -y onedrive',
      'fi',
      '',
      '# 2. Pro Benutzer: onedrive --configure (interaktiv, einmalig)',
      '# oder silent mit bereits gespeichertem Token:',
      '# mkdir -p ~/.config/onedrive',
      '# cp onedrive-token ~/.config/onedrive/refresh_token',
      '',
      '# 3. Konfiguration',
      'mkdir -p ~/.config/onedrive',
      'cat > ~/.config/onedrive/config << EOF',
      '# OpenDirectory OneDrive Config',
      'sync_dir = "~/OneDrive"',
      'skip_dotfiles = "true"',
      od.skipFiles ? `skip_file = "${od.skipFiles}"` : '# skip_file = "*.tmp"',
      'monitor_interval = "300"',
      'EOF',
      '',
      '# 4. Als systemd User-Service einrichten',
      'systemctl --user enable onedrive',
      'systemctl --user start onedrive',
      '',
      'echo "OneDrive Client konfiguriert — starte onedrive --synchronize für ersten Sync"',
    ];

    linuxArtifacts.push({
      type: 'shell_script', filename: 'setup-onedrive-linux.sh',
      content: odLinuxScript.join('\n'),
      description: 'OneDrive Client für Linux (abraunegg/onedrive)',
      apply_command: 'bash setup-onedrive-linux.sh',
    });

    // macOS: OneDrive plist configuration
    const odMacPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<!-- OneDrive macOS managed configuration -->
\t<key>PayloadDisplayName</key>
\t<string>OneDrive Configuration</string>
\t<key>PayloadIdentifier</key>
\t<string>local.opendirectory.${policy.id}.onedrive</string>
\t<key>PayloadUUID</key>
\t<string>${uuid(policy.id + 'onedrive-mac')}</string>
\t<key>PayloadVersion</key>
\t<integer>1</integer>
\t<key>PayloadType</key>
\t<string>Configuration</string>
\t<key>PayloadContent</key>
\t<array>
\t\t<dict>
\t\t\t<key>PayloadType</key>
\t\t\t<string>com.microsoft.OneDrive</string>
\t\t\t<key>PayloadIdentifier</key>
\t\t\t<string>local.opendirectory.${policy.id}.onedrive.app</string>
\t\t\t<key>PayloadUUID</key>
\t\t\t<string>${uuid(policy.id + 'onedrive-app')}</string>
\t\t\t<key>PayloadVersion</key>
\t\t\t<integer>1</integer>
${od.tenantId ? `\t\t\t<key>DefaultToBusinessFRE</key>\n\t\t\t<integer>1</integer>\n\t\t\t<key>DisablePersonalSync</key>\n\t\t\t<integer>0</integer>` : ''}
${od.filesOnDemand !== false ? `\t\t\t<key>FilesOnDemandEnabled</key>\n\t\t\t<integer>1</integer>` : ''}
${od.knownFolderMove ? `\t\t\t<key>KFMSilentOptIn</key>\n\t\t\t<string>${od.tenantId || '<TENANT_ID>'}</string>` : ''}
\t\t</dict>
\t</array>
</dict>
</plist>`;

    macArtifacts.push({
      type: 'mobileconfig', filename: 'OneDrive.mobileconfig',
      content: odMacPlist,
      description: `OneDrive macOS Configuration Profile${od.knownFolderMove ? ' + Dokumente-Sync' : ''}`,
      apply_command: 'sudo profiles -I -F OneDrive.mobileconfig',
    });
  }

  // ── iCloud ──────────────────────────────────────────────────────────────────
  if (cloud.iCloud?.enabled !== undefined) {
    const ic = cloud.iCloud;
    // macOS: iCloud managed via com.apple.applicationaccess restrictions
    const iCloudPayloads = [];
    if (ic.enabled === false) {
      // Disable iCloud Drive
      iCloudPayloads.push(`\t\t\t<key>allowCloudDocumentSync</key>\n\t\t\t<false/>`);
      iCloudPayloads.push(`\t\t\t<key>allowCloudKeychainSync</key>\n\t\t\t<false/>`);
    } else {
      iCloudPayloads.push(`\t\t\t<key>allowCloudDocumentSync</key>\n\t\t\t<true/>`);
      if (ic.keychain !== false) iCloudPayloads.push(`\t\t\t<key>allowCloudKeychainSync</key>\n\t\t\t<true/>`);
    }

    const iCloudProfile = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>PayloadDisplayName</key>
\t<string>iCloud Policy</string>
\t<key>PayloadIdentifier</key>
\t<string>local.opendirectory.${policy.id}.icloud</string>
\t<key>PayloadUUID</key>
\t<string>${uuid(policy.id + 'icloud')}</string>
\t<key>PayloadVersion</key>
\t<integer>1</integer>
\t<key>PayloadType</key>
\t<string>Configuration</string>
\t<key>PayloadContent</key>
\t<array>
\t\t<dict>
\t\t\t<key>PayloadType</key>
\t\t\t<string>com.apple.applicationaccess</string>
\t\t\t<key>PayloadIdentifier</key>
\t\t\t<string>local.opendirectory.${policy.id}.icloud.access</string>
\t\t\t<key>PayloadUUID</key>
\t\t\t<string>${uuid(policy.id + 'icloud-access')}</string>
\t\t\t<key>PayloadVersion</key>
\t\t\t<integer>1</integer>
${iCloudPayloads.join('\n')}
\t\t</dict>
\t</array>
</dict>
</plist>`;

    macArtifacts.push({
      type: 'mobileconfig', filename: 'iCloud-Policy.mobileconfig',
      content: iCloudProfile,
      description: `iCloud ${ic.enabled === false ? 'Deaktivieren' : 'Aktivieren'} via mobileconfig (macOS only)`,
      apply_command: 'sudo profiles -I -F iCloud-Policy.mobileconfig',
    });

    // Windows: iCloud for Windows registry policy
    if (ic.enabled === false) {
      winArtifacts.push({
        type: 'gpo_registry_xml', filename: 'iCloud-Disable-Registry.xml',
        content: `<?xml version="1.0" encoding="UTF-8"?>
<RegistrySettings clsid="{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}">
  <Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}"
    name="DisableiCloudDrive" changed="${now()}" uid="{${uuid('icloud-disable')}}">
    <Properties action="U" hive="HKEY_LOCAL_MACHINE"
      key="SOFTWARE\\Policies\\Apple\\iCloud"
      name="DisableiCloudDrive" type="DWORD" value="1"/>
  </Registry>
</RegistrySettings>`,
        description: 'iCloud für Windows deaktivieren (GPO Registry)',
      });
    }
  }

  // ── Google Drive ────────────────────────────────────────────────────────────
  if (cloud.googleDrive?.enabled) {
    const gd = cloud.googleDrive;

    // Windows: Google Drive for Desktop silent install + policy
    winArtifacts.push({
      type: 'powershell_script', filename: 'Install-GoogleDrive.ps1',
      content: [
        '# OpenDirectory — Google Drive for Desktop',
        '# Silent install + policy',
        '',
        '# Download und install',
        '$installer = "$env:TEMP\\GoogleDriveSetup.exe"',
        'Invoke-WebRequest -Uri "https://dl.google.com/drive-file-stream/GoogleDriveSetup.exe" -OutFile $installer',
        'Start-Process -FilePath $installer -ArgumentList "--silent --desktop_shortcut" -Wait',
        '',
        '# Policy: Stream-only (Files on Demand)',
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Google\\DriveFS" -Name "DefaultWebBasedDrive" -Value 1 -Force',
      ].join('\n'),
      description: 'Google Drive for Desktop — Silent Install + Policy',
    });

    // Linux: rclone for Google Drive
    linuxArtifacts.push({
      type: 'shell_script', filename: 'setup-gdrive-linux.sh',
      content: [
        '#!/bin/bash',
        '# OpenDirectory — Google Drive via rclone (Linux)',
        '',
        '# Install rclone',
        'curl https://rclone.org/install.sh | sudo bash',
        '',
        '# Configure (interactive, einmalig pro Benutzer)',
        '# rclone config → "gdrive" → Google Drive → follow OAuth',
        '',
        '# Mount als Systemd-User-Service',
        'mkdir -p ~/GoogleDrive',
        'cat > ~/.config/systemd/user/rclone-gdrive.service << EOF',
        '[Unit]',
        'Description=Google Drive (rclone)',
        'After=network-online.target',
        '',
        '[Service]',
        'Type=notify',
        'ExecStart=rclone mount gdrive: %h/GoogleDrive --vfs-cache-mode writes --allow-other',
        'ExecStop=/bin/fusermount -u %h/GoogleDrive',
        'Restart=on-failure',
        '',
        '[Install]',
        'WantedBy=default.target',
        'EOF',
        '',
        'systemctl --user daemon-reload',
        'systemctl --user enable rclone-gdrive',
        'systemctl --user start rclone-gdrive',
        'echo "Google Drive gemountet unter ~/GoogleDrive"',
      ].join('\n'),
      description: 'Google Drive via rclone (Linux) — FUSE Mount',
    });

    macArtifacts.push({
      type: 'shell_script', filename: 'setup-gdrive-macos.sh',
      content: [
        '#!/bin/bash',
        '# OpenDirectory — Google Drive (macOS)',
        '',
        '# Via Homebrew',
        'brew install --cask google-drive 2>/dev/null || true',
        '',
        '# Oder: rclone (ohne GUI)',
        '# brew install rclone',
        '# rclone config → gdrive',
        '# rclone mount gdrive: ~/GoogleDrive --vfs-cache-mode writes &',
        '',
        'echo "Google Drive for Desktop — bitte manuell anmelden"',
      ].join('\n'),
      description: 'Google Drive für macOS (Homebrew oder rclone)',
    });
  }

  // ── rclone (Generic: S3, Dropbox, etc.) ────────────────────────────────────
  if (cloud.rclone?.enabled && cloud.rclone.remotes?.length) {
    const remotes = cloud.rclone.remotes;
    const rcloneConf = remotes.map(r => `[${r.name}]\ntype = ${r.type}\n${Object.entries(r.config || {}).map(([k,v]) => `${k} = ${v}`).join('\n')}`).join('\n\n');
    const rcloneScript = [
      '#!/bin/bash',
      `# OpenDirectory — rclone Multi-Remote Setup: ${policy.name}`,
      '',
      'curl https://rclone.org/install.sh | sudo bash',
      '',
      'mkdir -p ~/.config/rclone',
      'cat >> ~/.config/rclone/rclone.conf << EOF',
      rcloneConf,
      'EOF',
      '',
      ...remotes.map(r => [
        `mkdir -p ~/${r.name}`,
        `cat > ~/.config/systemd/user/rclone-${r.name}.service << EOF`,
        `[Unit]\nDescription=rclone ${r.name}\nAfter=network-online.target`,
        `[Service]\nType=notify\nExecStart=rclone mount ${r.name}: ~/${r.name} --vfs-cache-mode writes\nExecStop=/bin/fusermount -u ~/${r.name}\nRestart=on-failure`,
        `[Install]\nWantedBy=default.target\nEOF`,
        `systemctl --user enable rclone-${r.name} --now`,
      ].join('\n')),
      'echo "rclone remotes configured!"',
    ];

    linuxArtifacts.push({
      type: 'shell_script', filename: 'setup-rclone.sh',
      content: rcloneScript.join('\n'),
      description: `rclone Cloud-Storage: ${remotes.map(r => r.name).join(', ')}`,
    });
  }

  return { windows: winArtifacts, linux: linuxArtifacts, macos: macArtifacts };
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXTEND MAIN COMPILERS with drives/printers/cloud
// ═══════════════════════════════════════════════════════════════════════════════
const _origCompile = compile;

function compileExtended(policy) {
  const base = _origCompile(policy);

  // Network drives
  const drives = compileNetworkDrives(policy);
  const printerArts = compilePrinters(policy);
  const cloudArts = compileCloudStorage(policy);

  for (const platform of ['windows', 'linux', 'macos']) {
    if (!base.artifacts[platform]) base.artifacts[platform] = [];
    base.artifacts[platform].push(...(drives[platform] || []));
    base.artifacts[platform].push(...(printerArts[platform] || []));
    base.artifacts[platform].push(...(cloudArts[platform] || []));
  }

  return base;
}

module.exports = {
  compile: compileExtended,
  compileWindows,
  compileLinux,
  compileMacOS,
  compileNetworkDrives,
  compilePrinters,
  compileCloudStorage,
};
