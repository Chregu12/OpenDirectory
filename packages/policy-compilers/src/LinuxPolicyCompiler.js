const { uuid, now } = require('./helpers');
const crypto = require('crypto');
const { logInfo } = require('./logger');

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

// =============================================================================
// LinuxPolicyCompiler (class) → RSoP → Linux-native configuration payload
// -----------------------------------------------------------------------------
// Companion to compileLinux() above: that function turns an authored
// policy.settings tree into deployable sysctl/sshd/PAM/sudoers/systemd
// artifacts. This class instead consumes the merged, flattened output of
// RSOPEngine.calculateRSOP() and returns a structured summary (sysctl
// params, PAM policy, systemd service state, firewall rules, SSH config,
// update policy, user policy), for inspection/API use (policy-service's
// RSoP/compile endpoints) rather than file deployment.
// =============================================================================
class LinuxPolicyCompiler {
  /**
   * Compile the full RSoP result into a Linux-native payload.
   *
   * @param {object} rsopResult - Output from RSOPEngine.calculateRSOP()
   * @returns {object} Linux-formatted policy payload
   */
  compile(rsopResult) {
    const { settings, sources, appliedPolicies } = rsopResult;

    logInfo('Compiling RSoP for Linux', {
      settingCount: Object.keys(settings).length,
      policyCount: appliedPolicies.length
    });

    return {
      platform: 'linux',
      compiledAt: new Date().toISOString(),
      sysctl: this.compileSysctl(settings),
      pam: this.compilePAM(settings),
      systemd: this.compileSystemd(settings),
      firewall: this.compileFirewall(settings),
      encryption: this.compileEncryption(settings),
      ssh: this.compileSSH(settings),
      updates: this.compileUpdates(settings),
      users: this.compileUserPolicy(settings),
      sources
    };
  }

  /**
   * Compile sysctl kernel parameters.
   */
  compileSysctl(settings) {
    const params = {};

    // Network hardening
    if (settings['network.ipForwarding'] !== undefined) {
      params['net.ipv4.ip_forward'] = settings['network.ipForwarding'] ? 1 : 0;
    }
    if (settings['network.icmpRedirects'] !== undefined) {
      params['net.ipv4.conf.all.accept_redirects'] = settings['network.icmpRedirects'] ? 1 : 0;
      params['net.ipv6.conf.all.accept_redirects'] = settings['network.icmpRedirects'] ? 1 : 0;
    }
    if (settings['network.sourceRouting'] !== undefined) {
      params['net.ipv4.conf.all.accept_source_route'] = settings['network.sourceRouting'] ? 1 : 0;
    }
    if (settings['network.synCookies'] !== undefined) {
      params['net.ipv4.tcp_syncookies'] = settings['network.synCookies'] ? 1 : 0;
    }
    if (settings['network.rpFilter'] !== undefined) {
      params['net.ipv4.conf.all.rp_filter'] = settings['network.rpFilter'] ? 1 : 0;
    }

    // Kernel hardening
    if (settings['kernel.sysrq'] !== undefined) {
      params['kernel.sysrq'] = Number(settings['kernel.sysrq']);
    }
    if (settings['kernel.coreDumps'] !== undefined) {
      params['fs.suid_dumpable'] = settings['kernel.coreDumps'] ? 1 : 0;
    }
    if (settings['kernel.aslr'] !== undefined) {
      params['kernel.randomize_va_space'] = settings['kernel.aslr'] ? 2 : 0;
    }
    if (settings['kernel.dmesgRestrict'] !== undefined) {
      params['kernel.dmesg_restrict'] = settings['kernel.dmesgRestrict'] ? 1 : 0;
    }
    if (settings['kernel.kptrRestrict'] !== undefined) {
      params['kernel.kptr_restrict'] = settings['kernel.kptrRestrict'] ? 2 : 0;
    }

    // Pass-through sysctl settings
    for (const [key, value] of Object.entries(settings)) {
      if (key.startsWith('sysctl.')) {
        const param = key.replace('sysctl.', '').replace(/\./g, '.');
        params[param] = value;
      }
    }

    return params;
  }

  /**
   * Compile PAM (Pluggable Authentication Modules) password policy.
   */
  compilePAM(settings) {
    return {
      passwordQuality: {
        minlen: settings['password.minLength'] || 12,
        dcredit: settings['password.requireDigit'] !== false ? -1 : 0,
        ucredit: settings['password.requireUppercase'] !== false ? -1 : 0,
        lcredit: settings['password.requireLowercase'] !== false ? -1 : 0,
        ocredit: settings['password.requireSymbol'] !== false ? -1 : 0,
        minclass: settings['password.minClasses'] || 3,
        maxrepeat: settings['password.maxRepeat'] || 3,
        maxclassrepeat: settings['password.maxClassRepeat'] || 4,
        dictcheck: settings['password.dictionaryCheck'] !== false ? 1 : 0,
        enforcing: settings['password.complexity'] !== false ? 1 : 0
      },
      passwordHistory: {
        remember: settings['password.history'] || 24
      },
      accountLockout: {
        deny: settings['lockout.threshold'] || 5,
        unlockTime: (settings['lockout.duration'] || 30) * 60,
        failInterval: (settings['lockout.window'] || 30) * 60,
        evenDenyRoot: settings['lockout.lockRoot'] || false
      },
      passwordAging: {
        maxDays: settings['password.maxAge'] || 90,
        minDays: settings['password.minAge'] || 1,
        warnDays: settings['password.warnAge'] || 14
      },
      sessionLimits: {
        maxLogins: settings['session.maxLogins'] || 10,
        maxSystemLogins: settings['session.maxSystemLogins'] || 64
      }
    };
  }

  /**
   * Compile systemd service configurations.
   */
  compileSystemd(settings) {
    const services = {};

    // SSH daemon
    if (settings['ssh.enabled'] !== undefined) {
      services['sshd'] = {
        enabled: settings['ssh.enabled'],
        state: settings['ssh.enabled'] ? 'started' : 'stopped'
      };
    }

    // Firewall
    if (settings['firewall.enabled'] !== undefined) {
      services['firewalld'] = {
        enabled: settings['firewall.enabled'],
        state: settings['firewall.enabled'] ? 'started' : 'stopped'
      };
    }

    // Automatic updates
    if (settings['updates.autoInstall'] !== undefined) {
      services['unattended-upgrades'] = {
        enabled: settings['updates.autoInstall'],
        state: settings['updates.autoInstall'] ? 'started' : 'stopped'
      };
    }

    // Audit daemon
    if (settings['audit.enabled'] !== undefined) {
      services['auditd'] = {
        enabled: settings['audit.enabled'],
        state: settings['audit.enabled'] ? 'started' : 'stopped'
      };
    }

    // Pass-through service settings
    for (const [key, value] of Object.entries(settings)) {
      if (key.startsWith('systemd.')) {
        const parts = key.replace('systemd.', '').split('.');
        const svc = parts[0];
        const prop = parts.slice(1).join('.');
        if (!services[svc]) services[svc] = {};
        services[svc][prop] = value;
      }
    }

    return services;
  }

  /**
   * Compile iptables/nftables firewall rules.
   */
  compileFirewall(settings) {
    const config = {
      enabled: settings['firewall.enabled'] !== undefined ? settings['firewall.enabled'] : true,
      backend: settings['firewall.backend'] || 'nftables',
      defaultInputPolicy: settings['firewall.defaultInbound'] || 'drop',
      defaultOutputPolicy: settings['firewall.defaultOutbound'] || 'accept',
      defaultForwardPolicy: settings['firewall.defaultForward'] || 'drop',
      rules: []
    };

    // Always allow loopback and established connections
    config.rules.push(
      { chain: 'input', rule: '-i lo -j ACCEPT', comment: 'Allow loopback' },
      { chain: 'input', rule: '-m state --state ESTABLISHED,RELATED -j ACCEPT', comment: 'Allow established' }
    );

    // SSH
    if (settings['ssh.enabled'] !== false) {
      const sshPort = settings['ssh.port'] || 22;
      config.rules.push({
        chain: 'input',
        rule: `-p tcp --dport ${sshPort} -j ACCEPT`,
        comment: `Allow SSH on port ${sshPort}`
      });
    }

    // Custom firewall rules
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
      const chain = rule.direction === 'outbound' ? 'output' : 'input';
      const action = rule.action === 'block' ? 'DROP' : 'ACCEPT';
      let iptRule = '';

      if (rule.protocol) iptRule += `-p ${rule.protocol} `;
      if (rule.localPort) iptRule += `--dport ${rule.localPort} `;
      if (rule.remoteAddress) iptRule += `-s ${rule.remoteAddress} `;
      iptRule += `-j ${action}`;

      config.rules.push({
        chain,
        rule: iptRule.trim(),
        comment: rule.name || id
      });
    }

    return config;
  }

  /**
   * Compile LUKS/dm-crypt encryption settings.
   */
  compileEncryption(settings) {
    return {
      luks: {
        required: settings['encryption.required'] !== false,
        algorithm: settings['encryption.algorithm'] || 'AES-256',
        cipher: settings['encryption.cipher'] || 'aes-xts-plain64',
        keySize: settings['encryption.keySize'] || 512,
        hash: settings['encryption.hash'] || 'sha256',
        iterTime: settings['encryption.iterTime'] || 5000,
        escrowServer: settings['encryption.escrowServer'] || null
      }
    };
  }

  /**
   * Compile SSH daemon (sshd_config) settings.
   */
  compileSSH(settings) {
    return {
      port: settings['ssh.port'] || 22,
      permitRootLogin: settings['ssh.permitRootLogin'] || 'no',
      passwordAuthentication: settings['ssh.passwordAuth'] !== undefined
        ? (settings['ssh.passwordAuth'] ? 'yes' : 'no')
        : 'no',
      pubkeyAuthentication: 'yes',
      maxAuthTries: settings['ssh.maxAuthTries'] || 3,
      loginGraceTime: settings['ssh.loginGraceTime'] || 60,
      clientAliveInterval: settings['ssh.clientAliveInterval'] || 300,
      clientAliveCountMax: settings['ssh.clientAliveCountMax'] || 3,
      allowTcpForwarding: settings['ssh.allowTcpForwarding'] !== undefined
        ? (settings['ssh.allowTcpForwarding'] ? 'yes' : 'no')
        : 'no',
      x11Forwarding: settings['ssh.x11Forwarding'] !== undefined
        ? (settings['ssh.x11Forwarding'] ? 'yes' : 'no')
        : 'no',
      protocol: 2,
      useDNS: 'no',
      banner: settings['ssh.banner'] || '/etc/issue.net',
      allowUsers: settings['ssh.allowUsers'] || null,
      allowGroups: settings['ssh.allowGroups'] || null
    };
  }

  /**
   * Compile automatic update settings (unattended-upgrades / dnf-automatic).
   */
  compileUpdates(settings) {
    return {
      autoInstall: settings['updates.autoInstall'] !== false,
      securityOnly: settings['updates.securityOnly'] || false,
      autoReboot: settings['updates.autoReboot'] || false,
      rebootTime: settings['updates.rebootTime'] || '03:00',
      maxDeferDays: settings['updates.maxDeferDays'] || 7,
      blacklist: settings['updates.blacklist'] || [],
      mailReport: settings['updates.mailReport'] || null,
      removeUnused: settings['updates.removeUnused'] !== false
    };
  }

  /**
   * Compile user/group policy settings.
   */
  compileUserPolicy(settings) {
    return {
      umask: settings['users.umask'] || '027',
      shellTimeout: settings['users.shellTimeout'] || 900,
      loginDefs: {
        passMaxDays: settings['password.maxAge'] || 90,
        passMinDays: settings['password.minAge'] || 1,
        passWarnAge: settings['password.warnAge'] || 14,
        passMinLen: settings['password.minLength'] || 12,
        loginRetries: settings['lockout.threshold'] || 5,
        loginTimeout: settings['lockout.loginTimeout'] || 60
      },
      secureTTY: settings['users.secureTTY'] || ['tty1'],
      suRestrict: settings['users.suRestrictGroup'] || 'wheel'
    };
  }
}

module.exports = { compileLinux, LinuxPolicyCompiler };
