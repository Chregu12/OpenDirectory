const { uuid, now } = require('./helpers');
const crypto = require('crypto');

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

module.exports = { compileLinux };
