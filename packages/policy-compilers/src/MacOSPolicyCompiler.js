const { uuid, now } = require('./helpers');

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

module.exports = { compileMacOS };
