const { uuid, now } = require('./helpers');

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

module.exports = { compileNetworkDrives };
