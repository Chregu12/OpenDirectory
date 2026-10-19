const { uuid, now } = require('./helpers');

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

module.exports = { compilePrinters };
