'use client';

export default function EnrollPage() {
  const dns1 = `sudo sh -c 'mkdir -p /etc/resolver && echo "nameserver 192.168.1.1" > /etc/resolver/heusser.local'`;
  const dns2 = `sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder`;
  const certCmd = `curl -sk https://192.168.1.245/heusser-ca.crt -H 'Host: opendirectory.heusser.local' -o /tmp/heusser-ca.crt && sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/heusser-ca.crt`;

  // macOS printer setup — direkter AirPrint-Proxy via opendirectory.heusser.local:631
  // Port 631 leitet direkt zum HP-Drucker weiter → macOS erkennt AirPrint automatisch
  const printerAddCmd = `sudo lpadmin -p "HP-OfficeJet-Pro-9010" -E -v "ipp://opendirectory.heusser.local:631/ipp/print" -m everywhere -D "HP OfficeJet Pro 9010" -L "Homelab"`;
  const printerDefaultCmd = `lpoptions -d HP-OfficeJet-Pro-9010`;
  const printerTestCmd = `lp -d HP-OfficeJet-Pro-9010 /System/Library/ColorSync/Profiles/sRGB\\ Profile.icc`;

  return (
    <div style={{ fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif', maxWidth: 720, margin: '40px auto', padding: '0 24px', color: '#1d1d1f' }}>

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
        <div style={{ width: 40, height: 40, background: '#0071e3', borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <svg width="22" height="22" fill="white" viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
        </div>
        <div>
          <h1 style={{ margin: 0, fontSize: 26, fontWeight: 700 }}>OpenDirectory Enrollment</h1>
          <p style={{ margin: 0, fontSize: 14, color: '#6e6e73' }}>Mac-Gerät für heusser.local konfigurieren</p>
        </div>
      </div>

      <div style={{ background: '#fff4e5', border: '1px solid #ffcc80', borderRadius: 12, padding: '14px 18px', marginTop: 24, marginBottom: 24, fontSize: 14 }}>
        <strong>Warum ist das nötig?</strong><br />
        macOS behandelt <code>.local</code>-Domains über mDNS (Bonjour) statt über deinen DNS-Server —
        deshalb kann dein Mac <code>*.heusser.local</code> nicht auflösen. Ausserdem kennt macOS deine
        private Homelab-CA noch nicht, weshalb HTTPS-Verbindungen als unsicher markiert werden.
        Diese zwei Schritte beheben beides.
      </div>

      {/* Step 1 */}
      <Step number={1} title="DNS-Auflösung für heusser.local aktivieren"
        description="Dieser Befehl erstellt eine Resolver-Datei, die macOS anweist, alle *.heusser.local-Anfragen an deinen Router-DNS (192.168.1.1) zu senden statt über mDNS."
        commands={[dns1, dns2]}
        note="Einmalig pro Mac • braucht sudo • sofort wirksam"
      />

      {/* Step 2 — mobileconfig (preferred) */}
      <Step number={2} title="Homelab-CA vertrauen (Methode A — Profil, empfohlen)"
        description='Lade das Konfigurationsprofil herunter und doppelklicke darauf. macOS öffnet die Systemeinstellungen → Profile → Installieren. Danach ist deine Homelab-CA vertrauenswürdig und alle *.heusser.local-Websites zeigen kein Schloss-Warning mehr.'
        downloadLink="/heusser-homelab.mobileconfig"
        downloadLabel="Konfigurationsprofil laden (.mobileconfig)"
        note="Empfohlen · gilt für Safari, Chrome, curl, alle Apps"
      />

      {/* Step 2 alt — terminal */}
      <Step number="2b" title="Homelab-CA vertrauen (Methode B — Terminal)"
        description="Wenn du das Profil nicht installieren möchtest, kannst du die CA auch direkt per Terminal vertrauen:"
        commands={[certCmd]}
        note="Alternativ zu Methode A"
      />

      {/* Step 3 */}
      <div style={{ background: '#f5f5f7', borderRadius: 12, padding: '20px 24px', marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
          <div style={{ minWidth: 32, height: 32, background: '#34c759', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white', fontWeight: 700, fontSize: 15 }}>✓</div>
          <div>
            <h2 style={{ margin: '0 0 6px', fontSize: 17, fontWeight: 600 }}>Fertig — OpenDirectory öffnen</h2>
            <p style={{ margin: '0 0 14px', fontSize: 14, color: '#3a3a3c' }}>
              Nach Schritt 1 und 2 kannst du das OpenDirectory-Dashboard im Browser öffnen:
            </p>
            <a href="https://opendirectory.heusser.local"
              style={{ display: 'inline-block', background: '#0071e3', color: 'white', borderRadius: 8,
                padding: '10px 20px', textDecoration: 'none', fontWeight: 600, fontSize: 15 }}>
              https://opendirectory.heusser.local →
            </a>
          </div>
        </div>
      </div>

      {/* Step 4 — Printer setup */}
      <div style={{ marginTop: 32, marginBottom: 8 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, margin: '0 0 4px' }}>Optionale Einrichtung</h2>
        <p style={{ fontSize: 14, color: '#6e6e73', margin: 0 }}>Drucker und Scanner zum Mac hinzufügen</p>
      </div>

      {/* Step A — macOS UI (primary) */}
      <div style={{ background: '#f5f5f7', borderRadius: 12, padding: '20px 24px', marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
          <div style={{ minWidth: 32, height: 32, background: '#0071e3', borderRadius: '50%',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'white', fontWeight: 700, fontSize: 15, flexShrink: 0 }}>A</div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <h2 style={{ margin: '0 0 6px', fontSize: 17, fontWeight: 600 }}>HP OfficeJet Pro 9010 hinzufügen — macOS Systemeinstellungen</h2>
            <p style={{ margin: '0 0 12px', fontSize: 14, color: '#3a3a3c', lineHeight: 1.5 }}>
              Öffne <strong>Systemeinstellungen → Drucker &amp; Scanner</strong>, klicke auf <strong>+</strong> und wähle den Tab <strong>IP</strong>:
            </p>
            <table style={{ borderCollapse: 'collapse', width: '100%', marginBottom: 12 }}>
              <tbody>
                {[
                  ['Adresse', 'opendirectory.heusser.local'],
                  ['Protokoll', 'IPP (Internet Printing Protocol)'],
                  ['Warteschlange', '/ipp/print'],
                  ['Name', 'HP OfficeJet Pro 9010'],
                ].map(([label, val]) => (
                  <tr key={label} style={{ borderBottom: '1px solid #e5e5e5' }}>
                    <td style={{ padding: '6px 12px 6px 0', color: '#6e6e73', fontSize: 13, whiteSpace: 'nowrap', width: 130 }}>{label}</td>
                    <td style={{ padding: '6px 0' }}>
                      <code style={{ background: '#1c1c1e', color: '#30d158', padding: '2px 8px', borderRadius: 4, fontSize: 12 }}>{val}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p style={{ margin: '0 0 6px', fontSize: 13, color: '#3a3a3c' }}>
              macOS erkennt den Drucker als <strong>AirPrint</strong>-Drucker und wählt automatisch den richtigen Treiber aus.
            </p>
            <p style={{ margin: '8px 0 0', fontSize: 12, color: '#6e6e73' }}>Kein Terminal nötig · AirPrint-Treiber automatisch · SSL optional</p>
          </div>
        </div>
      </div>

      {/* Step A-alt — terminal fallback */}
      <Step number="A₂" title="HP OfficeJet Pro 9010 hinzufügen (Terminal-Variante)"
        description="Alternativ zur macOS-UI kannst du den Drucker auch per Terminal hinzufügen:"
        commands={[printerAddCmd]}
        note="Braucht sudo · einmalig"
      />

      <div style={{ background: '#f0f9ff', border: '1px solid #bae6fd', borderRadius: 12, padding: '14px 18px', marginBottom: 16, fontSize: 14 }}>
        <strong>Nach dem Hinzufügen — Optionale Befehle:</strong>
        <table style={{ marginTop: 10, borderCollapse: 'collapse', width: '100%' }}>
          <tbody>
            <tr>
              <td style={{ padding: '4px 12px 4px 0', color: '#6e6e73', whiteSpace: 'nowrap', verticalAlign: 'top' }}>Als Standard setzen</td>
              <td><code style={{ background: '#1c1c1e', color: '#30d158', padding: '2px 8px', borderRadius: 4, fontSize: 12 }}>{printerDefaultCmd}</code></td>
            </tr>
            <tr>
              <td style={{ padding: '4px 12px 4px 0', color: '#6e6e73', whiteSpace: 'nowrap', verticalAlign: 'top' }}>Testseite drucken</td>
              <td><code style={{ background: '#1c1c1e', color: '#30d158', padding: '2px 8px', borderRadius: 4, fontSize: 12 }}>{printerTestCmd}</code></td>
            </tr>
          </tbody>
        </table>
      </div>

      <Step number="B" title="Scanner (HP OfficeJet Pro 9010) nutzen"
        description="Der Scanner des HP OfficeJet Pro 9010 ist nach dem Hinzufügen des Druckers automatisch in Image Capture und dem OpenDirectory-Dashboard verfügbar. Alternativ kannst du direkt über das Dashboard (Printers & Scanners → Scanners-Tab) scannen."
        note="Kein zusätzlicher Treiber nötig · AirScan-kompatibel"
      />

      {/* Downloads */}
      <div style={{ borderTop: '1px solid #d2d2d7', paddingTop: 20, marginTop: 8 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: '#6e6e73', textTransform: 'uppercase', letterSpacing: '0.05em', margin: '0 0 12px' }}>Direktdownloads</h3>
        <div style={{ display: 'flex', gap: 10 }}>
          {[
            { href: '/heusser-homelab.mobileconfig', label: 'Konfigurationsprofil', desc: '.mobileconfig' },
            { href: '/heusser-ca.crt', label: 'CA-Zertifikat', desc: '.crt (PEM)' },
          ].map(d => (
            <a key={d.href} href={d.href}
              style={{ flex: 1, display: 'block', border: '1px solid #d2d2d7', borderRadius: 10,
                padding: '12px 16px', textDecoration: 'none', color: '#1d1d1f' }}>
              <div style={{ fontWeight: 600, fontSize: 14, color: '#0071e3' }}>⬇ {d.label}</div>
              <div style={{ fontSize: 12, color: '#6e6e73', marginTop: 2 }}>{d.desc}</div>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}

function Step({ number, title, description, commands, downloadLink, downloadLabel, note }: {
  number: number | string;
  title: string;
  description: string;
  commands?: string[];
  downloadLink?: string;
  downloadLabel?: string;
  note?: string;
}) {
  return (
    <div style={{ background: '#f5f5f7', borderRadius: 12, padding: '20px 24px', marginBottom: 16 }}>
      <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
        <div style={{ minWidth: 32, height: 32, background: '#0071e3', borderRadius: '50%',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: 'white', fontWeight: 700, fontSize: 15, flexShrink: 0 }}>
          {number}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <h2 style={{ margin: '0 0 6px', fontSize: 17, fontWeight: 600 }}>{title}</h2>
          <p style={{ margin: '0 0 12px', fontSize: 14, color: '#3a3a3c', lineHeight: 1.5 }}>{description}</p>
          {commands && commands.map((cmd, i) => (
            <pre key={i} style={{
              background: '#1c1c1e', color: '#30d158', borderRadius: 8,
              padding: '12px 16px', fontSize: 12, overflowX: 'auto',
              margin: '0 0 8px', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
              fontFamily: '"SF Mono", Monaco, "Cascadia Code", monospace',
            }}>{cmd}</pre>
          ))}
          {downloadLink && (
            <a href={downloadLink}
              style={{ display: 'inline-block', background: '#0071e3', color: 'white',
                borderRadius: 8, padding: '10px 20px', textDecoration: 'none',
                fontWeight: 600, fontSize: 14, marginBottom: 8 }}>
              ⬇ {downloadLabel}
            </a>
          )}
          {note && <p style={{ margin: '8px 0 0', fontSize: 12, color: '#6e6e73' }}>{note}</p>}
        </div>
      </div>
    </div>
  );
}
