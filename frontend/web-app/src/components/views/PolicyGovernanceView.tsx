'use client';

import React, { useEffect, useRef, useState } from 'react';
import { CanonicalPolicy, PolicyAccess, PolicyDraft, policyGovernance } from '@/lib/policyGovernance';
import PolicyPublicationPanel from './PolicyPublicationPanel';
type Confirmation = { kind: 'create'; draft: PolicyDraft } | { kind: 'activate' | 'deactivate'; policy: CanonicalPolicy; publicationId?: string };

export default function PolicyGovernanceView() {
  const [access, setAccess] = useState<PolicyAccess | null>(null); const [rows, setRows] = useState<CanonicalPolicy[] | null>(null);
  const [total, setTotal] = useState(0); const [attempt, setAttempt] = useState(0); const [busy, setBusy] = useState(false);
  const [error, setError] = useState(''); const [message, setMessage] = useState(''); const [name, setName] = useState('');
  const [settings, setSettings] = useState('{}'); const [confirmation, setConfirmation] = useState<Confirmation | null>(null); const [ack, setAck] = useState(false);
  const [reason, setReason] = useState(''); const [policyType, setPolicyType] = useState('security');
  const [publications, setPublications] = useState<Record<string, string>>({});
  const epoch = useRef(0);
  const invalidate = () => { epoch.current++; setAccess(null); setRows(null); setPublications({}); setConfirmation(null); setAck(false); setReason(''); setName(''); setPolicyType('security'); setSettings('{}'); setBusy(false); };
  const reload = () => { invalidate(); setError(''); setMessage(''); setAttempt(value => value + 1); };
  useEffect(() => {
    const generation = ++epoch.current; const controller = new AbortController(); setBusy(true);
    policyGovernance.access(controller.signal).then(async current => {
      if (generation !== epoch.current) return;
      setAccess(current);
      if (!current.permissions.includes('policies.read')) return;
      const page = await policyGovernance.list(controller.signal);
      if (generation === epoch.current) { setRows(page.policies); setTotal(page.total); }
    }).catch(() => {
      if (generation === epoch.current) { setAccess(null); setRows(null); setError('Richtlinienberechtigungen oder gespeicherte Daten nicht verfügbar. Keine Beispieldaten.'); }
    }).finally(() => { if (generation === epoch.current) setBusy(false); });
    const revoked = () => { invalidate(); setError('Sitzung nicht mehr bestätigt. Erneut anmelden und Berechtigungen neu laden.'); };
    window.addEventListener('od:session-error', revoked);
    return () => { epoch.current++; controller.abort(); window.removeEventListener('od:session-error', revoked); };
  }, [attempt]);

  const canManage = access?.permissions.includes('policies.manage') === true;
  const canDeploy = access?.permissions.includes('policies.deploy') === true;
  const ready = !!access?.freshMfa && rows !== null && !error && !busy;
  function stageCreate() {
    if (!canManage || !ready) return;
    try {
      const parsed = JSON.parse(settings);
      if (!name.trim() || name.trim().length > 255 || !parsed || typeof parsed !== 'object' || Array.isArray(parsed) || settings.length > 65536) throw new Error('Invalid draft');
      setAck(false); setReason(''); setMessage(''); setConfirmation({ kind: 'create', draft: { name: name.trim(), type: policyType, platform: 'all', settings: parsed } });
    } catch { setError('Name und gültiges JSON-Einstellungsobjekt erforderlich. Neu laden.'); }
  }
  async function confirm() {
    if (!confirmation || !ack || !ready || !access || reason.trim().length < 10) return;
    const captured = confirmation; const expected = access; const generation = epoch.current; setBusy(true); setMessage('');
    try {
      const current = await policyGovernance.access();
      if (generation !== epoch.current) return;
      const permission = captured.kind === 'create' ? 'policies.manage' : 'policies.deploy';
      if (current.userId !== expected.userId || current.subject !== expected.subject || !current.freshMfa || !current.permissions.includes(permission)) throw new Error('Authority changed');
      const changed = captured.kind === 'create' ? await policyGovernance.create(captured.draft, current.userId, reason.trim()) : await policyGovernance.transition(captured.policy, captured.kind, reason.trim(), captured.publicationId);
      if (generation !== epoch.current) return;
      setRows(previous => captured.kind === 'create' ? [changed, ...(previous || [])].slice(0, 50) : previous?.map(row => row.id === changed.id ? changed : row) || null);
      if (captured.kind === 'create') { setTotal(value => value + 1); setName(''); setSettings('{}'); }
      setConfirmation(null); setPublications({}); setAck(false); setReason(''); setMessage(captured.kind === 'create' ? 'Richtlinienentwurf im kanonischen Dienst bestätigt.' : 'Gespeicherter Richtlinienstatus bestätigt. Keine Geräteausführung bestätigt.');
    } catch (failure: unknown) {
      if (generation === epoch.current) {
        invalidate();
        setError((failure as { response?: { status?: number } })?.response?.status === 428 ? 'Frische MFA-Anmeldung erforderlich. Danach Berechtigungen und Daten neu laden.' : 'Änderung nicht bestätigt. Berechtigungen und Daten neu laden; nicht blind wiederholen.');
      }
    } finally { if (generation === epoch.current) setBusy(false); }
  }
  return <section aria-label="Kanonische Richtlinienverwaltung" className="p-6 space-y-4 h-full overflow-auto text-[var(--text-primary,#e4e6ea)] [&_button]:rounded-md [&_button]:border [&_button]:border-white/20 [&_button]:px-3 [&_button]:py-2 [&_button:disabled]:opacity-50 [&_input]:bg-black/20 [&_textarea]:bg-black/20">
    <h1 className="text-xl font-semibold">Richtlinien &amp; Berechtigungen</h1>
    <p className="text-sm">Quelle: kanonischer Policy-Service. Richtlinienlesen, Konfiguration und Ausrollen sind eigene Rechte; keine Lizenz- oder Verzeichnisverwaltung. Dies ist noch keine Mandantentrennung.</p>
    <button onClick={reload} disabled={busy}>Richtlinienberechtigungen neu laden</button>
    {busy && <p role="status">Richtlinien werden geprüft …</p>}{error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    {access && !access.permissions.includes('policies.read') && <p>Keine Berechtigung zum Lesen der Richtlinien.</p>}
    {access && <p className="text-xs break-all">Kanonischer Operator: {access.userId} · {access.permissions.length} Richtlinienrechte</p>}
    {access && (canManage || canDeploy) && !access.freshMfa && <p role="alert">Schreibzugriffe benötigen eine echte MFA-Anmeldung innerhalb der letzten fünf Minuten.</p>}
    {rows !== null && <><p>{rows.length} von {total} gespeicherten Richtlinien. Keine Beispieldaten oder lokale Erfolgsannahmen.</p>
      {rows.map(row => <article className="border border-white/15 rounded-lg p-3 space-y-2" key={row.id}>
        <h2 className="font-medium">{row.name}</h2><p className="text-xs break-all">{row.id} · {row.type} · {row.platform} · Version {row.version} · {row.status}</p>
        <details><summary>Gespeicherte Einstellungen</summary><pre className="text-xs whitespace-pre-wrap break-all">{JSON.stringify(row.settings, null, 2)}</pre></details>
        {access && <PolicyPublicationPanel key={`${row.id}:${row.version}:${access.userId}`} kind="policy" id={row.id} version={row.version} access={access} disabled={busy || !!confirmation} onSelect={publicationId => setPublications(previous => ({ ...previous, [row.id]: publicationId }))} />}
        {publications[row.id] && <p className="text-xs break-all">Ausgewählte Freigabe: {publications[row.id]}</p>}
        {canDeploy && <button disabled={!ready || !!confirmation || row.status !== 'active' && !publications[row.id]} onClick={() => { setAck(false); setReason(''); setMessage(''); setConfirmation({ kind: row.status === 'active' ? 'deactivate' : 'activate', policy: row, ...(row.status !== 'active' ? { publicationId: publications[row.id] } : {}) }); }}>{row.status === 'active' ? 'Deaktivierung prüfen' : 'Aktivierung prüfen'}</button>}
      </article>)}
    </>}
    {canManage && <div className="border border-white/15 rounded-lg p-4 space-y-3">
      <h2>Neuer Sicherheitsrichtlinienentwurf</h2>
      <label className="block">Richtlinienart<select className="block bg-black/20 p-2" value={policyType} disabled={busy || !!confirmation} onChange={event => { const type = event.target.value; setPolicyType(type); setSettings(JSON.stringify(type === 'gpo' ? { configuration: {}, platforms: ['windows', 'macos', 'linux'], gpoType: 'custom' } : type === 'update-ring' ? { deferralDays: { windows: 14, macos: 7, linux: 0 } } : {}, null, 2)); }}><option value="security">Sicherheitsrichtlinie</option><option value="gpo">Persistente GPO-Konfiguration</option><option value="update-ring">Persistenter Update-Ring</option></select></label>
      <label className="block">Name der Richtlinie<input className="block w-full p-2" maxLength={255} value={name} disabled={busy || !!confirmation} onChange={event => setName(event.target.value)} /></label>
      <label className="block">Einstellungen (JSON)<textarea aria-label="Einstellungen (JSON)" className="block w-full p-2 font-mono" rows={5} maxLength={65536} value={settings} disabled={busy || !!confirmation} onChange={event => setSettings(event.target.value)} /></label>
      <button disabled={!ready || !!confirmation} onClick={stageCreate}>Richtlinienentwurf prüfen</button>
    </div>}
    {confirmation && <div role="group" aria-label="Richtlinienänderung bestätigen" className="border border-blue-400/40 rounded-lg p-4 space-y-3">
      <p>{confirmation.kind === 'create' ? `Neuer Entwurf: ${confirmation.draft.name}` : `${confirmation.kind === 'activate' ? 'Aktivieren' : 'Deaktivieren'}: ${confirmation.policy.name} · ${confirmation.policy.id} · exakte Version ${confirmation.policy.version}`}</p>
      {confirmation.kind === 'create' && <pre className="text-xs whitespace-pre-wrap">{JSON.stringify(confirmation.draft.settings, null, 2)}</pre>}
      <p className="text-xs">Eine gespeicherte Richtlinie oder ein aktiver Status bestätigt weder Zustellung noch Durchsetzung auf einem Gerät. Aktivierung benötigt eine unabhängige, unveränderte und weiterhin gültige Freigabe{confirmation.kind === 'activate' ? `: ${confirmation.publicationId}` : '.'}</p>
      <label className="block">Begründung der Richtlinienänderung<textarea aria-label="Begründung der Richtlinienänderung" className="block w-full p-2" maxLength={500} value={reason} disabled={busy} onChange={event => setReason(event.target.value)} /></label>
      <label className="flex gap-2"><input type="checkbox" checked={ack} disabled={busy} onChange={event => setAck(event.target.checked)} />Richtlinie, Aktion und Umfang geprüft.</label>
      <button disabled={!ready || !ack || reason.trim().length < 10} onClick={confirm}>Richtlinienänderung verbindlich bestätigen</button><button disabled={busy} onClick={() => { setConfirmation(null); setAck(false); setReason(''); }}>Richtlinienänderung abbrechen</button>
    </div>}
  </section>;
}
