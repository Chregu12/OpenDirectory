'use client';

import React, { useEffect, useRef, useState } from 'react';
import { ClientAccess } from '@/lib/registeredClients';
import { applicationAuthentication, AuthenticationPolicy, AuthenticationChange, authenticationPolicyError, policyClientId } from '@/lib/applicationAuthentication';
import { startLogin } from '@/lib/auth';

const field = 'w-full rounded border border-[var(--border)] bg-[var(--bg-surface-raised)] p-2';
const button = 'rounded border border-[var(--border)] px-3 py-2 disabled:opacity-40';
export default function AppAuthenticationView({ access, selectedClientId }: { access: ClientAccess; selectedClientId: string }) {
  const [input, setInput] = useState(''); const [target, setTarget] = useState(''); const [page, setPage] = useState<AuthenticationPolicy | null>(null);
  const [attempt, setAttempt] = useState(0); const [error, setError] = useState(''); const [busy, setBusy] = useState(false);
  const [required, setRequired] = useState(false); const [age, setAge] = useState(3600); const [reason, setReason] = useState('');
  const [pending, setPending] = useState<AuthenticationChange | null>(null); const [mutationError, setMutationError] = useState(''); const [notice, setNotice] = useState('');
  const current = useRef(target); current.current = target;
  const readable = access.permissions.includes('applications.authentication.read');
  const manageable = access.permissions.includes('applications.authentication.manage');
  useEffect(() => { if (selectedClientId) { setInput(selectedClientId); setTarget(selectedClientId); setAttempt(value => value + 1); } }, [selectedClientId]);
  useEffect(() => {
    setPage(null); setPending(null); setError(''); setMutationError(''); if (!readable || !target) return;
    let active = true; const controller = new AbortController();
    applicationAuthentication.get(target, controller.signal).then(value => { if (active) { setPage(value); setRequired(value.required); setAge(value.maxAgeSeconds); setReason(''); } })
      .catch(failure => { if (active) setError(authenticationPolicyError(failure)); });
    return () => { active = false; controller.abort(); };
  }, [readable, manageable, access.subject, access.clientId, access.userId, target, attempt]);
  if (!readable) return null;
  async function save() {
    if (!manageable || !page?.canManage || !pending || busy || mutationError) return; setBusy(true); const before = page; const change = pending;
    try {
      const result = await applicationAuthentication.change(before, change);
      if (current.current === before.clientId) { setPage(result); setRequired(result.required); setAge(result.maxAgeSeconds); setPending(null); setReason(''); }
      setNotice('Anmelderichtlinie bestätigt für ' + before.clientId + '. Frühere Client-Generationen müssen neu angemeldet werden.');
    } catch (failure) { if (current.current === before.clientId) setMutationError(authenticationPolicyError(failure)); }
    finally { setBusy(false); }
  }
  return <section className="space-y-4 border border-[var(--border)] rounded p-4" aria-label="Anwendungs-MFA-Richtlinie">
    <h3 className="text-lg font-semibold">Verbindliche MFA für Benutzeranmeldungen</h3>
    <p>Getrennte Richtlinienberechtigung, kein Geheimnis- oder Benutzerlisten-Zugriff. Änderungen verlangen frische MFA, eine Begründung und die genaue Registerversion. Vorherige Zugriffe, Refresh- und ausstehende Anmeldegrants dieser Client-Generation werden ungültig.</p>
    <form className="flex gap-3" onSubmit={event => { event.preventDefault(); try { const next = policyClientId(input.trim()); setTarget(next); setAttempt(value => value + 1); } catch (failure) { setError(authenticationPolicyError(failure)); } }}>
      <label className="grow">Anwendungs-ID für MFA-Richtlinie<input className={field} required disabled={busy} value={input} onChange={event => setInput(event.target.value)} /></label><button className={button} disabled={busy}>Richtlinie laden</button>
    </form>
    {notice && <p role="status">{notice}</p>}{error && <p role="alert">{error}</p>}
    {page && <div className="space-y-3"><h4 className="font-semibold">{page.name}</h4><p className="break-all">{page.clientId} · Version {page.version}</p>
      <p role="status">{page.required ? `MFA verbindlich; Anmeldung höchstens ${page.maxAgeSeconds} Sekunden alt.` : 'Anwendungs-MFA nicht verbindlich. Rollenrichtlinien, bestehende Benutzerfaktoren und PIM-Vorgaben bleiben bestehen.'}</p>
      {page.protected && <p>Privilegierte Scopes: nur globale Administration.</p>}
      {manageable && page.requiresFreshMfa && <p>Für Änderungen mit Passwort und OpenDirectory-TOTP neu anmelden. Falls nötig zuerst <a href="/mfa" className="underline">eigene MFA einrichten</a>. <button className={button} onClick={startLogin}>Für Richtlinienänderung neu anmelden</button></p>}
      {manageable && page.canManage && !pending && <form className="grid gap-3 max-w-2xl" onSubmit={event => { event.preventDefault(); setMutationError(''); setPending({ required, maxAgeSeconds: age, reason: reason.trim() }); }}>
        <label><input type="checkbox" checked={required} disabled={busy} onChange={event => setRequired(event.target.checked)} /> MFA für Benutzeranmeldungen verlangen</label>
        <label>Maximales Anmeldealter in Sekunden<input className={field} type="number" min={300} max={86400} required disabled={busy} value={age} onChange={event => setAge(Number(event.target.value))} /></label>
        <label>Begründung der Anmelderichtlinie<textarea className={field} required minLength={10} maxLength={500} disabled={busy} value={reason} onChange={event => setReason(event.target.value)} /></label>
        <button className={button} disabled={busy}>Anmelderichtlinie prüfen</button>
      </form>}
      {(!manageable || !page.canManage && !page.requiresFreshMfa) && <p>Nur lesbar: getrennte Berechtigung, geschützter Client oder eigener Anmeldeclient.</p>}
    </div>}
    {pending && page && <div role="alertdialog" aria-label="Anmelderichtlinie bestätigen" className="space-y-3 border border-[var(--border)] rounded p-4">
      <p>{page.clientId}: MFA {pending.required ? 'verbindlich' : 'nicht verbindlich'}, maximales Alter {pending.maxAgeSeconds} Sekunden.</p><p>{pending.reason}</p>
      <p>Eine Sitzungserneuerung verjüngt den MFA-Nachweis nicht. Workload-Anmeldungen erhalten keine menschliche MFA; die gemeinsame Client-Generation ändert sich trotzdem. Neue Benutzer richten bei Bedarf nur ihren Faktor über das Anmeldeportal ein.</p>
      {mutationError && <p role="alert">{mutationError}</p>}<button className={button} disabled={busy || !!mutationError} onClick={() => void save()}>Richtlinie verbindlich speichern</button>
      <button className={button} disabled={busy} onClick={() => { setPending(null); setAttempt(value => value + 1); }}>Schließen und Stand prüfen</button>
    </div>}
  </section>;
}
