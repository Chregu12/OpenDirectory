'use client';

import React, { useEffect, useRef, useState } from 'react';
import { DirectoryAccess } from '@/lib/directoryUsers';
import { roleAuthentication, RoleAuthenticationPolicy, RoleAuthenticationChange, roleAuthenticationError, authenticationRole } from '@/lib/roleAuthentication';
import { startLogin } from '@/lib/auth';

const field = 'w-full rounded border border-[var(--border)] bg-[var(--bg-surface-raised)] p-2';
const button = 'rounded border border-[var(--border)] px-3 py-2 disabled:opacity-40';
export default function RoleAuthenticationView({ access }: { access: DirectoryAccess }) {
  const readable = access.permissions.includes('authentication.policies.read'); const manageable = access.permissions.includes('authentication.policies.manage');
  const [input,setInput] = useState(''); const [target,setTarget] = useState(''); const [page,setPage] = useState<RoleAuthenticationPolicy | null>(null);
  const [attempt,setAttempt] = useState(0); const [error,setError] = useState(''); const [busy,setBusy] = useState(false);
  const [required,setRequired] = useState(false); const [age,setAge] = useState(3600); const [reason,setReason] = useState('');
  const [pending,setPending] = useState<RoleAuthenticationChange | null>(null); const [mutationError,setMutationError] = useState(''); const [notice,setNotice] = useState('');
  const context = `${target}:${access.subject}:${access.userId}:${readable}:${manageable}`;
  const current = useRef(context); current.current = context;
  useEffect(() => {
    setPage(null); setPending(null); setError(''); setMutationError('');
    if (!readable || !target) return;
    let active = true; const controller = new AbortController();
    roleAuthentication.get(target,controller.signal).then(value => { if (active) { setPage(value); setRequired(value.required); setAge(value.maxAgeSeconds); setReason(''); } })
      .catch(failure => { if (active) setError(roleAuthenticationError(failure)); });
    return () => { active = false; controller.abort(); };
  },[readable,manageable,access.subject,access.userId,target,attempt]);
  if (!readable) return null;
  async function save() {
    if (!manageable || !page?.canManage || !pending || busy || mutationError) return;
    const before = page; const change = pending; const operationContext = context; setBusy(true);
    try {
      const result = await roleAuthentication.change(before,change);
      setNotice(`Rollenrichtlinie bestätigt für ${before.role}. Betroffene Benutzer müssen sich neu anmelden.`);
      if (current.current === operationContext) { setPage(result); setRequired(result.required); setAge(result.maxAgeSeconds); setReason(''); setPending(null); }
    } catch (failure) { if (current.current === operationContext) setMutationError(roleAuthenticationError(failure)); }
    finally { setBusy(false); }
  }
  return <section className="space-y-4 border border-[var(--border)] rounded p-4" aria-label="Rollenweite MFA-Richtlinien">
    <h2 className="text-lg font-semibold">MFA unabhängig von der Anwendung</h2>
    <p>Die strengste aktive kanonische Rollenrichtlinie gilt über alle angebundenen Clients, auch ohne Rollen-Claims im Token. Sie verleiht keine Rolle oder Lizenz. Vorherige Sitzungen und ausstehende Anmeldungen betroffener Rollen werden bei jeder Änderung ungültig.</p>
    <form className="flex gap-3" onSubmit={event => { event.preventDefault(); try { const next = authenticationRole(input.trim()); setTarget(next); setAttempt(value => value + 1); } catch (failure) { setError(roleAuthenticationError(failure)); } }}>
      <label className="grow">Kanonische Rolle für MFA-Richtlinie<input className={field} value={input} required disabled={busy} onChange={event => setInput(event.target.value)} /></label>
      <button className={button} disabled={busy}>Rollenrichtlinie laden</button>
    </form>
    {notice && <p role="status">{notice}</p>}{error && <p role="alert">{error}</p>}
    {page && <div className="space-y-3"><h3>{page.role} · Version {page.version}</h3>
      <p role="status">{page.required ? `Rollenweite MFA verbindlich; Anmeldung höchstens ${page.maxAgeSeconds} Sekunden alt.` : 'Keine zusätzliche rollenweite MFA-Vorgabe. Anwendungsregeln, persönliche Faktoren und PIM bleiben verbindlich.'}</p>
      {page.protected && <p>Geschützte Rolle: Änderungen nur durch globale Administration.</p>}
      {page.locked && <p>Für die Sicherheitsrichtlinien-Administration gilt unveränderlich MFA mit höchstens fünf Minuten Anmeldealter.</p>}
      {manageable && page.requiresFreshMfa && <p>Für Änderungen frisch mit Passwort und OpenDirectory-TOTP anmelden. <button className={button} onClick={startLogin}>Für Rollenrichtlinie neu anmelden</button></p>}
      {manageable && page.canManage && !pending && <form className="grid gap-3 max-w-2xl" onSubmit={event => { event.preventDefault(); setMutationError(''); setPending({ required,maxAgeSeconds:age,reason:reason.trim() }); }}>
        <label><input type="checkbox" checked={required} disabled={busy} onChange={event => setRequired(event.target.checked)} /> MFA für diese Rolle verlangen</label>
        <label>Maximales Rollen-Anmeldealter in Sekunden<input className={field} type="number" min={300} max={86400} required disabled={busy} value={age} onChange={event => setAge(Number(event.target.value))} /></label>
        <label>Begründung der Rollenrichtlinie<textarea className={field} minLength={10} maxLength={500} required disabled={busy} value={reason} onChange={event => setReason(event.target.value)} /></label>
        <button className={button} disabled={busy}>Rollenrichtlinie prüfen</button>
      </form>}
      {(!manageable || !page.canManage && !page.requiresFreshMfa) && <p>Rollenrichtlinie nur lesbar.</p>}
    </div>}
    {pending && page && <div role="alertdialog" aria-label="Rollenrichtlinie bestätigen" className="space-y-3 border rounded p-4">
      <p>{page.role}: MFA {pending.required ? 'verbindlich' : 'nicht verbindlich'}, höchstens {pending.maxAgeSeconds} Sekunden.</p><p>{pending.reason}</p>
      <p>Auch die eigene Sitzung kann ungültig werden. Refresh verjüngt den Nachweis nicht. Bei verlorenem Ergebnis zuerst den Stand prüfen.</p>
      {mutationError && <p role="alert">{mutationError}</p>}<button className={button} disabled={busy || !!mutationError} onClick={() => void save()}>Rollenrichtlinie verbindlich speichern</button>
      <button className={button} disabled={busy} onClick={() => { setPending(null); setAttempt(value => value + 1); }}>Schließen und Rollenstand prüfen</button>
    </div>}
  </section>;
}
