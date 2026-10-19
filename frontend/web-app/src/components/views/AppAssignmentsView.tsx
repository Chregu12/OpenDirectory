'use client';
import React, { useEffect,useState } from 'react';
import { ClientAccess,clientError } from '@/lib/registeredClients';
import { ApplicationAssignmentPage,ApplicationAssignment,ApplicationGrant,applicationAssignments,assignmentRequestId } from '@/lib/applicationAssignments';
import { canonicalRoleUser } from '@/lib/directoryRoles';

const field = 'w-full rounded border border-[var(--border)] bg-[var(--bg-surface-raised)] p-2';
const button = 'rounded border border-[var(--border)] px-3 py-2 disabled:opacity-40';
export default function AppAssignmentsView({ access,selectedClientId }: { access: ClientAccess; selectedClientId: string }) {
  const [input,setInput] = useState(''); const [target,setTarget] = useState(''); const [page,setPage] = useState<ApplicationAssignmentPage | null>(null);
  const [attempt,setAttempt] = useState(0); const [error,setError] = useState(''); const [busy,setBusy] = useState(false); const [mutationError,setMutationError] = useState(''); const [notice,setNotice] = useState('');
  const [type,setType] = useState<'user' | 'group'>('user'); const [targetId,setTargetId] = useState(''); const [duration,setDuration] = useState(86400); const [reason,setReason] = useState('');
  const [action,setAction] = useState<{ clientId: string; grant?: ApplicationGrant; revoke?: ApplicationAssignment } | null>(null);
  const canRead = access.permissions.includes('applications.assignments.read'); const canManage = access.permissions.includes('applications.assignments.manage') && page?.canManage === true;
  useEffect(() => { if (selectedClientId) { setAction(null); setMutationError(''); setNotice(''); setInput(selectedClientId); setTarget(selectedClientId); } },[selectedClientId]);
  useEffect(() => {
    setPage(null); setError(''); if (!target || !canRead) return;
    let active = true; const controller = new AbortController();
    applicationAssignments.list(target,controller.signal).then(result => { if (active) setPage(result); }).catch(failure => { if (active) setError(clientError(failure)); });
    return () => { active = false; controller.abort(); };
  },[target,attempt,canRead]);
  function prepare(event: React.FormEvent) {
    event.preventDefault(); if (!page || !canManage) return;
    try {
      const id = canonicalRoleUser(targetId.trim());
      if (type === 'user' && id === access.userId) throw new Error('Eigene Anwendungszugriffe dürfen nicht administrativ zugewiesen werden.');
      setMutationError(''); setAction({ clientId: target,grant: { requestId: assignmentRequestId(),targetType: type,targetId: id,durationSeconds: duration,reason: reason.trim() } });
    } catch (failure) { setError(clientError(failure)); }
  }
  async function perform() {
    if (!action || busy || mutationError || !canManage) return;
    setBusy(true);
    try {
      if (action.grant) await applicationAssignments.grant(action.clientId,action.grant);
      else if (action.revoke) await applicationAssignments.revoke(action.clientId,action.revoke);
      setNotice(`Zuweisung für ${action.clientId} bestätigt. Neue Anmeldung erforderlich; eine Zuweisung erteilt keine Plattformrolle oder Herstellerlizenz.`);
      setAction(null); setReason(''); setAttempt(value => value + 1);
    } catch (failure) { setMutationError(clientError(failure)); } finally { setBusy(false); }
  }
  if (!canRead) return null;
  return <section className="space-y-3 rounded border border-[var(--border)] p-4" aria-label="Anwendungszugriff">
    <h3 className="font-semibold">Benutzer- und Gruppenzuweisungen</h3><p>Anmeldungen benötigen eine ausdrückliche, gültige Zuweisung. Globale Rollen ersetzen diese nicht.</p>
    <p>Eine laufende Zuweisung ist keine bestätigte Anmeldung: Kontostatus und Gruppenmitgliedschaft werden zusätzlich live geprüft.</p>
    <label className="block">Client-ID für Zugriffsverwaltung<input className={field} value={input} onChange={event => setInput(event.target.value)} /></label>
    <button className={button} onClick={() => { setAction(null); setTarget(input.trim()); setAttempt(value => value + 1); }}>Zuweisungen laden</button>
    {error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}{target && !page && !error && <p role="status">Zuweisungen werden geprüft …</p>}
    {page && <><h4>Zugriff für {page.name}</h4>{page.protected && <p>Privilegierte Anwendung: Änderungen nur durch globale Administration.</p>}
      {page.truncated && <p role="alert">Nur 100 Zuweisungen sichtbar. Kein vollständiger Bestandsbericht.</p>}
      <ul>{page.assignments.length === 0 ? <li>Keine Zuweisungen.</li> : page.assignments.map(row => <li key={row.id} className="my-2 rounded border border-[var(--border)] p-3">
        <p className="break-all">{row.targetType === 'user' ? 'Benutzer' : 'Gruppe'}: <code>{row.targetId}</code> · {row.status === 'active' ? 'Gültig' : row.status === 'expired' ? 'Abgelaufen' : 'Widerrufen'}</p>
        <p>{row.reason} · Bis {new Date(row.expiresAt).toLocaleString()}</p>
        {canManage && row.status === 'active' && !(row.targetType === 'user' && row.targetId === access.userId) && <button className={button} onClick={() => { setMutationError(''); setAction({ clientId: target,revoke: row }); }}>Zuweisung widerrufen</button>}
      </li>)}</ul>
      {canManage && <form className="space-y-3" onSubmit={prepare}>
        <div><label htmlFor="application-assignment-type">Zieltyp</label><select id="application-assignment-type" className={field} value={type} onChange={event => setType(event.target.value as 'user' | 'group')}><option value="user">Benutzer</option><option value="group">Gruppe, direkte Mitglieder</option></select></div>
        <label className="block">Kanonische Ziel-ID<input className={field} required value={targetId} onChange={event => setTargetId(event.target.value)} /></label>
        <label className="block">Gültigkeit in Sekunden<input className={field} type="number" min={60} max={2592000} required value={duration} onChange={event => setDuration(Number(event.target.value))} /></label>
        <label className="block">Begründung der Anwendungszuweisung<textarea className={field} minLength={10} maxLength={500} required value={reason} onChange={event => setReason(event.target.value)} /></label>
        <button className={button} type="submit">Anwendungszuweisung prüfen</button>
      </form>}</>}
    {action && <div role="dialog" aria-label="Anwendungszuweisung bestätigen" className="space-y-3 rounded border border-amber-500 p-4">
      <h4>{action.revoke ? 'Anwendungszugriff widerrufen' : 'Anwendungszugriff zuweisen'}</h4><p className="break-all">Client-ID: {action.clientId}</p><p className="break-all">{action.grant?.targetId || action.revoke?.targetId}</p>
      <p>Eine Zuweisungsänderung beendet bisherige Anmeldegrants des betroffenen Zugriffs. Überlappende gültige Quellen können eine neue Anmeldung weiter erlauben. Ausgeführte Fremdsystemaktionen werden nicht zurückgerollt.</p>
      {mutationError && <p role="alert">{mutationError}</p>}<button className={button} disabled={busy || !!mutationError} onClick={perform}>Zuweisungsänderung bestätigen</button> <button className={button} disabled={busy} onClick={() => setAction(null)}>Schließen und Stand prüfen</button>
    </div>}
  </section>;
}
