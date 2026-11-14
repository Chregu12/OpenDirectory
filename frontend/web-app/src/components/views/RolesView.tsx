'use client';

import React, { useEffect, useRef, useState } from 'react';
import toast from 'react-hot-toast';
import { useIdentityAccess } from '@/hooks/useIdentityAccess';
import { CatalogRole, RolePage, RoleAssignment, canonicalRoleUser, directoryRoles } from '@/lib/directoryRoles';
import { directoryError, DirectoryUser, userName } from '@/lib/directoryUsers';
import { DirectoryConfirmation } from './UserDetailPanel';
import RoleAuthenticationView from './RoleAuthenticationView';
import RoleReviewsView from './RoleReviewsView';
import GroupMembershipReviewsView from './GroupMembershipReviewsView';

function RoleAssignmentsView({ selectedUser }: { selectedUser?: DirectoryUser }) {
  const { access, can, unavailable, reload: reloadAccess } = useIdentityAccess();
  const authority = `${access?.userId || ''}:${access?.permissions.join(' ') || ''}`;
  const currentAuthority = useRef(authority); currentAuthority.current = authority;
  const [catalog, setCatalog] = useState<CatalogRole[]>([]); const [inputId, setInputId] = useState(''); const [target, setTarget] = useState(selectedUser?.id || '');
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const [page, setPage] = useState<RolePage | null>(null); const [loading, setLoading] = useState(false); const [error, setError] = useState('');
  const [role, setRole] = useState(''); const [duration, setDuration] = useState(3600); const [reason, setReason] = useState('');
  const [attempt, setAttempt] = useState(0); const [busy, setBusy] = useState(false); const [mutationError, setMutationError] = useState('');
  const [action, setAction] = useState<{ authority: string; userId: string; role: string; duration: number; reason: string; assignment?: RoleAssignment } | null>(null);
  useEffect(() => { setAction(null); setMutationError(''); setBusy(false); }, [authority]);
  const refresh = () => { setPage(null); setError(''); setAttempt(value => value + 1); };
  useEffect(() => {
    setCatalog([]); setPage(null); setError('');
    if (!access?.permissions.includes('identities.roles.read')) return;
    let active = true; const controller = new AbortController();
    directoryRoles.catalog(controller.signal).then(result => { if (active) setCatalog(result); })
      .catch(failure => { if (active) setError(directoryError(failure)); });
    return () => { active = false; controller.abort(); };
  }, [access, attempt]);
  useEffect(() => {
    setPage(null);
    if (!target || !access?.permissions.includes('identities.roles.read')) return;
    let active = true; const controller = new AbortController(); setLoading(true);
    directoryRoles.list(target, controller.signal).then(result => { if (active) setPage(result); })
      .catch(failure => { if (active) setError(directoryError(failure)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [access, target, attempt]);

  async function perform() {
    if (!action || action.authority !== currentAuthority.current || !can('identities.roles.manage') || action.userId === access?.userId) return;
    setBusy(true);
    try {
      if (action.assignment) await directoryRoles.revoke(action.userId, action.assignment.id);
      else await directoryRoles.grant(action.userId, action.role, action.duration, action.reason);
      if (!mounted.current || action.authority !== currentAuthority.current) return;
      toast.success(action.assignment ? 'Rollenzuweisung widerrufen.' : 'Zeitlich begrenzte Rolle zugewiesen. Erneute Anmeldung erforderlich.');
      setAction(null); setReason(''); refresh();
    } catch (failure: any) {
      if (!mounted.current || action.authority !== currentAuthority.current) return; setMutationError(directoryError(failure));
      if (failure?.response?.status === 403) reloadAccess();
    } finally { if (mounted.current && action.authority === currentAuthority.current) setBusy(false); }
  }

  if (unavailable) return <section className="p-8" role="alert">Rollenberechtigungen nicht verfügbar. Keine Beispieldaten. <button onClick={reloadAccess}>Erneut prüfen</button></section>;
  if (!access) return <p className="p-8" role="status">Rollenberechtigungen werden geprüft …</p>;
  if (!can('identities.roles.read')) return <section className="space-y-5"><h2>Rollen &amp; Rechte</h2>{!selectedUser && <><RoleAuthenticationView access={access} /><RoleReviewsView access={access} /><GroupMembershipReviewsView access={access} /></>}<p>Keine Berechtigung zum Lesen der Rollenzuweisungen.</p></section>;
  const self = target === access.userId?.toLowerCase();
  const writable = !!access.userId && can('identities.roles.manage') && !self && !error && !!page && !!catalog.length;
  const statusName = { active: 'Aktiv', expired: 'Abgelaufen', revoked: 'Widerrufen', policy_changed: 'Durch PIM-Richtlinie entzogen', review_expired: 'Zugriffsprüfung abgelaufen' };
  return <section className={selectedUser ? 'space-y-5' : 'p-6 space-y-5 overflow-auto h-full'} aria-label="Rollenzuweisungen" style={{ background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)' }}>
    {selectedUser ? <h2 className="text-lg font-semibold">Rollen für {userName(selectedUser)}</h2> : <h1 className="text-xl font-semibold">Rollen &amp; Rechte</h1>}
    {!selectedUser && <><RoleAuthenticationView access={access} />
    <RoleReviewsView access={access} />
    <GroupMembershipReviewsView access={access} /></>}
    <p>Quelle: kanonischer Verzeichnisdienst. Anmeldedienst-Rollen vergeben hier keine Rechte. Status gilt zum Abrufzeitpunkt.</p>
    <p>API-Zuweisungen erfordern eine Begründung und laufen nach spätestens acht Stunden ab. Rollenänderungen entziehen bisherigen Sitzungen den Zugriff; zur Übernahme erneut anmelden. PIM-Aktivierungen werden im Bereich Privilegierter Zugriff verwaltet. Aktive und berechtigte Vergaben können zusätzlich verbindlichen Zugriffsprüfungen unterliegen.</p>
    {!selectedUser && <form className="flex gap-3 flex-wrap" onSubmit={event => {
      event.preventDefault(); setError(''); setPage(null);
      try { const identifier = canonicalRoleUser(inputId.trim()); if (identifier === target) refresh(); else setTarget(identifier); }
      catch (failure: any) { setTarget(''); setError(failure.message); }
    }}><label>Verzeichnis-ID<input className="block p-2 border rounded bg-transparent w-96 max-w-full font-mono" value={inputId} disabled={busy || !!action} onChange={event => setInputId(event.target.value)} required /></label>
      <button disabled={busy || !!action}>Zuweisungen laden</button><button type="button" disabled={busy || !!action} onClick={refresh}>Neu laden</button></form>}
    {selectedUser && <button className="fluent-btn-secondary" disabled={busy || !!action} onClick={refresh}>Rollen neu laden</button>}
    {error && <p role="alert">{error}</p>}{loading && <p role="status">Zuweisungen werden geladen …</p>}
    {self && <p>Eigene Rollen können hier nicht selbst administriert werden.</p>}
    {page && !error && <><h2 className="font-semibold break-all">Rollenzuweisungen für {page.userId}</h2>
      {!page.assignments.length && <p>Keine Rollenzuweisungen vorhanden.</p>}
      {page.truncated && <p>Die neuesten 100 Zuweisungen werden angezeigt; aktive Zuweisungen zuerst.</p>}
      <ul className="space-y-3">{page.assignments.map(item => <li key={item.id} className="border border-[var(--border)] rounded p-3 space-y-1">
        <p><strong>{item.role}</strong> · {statusName[item.status]}</p><p>{item.reason}</p>
        <p>Ablauf: {item.expiresAt || 'Unbefristet · Offline-Provisionierung prüfen'}</p>
        {item.revokedAt && <p>Widerrufen: {item.revokedAt}</p>}
        {writable && item.status === 'active' && catalog.some(entry => entry.role === item.role && entry.assignable) && <button className="fluent-btn-secondary" onClick={() => { setMutationError(''); setAction({ authority, userId: target, role: item.role, duration, reason, assignment: item }); }}>Widerrufen: {item.role}</button>}
      </li>)}</ul></>}
    {writable && <form className="space-y-3 max-w-xl" onSubmit={event => {
      event.preventDefault(); if (!catalog.some(item => item.role === role && item.assignable)) return;
      setMutationError(''); setAction({ authority, userId: target, role, duration, reason });
    }}><h2 className="font-semibold">Rolle zeitlich begrenzt zuweisen</h2>
      <label className="block" htmlFor="directory-role-choice">Rolle</label><select id="directory-role-choice" className="input-apple block w-full" value={role} onChange={event => setRole(event.target.value)} required>
        <option value="">Rolle wählen</option>{catalog.map(item => <option key={item.role} value={item.role} disabled={!item.assignable}>{item.role}{item.protected ? ' · geschützt' : ''}</option>)}</select>
      <label className="block" htmlFor="directory-role-duration">Dauer</label><select id="directory-role-duration" className="input-apple block w-full" value={duration} onChange={event => setDuration(Number(event.target.value))}>
        <option value={3600}>1 Stunde</option><option value={14400}>4 Stunden</option><option value={28800}>8 Stunden</option></select>
      <label className="block">Begründung<textarea className="input-apple block w-full" value={reason} minLength={10} maxLength={500} required onChange={event => setReason(event.target.value)} /></label>
      <button className="fluent-btn-primary">Rollenzuweisung prüfen</button></form>}
    {action && <DirectoryConfirmation title={action.assignment ? 'Rollenzuweisung widerrufen' : 'Rolle zuweisen'} busy={busy} error={mutationError} onClose={() => { setAction(null); setMutationError(''); refresh(); }} onConfirm={() => void perform()}>
      <p className="break-all">Verzeichnis-ID: {action.userId}</p><p>Rolle: {action.role}</p>
      {action.assignment && <p className="break-all">Zuweisungs-ID: {action.assignment.id} · Ablauf: {action.assignment.expiresAt || 'unbefristet'}</p>}
      {!action.assignment && <p>Dauer: {action.duration / 3600} Stunden · {action.reason}</p>}
      <p>An den angebundenen APIs verlieren bestehende Sitzungen des Zielbenutzers ihre Zugriffsberechtigung. Keine automatische Wiederherstellung alter Sitzungen.</p>
    </DirectoryConfirmation>}
  </section>;
}

export default function RolesView({ selectedUser }: { selectedUser?: DirectoryUser } = {}) {
  return <RoleAssignmentsView key={selectedUser?.id || 'directory'} selectedUser={selectedUser} />;
}
