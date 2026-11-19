'use client';

import React, { useEffect, useRef, useState } from 'react';
import { EnvelopeIcon } from '@heroicons/react/24/outline';
import { PageHeader } from '@/components/ui/PageHeader';
import { DirectoryUser, directoryUsers } from '@/lib/directoryUsers';
import { useIdentityAccess } from '@/hooks/useIdentityAccess';
import { employeeInvitationManagement, employeeInvitationManagementError, EmployeeInvitationRecord } from '@/lib/employeeInvitationManagement';
import EmployeeOnboardingDialog from './EmployeeOnboardingDialog';

export default function EmployeeInvitationManager() {
  const { access, unavailable, reload: reloadAccess } = useIdentityAccess();
  const owner = access?.companyOwner === true && access.userId !== null;
  const [users, setUsers] = useState<DirectoryUser[]>([]); const [usersPage, setUsersPage] = useState(1); const [usersHasMore, setUsersHasMore] = useState(false); const [search, setSearch] = useState('');
  const [userBusy, setUserBusy] = useState(false);
  const [invitations, setInvitations] = useState<EmployeeInvitationRecord[]>([]); const [invitationPage, setInvitationPage] = useState(1); const [invitationHasMore, setInvitationHasMore] = useState(false);
  const [onboarding, setOnboarding] = useState<{ user?: DirectoryUser } | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<EmployeeInvitationRecord | null>(null); const [revokeReason, setRevokeReason] = useState(''); const [revokeConfirmed, setRevokeConfirmed] = useState(false);
  const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [notice, setNotice] = useState(''); const [reload, setReload] = useState(0);
  const generation = useRef(0);

  useEffect(() => {
    generation.current++; setUsers([]); setInvitations([]); setOnboarding(null); setRevokeTarget(null); setError(''); setNotice(''); setBusy(false);
    return () => { generation.current++; };
  }, [access?.userId, access?.subject, owner]);

  useEffect(() => {
    if (!owner) return;
    const controller = new AbortController(); setUserBusy(true);
    directoryUsers.list(usersPage, search.trim(), 'false', controller.signal).then(result => {
      if (!controller.signal.aborted) { setUsers(result.users); setUsersHasMore(usersPage * result.limit < result.total); }
    }).catch(failure => { if (!controller.signal.aborted) setError(employeeInvitationManagementError(failure)); })
      .finally(() => { if (!controller.signal.aborted) setUserBusy(false); });
    return () => controller.abort();
  }, [owner, access?.userId, access?.subject, usersPage, search, reload]);

  async function loadInvitations(page = invitationPage) {
    if (!owner) return;
    const original = generation.current; setBusy(true); setError('');
    try {
      const result = await employeeInvitationManagement.list(page);
      if (generation.current === original) { setInvitations(result.invitations); setInvitationHasMore(result.hasMore); setInvitationPage(page); }
    } catch (failure) { if (generation.current === original) setError(employeeInvitationManagementError(failure)); }
    finally { if (generation.current === original) setBusy(false); }
  }
  useEffect(() => { if (owner) void loadInvitations(1); }, [owner, access?.userId, access?.subject]);

  async function revokeInvitation(event: React.FormEvent) {
    event.preventDefault(); if (!revokeTarget || !revokeConfirmed || revokeReason.trim().length < 10 || busy) return;
    const original = generation.current; setBusy(true); setError(''); setNotice('');
    try {
      await employeeInvitationManagement.revoke({ id: revokeTarget.id, revision: revokeTarget.revision, reason: revokeReason.trim(), confirm: true });
      if (generation.current !== original) return;
      setNotice('Einladung widerrufen. Eine unveränderte angefangene Teilaufnahme wurde ebenfalls zurückgenommen.'); setRevokeTarget(null); setRevokeReason(''); setRevokeConfirmed(false); await loadInvitations(invitationPage);
    } catch (failure) { if (generation.current === original) setError(employeeInvitationManagementError(failure)); }
    finally { if (generation.current === original) setBusy(false); }
  }

  if (unavailable) return <section className="p-8" role="alert">Firmenberechtigung nicht verfügbar. <button onClick={reloadAccess}>Erneut prüfen</button></section>;
  if (!access) return <p className="p-8" role="status">Firmenberechtigung wird geprüft …</p>;
  if (!owner) return <main className="p-8 space-y-3"><PageHeader title="Mitarbeitereinladungen" icon={EnvelopeIcon} /><p>Nur der aktuelle Firmeninhaber kann Einladungen erstellen oder widerrufen.</p></main>;

  return <main className="space-y-6 text-[var(--text-primary)]">
    <div className="flex flex-wrap items-center justify-between gap-3"><div><PageHeader title="Mitarbeitereinladungen" icon={EnvelopeIcon} /><p className="mt-2">Neue Mitarbeitende in einem Ablauf aufnehmen oder eine Einladung für einen vorhandenen gesperrten Eintrag vorbereiten.</p></div>
      {access.permissions.includes('users.create') && <button className="bg-blue-600 text-white rounded px-4 py-2" onClick={() => setOnboarding({})}>Mitarbeiter aufnehmen</button>}
    </div>
    {error && <p role="alert" className="border border-red-400 rounded p-3">{error}</p>}
    {notice && <p role="status" className="border border-green-500 rounded p-3">{notice}</p>}
    <section className="bg-[var(--bg-surface)] border rounded-lg p-4 space-y-4"><h2 className="text-lg font-semibold">Vorhandenen Eintrag einladen</h2>
      <label className="block">Suchen<input className="block border rounded p-2 w-full" value={search} onChange={event => { setSearch(event.target.value); setUsersPage(1); }} placeholder="Benutzername oder Name" /></label>
      {userBusy ? <p role="status">Benutzer werden geladen …</p> : users.length ? <ul className="divide-y">{users.map(user => <li key={user.id} className="py-3 flex flex-wrap items-center justify-between gap-3"><div><strong>{user.displayName || user.username}</strong><p>{user.username} · {user.email}</p></div><button className="border rounded px-3 py-2" onClick={() => setOnboarding({ user })}>Einladung vorbereiten</button></li>)}</ul> : <p>Keine passenden gesperrten Einträge gefunden.</p>}
      <div className="flex gap-2"><button disabled={userBusy || usersPage <= 1} onClick={() => setUsersPage(page => page - 1)}>Zurück</button><span>Seite {usersPage}</span><button disabled={userBusy || !usersHasMore} onClick={() => setUsersPage(page => page + 1)}>Weiter</button></div>
    </section>
    <section className="bg-[var(--bg-surface)] border rounded-lg p-4 space-y-4"><div className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-lg font-semibold">Eigene Einladungen</h2><button className="border rounded px-3 py-1.5" disabled={busy} onClick={() => void loadInvitations(invitationPage)}>Aktualisieren</button></div>
      {invitations.length ? <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="text-left border-b"><th className="p-2">Anmeldename</th><th className="p-2">Status</th><th className="p-2">Gültig bis</th><th className="p-2">Aktion</th></tr></thead><tbody>{invitations.map(invitation => <tr key={invitation.id} className="border-b"><td className="p-2">{invitation.loginName}</td><td className="p-2">{({ pending: 'Ausstehend', credential_pending: 'Passwort gesetzt', accepted: 'Angenommen', revoked: 'Widerrufen' })[invitation.status]}</td><td className="p-2">{new Date(invitation.expiresAt).toLocaleString('de-CH')}</td><td className="p-2">{['pending', 'credential_pending'].includes(invitation.status) ? <button className="underline text-red-700" disabled={busy} onClick={() => { setRevokeTarget(invitation); setRevokeReason(''); setRevokeConfirmed(false); }}>Widerrufen</button> : '—'}</td></tr>)}</tbody></table></div> : <p>Noch keine Einladungen auf dieser Seite.</p>}
      <div className="flex gap-2"><button disabled={busy || invitationPage <= 1} onClick={() => void loadInvitations(invitationPage - 1)}>Zurück</button><span>Seite {invitationPage}</span><button disabled={busy || !invitationHasMore} onClick={() => void loadInvitations(invitationPage + 1)}>Weiter</button></div>
    </section>
    {revokeTarget && <section className="bg-red-50 border border-red-300 rounded-lg p-4 space-y-3"><h2 className="font-semibold">Einladung widerrufen: {revokeTarget.loginName}</h2><form className="space-y-3" onSubmit={event => void revokeInvitation(event)}><label className="block">Grund<input className="block border rounded p-2 w-full" minLength={10} maxLength={500} required value={revokeReason} onChange={event => setRevokeReason(event.target.value)} /></label><label className="flex gap-3"><input type="checkbox" checked={revokeConfirmed} onChange={event => setRevokeConfirmed(event.target.checked)} /><span>Originaleinladung und unveränderte Teilaufnahme zurücknehmen.</span></label><div className="flex gap-2"><button disabled={busy || !revokeConfirmed || revokeReason.trim().length < 10}>Widerruf bestätigen</button><button type="button" disabled={busy} onClick={() => setRevokeTarget(null)}>Abbrechen</button></div></form></section>}
    {onboarding && access.userId && <EmployeeOnboardingDialog key={onboarding.user?.id || 'new'} actorUserId={access.userId} user={onboarding.user} onClose={() => setOnboarding(null)} onCreated={() => setReload(value => value + 1)} onInvited={() => void loadInvitations(1)} />}
  </main>;
}
