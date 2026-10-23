'use client';

import React, { useEffect, useState } from 'react';
import { DirectoryUser, directoryUsers } from '@/lib/directoryUsers';
import { DirectoryGroup, directoryGroups } from '@/lib/directoryGroups';
import { useIdentityAccess } from '@/hooks/useIdentityAccess';
import { employeeInvitationManagement, employeeInvitationManagementError, EmployeeInvitationRecord, EmployeeInvitationTarget } from '@/lib/employeeInvitationManagement';

export default function EmployeeInvitationManager() {
  const { access, unavailable, reload: reloadAccess } = useIdentityAccess();
  const [users, setUsers] = useState<DirectoryUser[]>([]); const [usersPage, setUsersPage] = useState(1); const [usersHasMore, setUsersHasMore] = useState(false); const [search, setSearch] = useState('');
  const [groups, setGroups] = useState<DirectoryGroup[]>([]); const [groupsLoading, setGroupsLoading] = useState(false); const [groupIds, setGroupIds] = useState<string[]>([]); const [groupSearch, setGroupSearch] = useState(''); const [groupError, setGroupError] = useState('');
  const [userBusy, setUserBusy] = useState(false); const [targetBusy, setTargetBusy] = useState(false); const [target, setTarget] = useState<EmployeeInvitationTarget | null>(null);
  const [invitations, setInvitations] = useState<EmployeeInvitationRecord[]>([]); const [invitationPage, setInvitationPage] = useState(1); const [invitationHasMore, setInvitationHasMore] = useState(false);
  const [loginName, setLoginName] = useState(''); const [durationHours, setDurationHours] = useState(72); const [reason, setReason] = useState(''); const [confirmed, setConfirmed] = useState(false);
  const [invitationId, setInvitationId] = useState(''); const [inviteLink, setInviteLink] = useState(''); const [revokeTarget, setRevokeTarget] = useState<EmployeeInvitationRecord | null>(null);
  const [revokeReason, setRevokeReason] = useState(''); const [revokeConfirmed, setRevokeConfirmed] = useState(false);
  const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [notice, setNotice] = useState('');
  const owner = access?.companyOwner === true;

  useEffect(() => {
    if (!owner) { setUsers([]); return; }
    const controller = new AbortController(); let active = true; setUserBusy(true);
    directoryUsers.list(usersPage, search.trim(), 'false', controller.signal).then(result => {
      if (active) { setUsers(result.users); setUsersHasMore(usersPage * result.limit < result.total); }
    }).catch(failure => { if (active) setError(employeeInvitationManagementError(failure)); })
      .finally(() => { if (active) setUserBusy(false); });
    return () => { active = false; controller.abort(); };
  }, [owner, usersPage, search]);

  useEffect(() => {
    if (!owner) { setGroups([]); return; }
    let active = true; setGroupError(''); setGroupsLoading(true);
    directoryGroups.list().then(result => { if (active) setGroups(result.groups); })
      .catch(() => { if (active) setGroupError('Eigene Gruppen konnten nicht vollständig geladen werden.'); })
      .finally(() => { if (active) setGroupsLoading(false); });
    return () => { active = false; };
  }, [owner]);

  async function loadInvitations(page = invitationPage, force = false) {
    if (!owner || busy && !force) return;
    setBusy(true); setError('');
    try { const result = await employeeInvitationManagement.list(page); setInvitations(result.invitations); setInvitationHasMore(result.hasMore); setInvitationPage(page); }
    catch (failure) { setError(employeeInvitationManagementError(failure)); }
    finally { setBusy(false); }
  }
  useEffect(() => { if (owner) void loadInvitations(1); }, [owner]);

  async function selectUser(user: DirectoryUser) {
    if (!access?.userId || targetBusy || user.enabled) return;
    setTarget(null); setInviteLink(''); setError(''); setNotice(''); setTargetBusy(true);
    try { const result = await employeeInvitationManagement.target(user.id, access.userId); setTarget(result); setLoginName(result.username); setReason(''); setConfirmed(false); setGroupIds([]); setInvitationId(crypto.randomUUID()); }
    catch (failure: any) { setError(failure?.response ? employeeInvitationManagementError(failure) : failure.message || 'Einladungsziel nicht bestätigt.'); }
    finally { setTargetBusy(false); }
  }

  async function createInvitation(event: React.FormEvent) {
    event.preventDefault();
    if (!target || !invitationId || !confirmed || reason.trim().length < 10 || busy || targetBusy) return;
    setBusy(true); setError(''); setNotice(''); setInviteLink('');
    const added: Array<{ id: string; group: DirectoryGroup }> = []; let pendingReviews = 0; let invitationAttempted = false; let groupMutationUncertain = false;
    try {
      for (const id of groupIds) {
        const current = await directoryGroups.get(id);
        if (current.members.includes(target.id)) continue;
        groupMutationUncertain = true; const updated = await directoryGroups.add(current, target.id); groupMutationUncertain = false; added.push({ id, group: updated });
        if (updated.membershipReview?.effective === false) pendingReviews++;
      }
      invitationAttempted = true;
      const result = await employeeInvitationManagement.create({ id: invitationId, userId: target.id, userRevision: target.revision,
        loginName: loginName.trim(), durationHours, reason: reason.trim(), confirm: true });
      if (result.created && result.invitationToken) {
        const url = new URL('/employees/accept', window.location.origin); url.hash = result.invitationToken; setInviteLink(url.href);
        const delivery = result.mailStatus === 'sent' ? 'Der Einladungslink wurde per Microsoft Graph an die hinterlegte Adresse gesendet.'
          : 'Graph-Mail wurde nicht zugestellt; teile den Einmal-Link vertraulich mit der eingeladenen Person.';
        setNotice(`Einladung erstellt. ${delivery}${groupIds.length ? ` ${groupIds.length} Gruppen wurden vorgemerkt.` : ''}${pendingReviews ? ` ${pendingReviews} Gruppenmitgliedschaft(en) warten auf eine unabhängige Prüfung.` : ''}`);
      } else setNotice('Diese Einladung wurde bereits erstellt. Das Original-Token wird aus Sicherheitsgründen nicht erneut ausgegeben. Widerrufe sie und erstelle bei Bedarf eine neue Einladung.');
      setInvitationId(''); setTarget(null); setConfirmed(false); setReason(''); setGroupIds([]); await loadInvitations(1, true);
    } catch (failure) {
      const status = failure?.response?.status;
      const invitationRejected = invitationAttempted && [400, 401, 403, 404, 409, 412, 428, 429].includes(status);
      let rolledBack = false;
      if (!groupMutationUncertain && (!invitationAttempted || invitationRejected)) {
        rolledBack = true;
        for (const item of added.reverse()) {
          try { const current = await directoryGroups.get(item.id); if (current.members.includes(target.id)) await directoryGroups.removeMember(current, target.id); }
          catch { rolledBack = false; }
        }
      }
      const uncertain = groupMutationUncertain || invitationAttempted && !invitationRejected;
      setError(`${employeeInvitationManagementError(failure)}${uncertain ? ' Gruppen- oder Einladungsergebnis ist unklar. Mitgliedschaften und Einladungsstatus prüfen, bevor du es erneut versuchst.' : added.length ? rolledBack ? ' Die bestätigten Gruppenänderungen wurden zurückgenommen.' : ' Mindestens eine Gruppenänderung blieb bestehen; Gruppenmitgliedschaften bitte prüfen.' : ''}`);
    }
    finally { setBusy(false); }
  }

  async function revokeInvitation(event: React.FormEvent) {
    event.preventDefault();
    if (!revokeTarget || !revokeConfirmed || revokeReason.trim().length < 10 || busy) return;
    setBusy(true); setError(''); setNotice('');
    try {
      await employeeInvitationManagement.revoke({ id: revokeTarget.id, revision: revokeTarget.revision, reason: revokeReason.trim(), confirm: true });
      setNotice('Einladung widerrufen. Eine unveränderte angefangene Teilaufnahme wurde ebenfalls zurückgenommen.'); setRevokeTarget(null); setRevokeReason(''); setRevokeConfirmed(false); await loadInvitations(invitationPage, true);
    } catch (failure) { setError(employeeInvitationManagementError(failure)); }
    finally { setBusy(false); }
  }

  async function copyLink() {
    try { await navigator.clipboard.writeText(inviteLink); setNotice('Einladungslink kopiert.'); }
    catch { setError('Der Link konnte nicht kopiert werden. Markiere ihn und kopiere ihn manuell.'); }
  }

  if (unavailable) return <section className="p-8" role="alert">Firmenberechtigung nicht verfügbar. Es werden keine Beispieldaten angezeigt. <button onClick={reloadAccess}>Erneut prüfen</button></section>;
  if (!access) return <p className="p-8" role="status">Firmenberechtigung wird geprüft …</p>;
  if (!owner) return <main className="p-8 space-y-3"><h1 className="text-2xl font-semibold">Mitarbeitereinladungen</h1><p>Nur der aktuelle Firmeninhaber kann Einladungen erstellen oder widerrufen.</p></main>;

  return <main className="max-w-6xl mx-auto p-6 space-y-6 text-gray-900">
    <header><h1 className="text-2xl font-semibold">Mitarbeitereinladungen</h1><p className="mt-2">Wähle einen eigenen deaktivierten Verzeichniseintrag. Erstellung und Widerruf verlangen frische MFA. Es wird kein Konto aktiviert, bevor die eingeladene Person selbst ein Passwort setzt.</p></header>
    {error && <p role="alert" className="border border-red-400 rounded p-3">{error}</p>}
    {notice && <p role="status" className="border border-green-500 rounded p-3">{notice}</p>}
    {inviteLink && <section className="bg-white border rounded-lg p-4 space-y-3"><h2 className="font-semibold">Einmaliger Einladungslink</h2><div className="flex flex-wrap gap-2"><input className="border rounded p-2 min-w-0 flex-1" readOnly value={inviteLink} aria-label="Einmaliger Einladungslink" /><button className="border rounded px-3 py-2" onClick={() => void copyLink()}>Link kopieren</button><button className="border rounded px-3 py-2" onClick={() => setInviteLink('')}>Link schliessen</button></div><p className="text-sm">Der Link enthält ein vertrauliches Token im URL-Fragment. Versende es nur an die eingeladene Person; das Token wird nicht per E-Mail automatisch versendet.</p></section>}

    <section className="grid lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)] gap-6">
      <div className="bg-white border rounded-lg p-4 space-y-4"><h2 className="text-lg font-semibold">Deaktivierte Verzeichniseinträge</h2>
        <label className="block">Suchen<input className="block border rounded p-2 w-full" value={search} onChange={event => { setSearch(event.target.value); setUsersPage(1); }} placeholder="Benutzername oder Name" /></label>
        {userBusy ? <p role="status">Benutzer werden geladen …</p> : users.length ? <ul className="divide-y">{users.map(user => <li key={user.id} className="py-2 flex items-center justify-between gap-3"><span className="min-w-0"><strong className="block truncate">{user.displayName || user.username}</strong><small className="block truncate">{user.username} · {user.email}</small></span><button className="border rounded px-3 py-1.5 disabled:opacity-50" disabled={user.enabled || targetBusy} onClick={() => void selectUser(user)}>{user.enabled ? 'Aktiv' : 'Auswählen'}</button></li>)}</ul> : <p>Keine passenden deaktivierten Einträge.</p>}
        <div className="flex gap-2"><button className="border rounded px-3 py-1.5" disabled={userBusy || usersPage <= 1} onClick={() => setUsersPage(page => page - 1)}>Zurück</button><span className="self-center">Seite {usersPage}</span><button className="border rounded px-3 py-1.5" disabled={userBusy || !usersHasMore} onClick={() => setUsersPage(page => page + 1)}>Weiter</button></div>
      </div>

      <div className="bg-white border rounded-lg p-4 space-y-4"><h2 className="text-lg font-semibold">Neue Einladung</h2>
        {!target && <p>Wähle links eine Person aus. Der Server prüft erneut, ob sie im eigenen Mandanten deaktiviert, unverknüpft und ohne privilegierte Zuweisungen ist.</p>}
        {targetBusy && <p role="status">Einladungsziel wird unabhängig geprüft …</p>}
        {target && <form className="space-y-3" onSubmit={event => void createInvitation(event)}>
          <p>Ausgewählt: <strong>{target.username}</strong> · Version {target.revision}</p>
          <label className="block">Anmeldename<input className="block border rounded p-2 w-full" required minLength={3} maxLength={254} value={loginName} onChange={event => setLoginName(event.target.value)} /></label>
          <fieldset className="space-y-2"><legend className="font-medium">Gruppen für den Eintritt (optional)</legend>
            <p className="text-sm text-gray-600">Die ausgewählten Gruppen werden vor der Einladung mit dem deaktivierten Verzeichniseintrag verknüpft. Gruppenrichtlinien können Apps freigeben; verknüpfte Lizenzgruppen vergeben Plätze aus ihrem Pool, sobald das Konto aktiv ist und der Lizenzabgleich läuft.</p>
            <label className="block">Gruppen suchen<input className="block border rounded p-2 w-full" value={groupSearch} onChange={event => setGroupSearch(event.target.value)} /></label>
            {groupsLoading && <p role="status">Eigene Gruppen werden geladen …</p>}
            {groupError && <p role="alert" className="text-amber-700">{groupError}</p>}
            {!groupError && groups.filter(group => group.name.toLocaleLowerCase().includes(groupSearch.trim().toLocaleLowerCase())).slice(0, 100).map(group => <label key={group.id} className="flex gap-2 items-start"><input type="checkbox" checked={groupIds.includes(group.id)} onChange={event => setGroupIds(current => event.target.checked ? [...current, group.id] : current.filter(id => id !== group.id))} disabled={busy} /><span>{group.name}{group.members.includes(target.id) ? ' · bereits Mitglied' : ''}</span></label>)}
            {!groupError && groups.filter(group => group.name.toLocaleLowerCase().includes(groupSearch.trim().toLocaleLowerCase())).length > 100 && <p className="text-sm text-gray-600">Bitte die Suche weiter eingrenzen (maximal 100 Treffer werden angezeigt).</p>}
            {!groupsLoading && !groupError && groups.length === 0 && <p>Keine eigenen Gruppen verfügbar.</p>}
          </fieldset>
          <label className="block">Gültigkeit<select className="block border rounded p-2 w-full" value={durationHours} onChange={event => setDurationHours(Number(event.target.value))}>{[1, 4, 12, 24, 48, 72].map(value => <option key={value} value={value}>{value} Stunden</option>)}</select></label>
          <label className="block">Grund<input className="block border rounded p-2 w-full" minLength={10} maxLength={500} required value={reason} onChange={event => setReason(event.target.value)} /></label>
          <label className="flex gap-3"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} disabled={busy} /><span>Ich bestätige die Einladung und die ausgewählten Gruppenmitgliedschaften für den Eintrag.</span></label>
          <div className="flex gap-2"><button className="bg-blue-600 text-white rounded px-4 py-2 disabled:opacity-50" disabled={busy || !confirmed || reason.trim().length < 10}>{busy ? 'Wird erstellt …' : 'Einladung erstellen'}</button><button type="button" className="border rounded px-4 py-2" disabled={busy} onClick={() => { setTarget(null); setInvitationId(''); }}>Abbrechen</button></div>
        </form>}
      </div>
    </section>

    <section className="bg-white border rounded-lg p-4 space-y-4"><div className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-lg font-semibold">Eigene Einladungen</h2><button className="border rounded px-3 py-1.5" disabled={busy} onClick={() => void loadInvitations(invitationPage)}>Aktualisieren</button></div>
      {invitations.length ? <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="text-left border-b"><th className="p-2">Anmeldename</th><th className="p-2">Status</th><th className="p-2">Gültig bis</th><th className="p-2">Aktion</th></tr></thead><tbody>{invitations.map(invitation => <tr key={invitation.id} className="border-b"><td className="p-2">{invitation.loginName}</td><td className="p-2">{({ pending: 'Ausstehend', credential_pending: 'Passwort gesetzt', accepted: 'Angenommen', revoked: 'Widerrufen' })[invitation.status]}</td><td className="p-2">{new Date(invitation.expiresAt).toLocaleString('de-CH')}</td><td className="p-2">{['pending', 'credential_pending'].includes(invitation.status) ? <button className="underline text-red-700" disabled={busy} onClick={() => { setRevokeTarget(invitation); setRevokeReason(''); setRevokeConfirmed(false); }}>Widerrufen</button> : '—'}</td></tr>)}</tbody></table></div> : <p>Noch keine Einladungen auf dieser Seite.</p>}
      <div className="flex gap-2"><button className="border rounded px-3 py-1.5" disabled={busy || invitationPage <= 1} onClick={() => void loadInvitations(invitationPage - 1)}>Zurück</button><span className="self-center">Seite {invitationPage}</span><button className="border rounded px-3 py-1.5" disabled={busy || !invitationHasMore} onClick={() => void loadInvitations(invitationPage + 1)}>Weiter</button></div>
    </section>

    {revokeTarget && <section className="bg-red-50 border border-red-300 rounded-lg p-4 space-y-3"><h2 className="font-semibold">Einladung widerrufen: {revokeTarget.loginName}</h2><form className="space-y-3" onSubmit={event => void revokeInvitation(event)}><label className="block">Grund<input className="block border rounded p-2 w-full" required minLength={10} maxLength={500} value={revokeReason} onChange={event => setRevokeReason(event.target.value)} /></label><label className="flex gap-3"><input type="checkbox" checked={revokeConfirmed} onChange={event => setRevokeConfirmed(event.target.checked)} /><span>Ich bestätige den Widerruf dieser Einladung. Eine unveränderte Teilaufnahme wird zurückgenommen.</span></label><div className="flex gap-2"><button className="bg-red-700 text-white rounded px-4 py-2" disabled={busy || !revokeConfirmed || revokeReason.trim().length < 10}>Einladung widerrufen</button><button type="button" className="border rounded px-4 py-2" disabled={busy} onClick={() => setRevokeTarget(null)}>Abbrechen</button></div></form></section>}
    <p className="text-sm text-gray-600">Graph akzeptiert die E-Mail asynchron. Den Einmal-Link kannst du zusätzlich kopieren. Bei Gruppen mit unabhängiger Mitgliedschaftsprüfung werden App-Zugriffe und Lizenzplätze erst nach deren Freigabe wirksam.</p>
  </main>;
}
