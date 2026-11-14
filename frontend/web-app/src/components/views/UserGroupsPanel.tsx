'use client';

import React, { useEffect, useRef, useState } from 'react';
import { DataTable } from '@/components/ui/DataTable';
import { DirectoryUser, directoryError, userName } from '@/lib/directoryUsers';
import { DirectoryGroup, directoryGroups } from '@/lib/directoryGroups';
import { listUserGroups, UserGroup, UserGroupPage } from '@/lib/userGroups';
import { ensureSession } from '@/lib/auth';
import { DirectoryConfirmation } from './UserDetailPanel';

export default function UserGroupsPanel({ user, permissions, actorUserId, onDenied }: {
  user: DirectoryUser; permissions: string[]; actorUserId: string | null; onDenied: () => void;
}) {
  const generation = useRef(0);
  const [data, setData] = useState<UserGroupPage | null>(null);
  const [page, setPage] = useState(1); const [search, setSearch] = useState(''); const [draft, setDraft] = useState('');
  const [membership, setMembership] = useState<'member' | 'available'>('member'); const [reload, setReload] = useState(0);
  const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [notice, setNotice] = useState('');
  const [pending, setPending] = useState<{ group: DirectoryGroup; kind: 'add' | 'remove' } | null>(null);
  const read = permissions.includes('users.read') && permissions.includes('groups.read');
  const manage = read && permissions.includes('groups.members.manage');
  const permissionKey = permissions.join(' ');

  useEffect(() => {
    const expected = ++generation.current; const controller = new AbortController();
    setData(null); setPending(null); setBusy(false); setError('');
    if (read) listUserGroups(user.id, page, search, membership, controller.signal).then(result => {
      if (generation.current === expected) setData(result);
    }).catch(failure => {
      if (generation.current !== expected) return;
      setError(directoryError(failure));
      if ([401, 403].includes(failure?.response?.status)) onDenied();
    });
    const invalidate = () => { generation.current += 1; controller.abort(); setData(null); setPending(null); setBusy(false); setError('Die Sitzung ist nicht mehr gültig. Bitte erneut anmelden.'); };
    window.addEventListener('od:session-error', invalidate);
    return () => { generation.current += 1; controller.abort(); window.removeEventListener('od:session-error', invalidate); };
  }, [user.id, actorUserId, permissionKey, page, search, membership, reload]);

  const fail = (failure: any, expected: number) => {
    if (generation.current !== expected) return;
    setError(directoryError(failure)); setData(null); setPending(null);
    if ([401, 403].includes(failure?.response?.status)) onDenied();
  };
  const prepare = async (entry: UserGroup) => {
    if (!manage || busy || error || entry.membership?.source === 'rule') return;
    const expected = generation.current; setBusy(true); setNotice('');
    try {
      const snapshot = await directoryGroups.get(entry.id);
      if (generation.current !== expected) return;
      if (snapshot.revision !== entry.revision || snapshot.members.includes(user.id) !== (membership === 'member')) throw { response: { status: 412 } };
      setPending({ group: snapshot, kind: membership === 'member' ? 'remove' : 'add' });
    } catch (failure) { fail(failure, expected); }
    finally { if (generation.current === expected) setBusy(false); }
  };
  const perform = async () => {
    if (!pending || !manage || busy || error) return;
    const expected = generation.current; const intent = pending; setBusy(true);
    try {
      if (intent.kind === 'add') {
        const result = await directoryGroups.add(intent.group, user.id);
        if (generation.current !== expected) return;
        setNotice(result.membershipReview && !result.membershipReview.effective
          ? 'Mitgliedschaft gespeichert. Sie ist erst nach der erforderlichen Zugriffsprüfung wirksam.'
          : 'Gruppenmitgliedschaft gespeichert.');
      } else {
        await directoryGroups.removeMember(intent.group, user.id);
        if (generation.current !== expected) return;
        setNotice('Gruppenmitgliedschaft entfernt.');
      }
      setPending(null); setMembership('member'); setPage(1); setSearch(''); setDraft(''); setReload(value => value + 1);
      if (user.id === actorUserId) void ensureSession(true).catch(() => {});
    } catch (failure) { fail(failure, expected); }
    finally { if (generation.current === expected) setBusy(false); }
  };

  if (!read) return <p>Keine Berechtigung zum Lesen dieser Gruppenmitgliedschaften.</p>;
  return <section className="space-y-4" aria-label="Gruppenmitgliedschaften">
    <div className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-lg font-semibold">Gruppen für {userName(user)}</h2>
      <div className="flex flex-wrap gap-2">{manage && <button className="fluent-btn-primary" disabled={busy || !!pending} onClick={() => { setMembership(value => value === 'member' ? 'available' : 'member'); setPage(1); setSearch(''); setDraft(''); setNotice(''); }}>{membership === 'member' ? 'Gruppe hinzufügen' : 'Mitgliedschaften anzeigen'}</button>}
        <button className="fluent-btn-secondary" disabled={busy || !!pending} onClick={() => setReload(value => value + 1)}>Gruppen neu laden</button></div>
    </div>
    <p className="text-sm text-[var(--text-secondary)]">{membership === 'member' ? 'Gespeicherte Mitgliedschaften mit ihrem aktuellen Freigabestatus. Gruppenregeln werden an ihrer Quelle verwaltet.' : 'Eigene Gruppen, denen dieser Benutzer noch nicht angehört.'}</p>
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
    <form className="flex flex-wrap items-end gap-2" onSubmit={event => { event.preventDefault(); setPage(1); setSearch(draft.trim()); setReload(value => value + 1); }}>
      <label className="text-sm">Gruppen suchen<input className="input-apple block" maxLength={255} disabled={busy || !!pending} value={draft} onChange={event => setDraft(event.target.value)} /></label>
      <button className="fluent-btn-secondary" disabled={busy || !!pending}>Suchen</button>
    </form>
    {data && !error ? <>
      <DataTable<UserGroup> label={membership === 'member' ? 'Gruppenmitgliedschaften' : 'Verfügbare Gruppen'} rows={data.groups} getRowId={entry => entry.id}
        emptyMessage={membership === 'member' ? 'Keine Gruppenmitgliedschaften gefunden.' : 'Keine verfügbaren Gruppen gefunden.'} columns={[
          { key: 'name', header: 'Gruppe', render: entry => <span className="font-medium">{entry.name}</span> },
          { key: 'source', header: 'Zuweisung', render: entry => <span className="whitespace-nowrap">{entry.membership ? entry.membership.source === 'rule' ? 'Gruppenregel' : 'Manuell' : 'Noch nicht zugewiesen'}</span> },
          { key: 'effective', header: 'Status', render: entry => <span className="whitespace-nowrap">{entry.membership ? entry.membership.effective ? 'Wirksam' : 'Nicht wirksam' : '—'}</span> },
          ...(manage ? [{ key: 'actions', header: 'Aktion', render: (entry: UserGroup) => entry.membership?.source === 'rule'
            ? <a className="text-blue-600 underline" href="/usergroups">Regel verwalten</a>
            : <button className="fluent-btn-secondary whitespace-nowrap" disabled={busy || !!pending} onClick={() => void prepare(entry)} aria-label={`${membership === 'member' ? 'Aus Gruppe entfernen' : 'Zu Gruppe hinzufügen'}: ${entry.name}`}>{membership === 'member' ? 'Entfernen' : 'Hinzufügen'}</button> }] : []),
        ]} />
      <nav aria-label="Gruppenseiten" className="flex flex-wrap items-center gap-3 text-sm">
        <button className="fluent-btn-secondary" disabled={busy || !!pending || page <= 1} onClick={() => setPage(value => value - 1)}>Zurück</button>
        <span>Seite {data.page} von {Math.max(1, Math.ceil(data.total / 25))} · {data.total} Gruppen</span>
        <button className="fluent-btn-secondary" disabled={busy || !!pending || page * 25 >= data.total} onClick={() => setPage(value => value + 1)}>Weiter</button>
      </nav>
    </> : !error && <p role="status">Gruppenmitgliedschaften werden geladen …</p>}
    {pending && manage && <DirectoryConfirmation title={pending.kind === 'add' ? 'Gruppenmitgliedschaft hinzufügen' : 'Gruppenmitgliedschaft entfernen'} busy={busy} error={error} onClose={() => setPending(null)} onConfirm={() => void perform()}>
      <p>{userName(user)} · <span className="break-all">{user.id}</span></p><p className="mt-3">{pending.group.name} · Version {pending.group.revision}</p>
      <p className="mt-3">{pending.kind === 'add' ? 'Die Mitgliedschaft wird im eigenen Verzeichnis angelegt. Eine vorgeschriebene Zugriffsprüfung bleibt erforderlich.' : 'Genau die aktuell bestätigte Mitgliedschaft wird entfernt. Anwendungszugriffe können dadurch enden.'}</p>
      <p className="mt-3">Herstellerlizenzen und externe Konten werden dadurch nicht automatisch provisioniert oder entfernt.</p>
      {user.id === actorUserId && <p className="mt-3 text-amber-600">Dies ist dein eigenes Konto. Dein Zugriff kann durch die Änderung enden.</p>}
    </DirectoryConfirmation>}
  </section>;
}
