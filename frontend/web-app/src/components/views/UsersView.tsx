'use client';

import React, { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import ABMShell from '@/components/layout/ABMShell';
import { useIdentityAccess } from '@/hooks/useIdentityAccess';
import { directoryUsers, DirectoryUser, directoryError } from '@/lib/directoryUsers';
import { ensureSession } from '@/lib/auth';
import UserListColumn from './UserListColumn';
import UserDetailPanel, { DirectoryConfirmation } from './UserDetailPanel';
import DirectoryUserEditor from './DirectoryUserEditor';

export default function UsersView() {
  const { access, can, unavailable, reload: reloadAccess } = useIdentityAccess();
  const [users, setUsers] = useState<DirectoryUser[]>([]); const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1); const [search, setSearch] = useState(''); const [enabled, setEnabled] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null); const [selected, setSelected] = useState<DirectoryUser | null>(null);
  const [loading, setLoading] = useState(false); const [listError, setListError] = useState(''); const [detailError, setDetailError] = useState('');
  const [creating, setCreating] = useState(false); const [reload, setReload] = useState(0);
  const [createdReceipt, setCreatedReceipt] = useState<DirectoryUser | null>(null);
  const [knownId, setKnownId] = useState(''); const [resetId, setResetId] = useState(''); const [resetBusy, setResetBusy] = useState(false); const [resetError, setResetError] = useState('');
  const refresh = () => setReload(value => value + 1);
  const choose = (id: string | null) => { setSelected(null); setDetailError(''); setSelectedId(id); };
  useEffect(() => {
    if (!access || !access.permissions.includes('users.read')) { setUsers([]); setSelected(null); return; }
    const controller = new AbortController(); let active = true;
    setLoading(true); setListError(''); setUsers([]);
    const timer = window.setTimeout(() => {
      directoryUsers.list(page, search, enabled, controller.signal).then(result => {
        if (active) { setUsers(result.users); setTotal(result.total); }
      }).catch(error => { if (active) { setListError(directoryError(error)); setSelected(null); setSelectedId(null); } })
        .finally(() => { if (active) setLoading(false); });
    }, 150);
    return () => { active = false; controller.abort(); window.clearTimeout(timer); };
  }, [access, page, search, enabled, reload]);
  useEffect(() => {
    setSelected(null); setDetailError('');
    if (!selectedId || !access?.permissions.includes('users.read')) return;
    const controller = new AbortController(); let active = true;
    directoryUsers.get(selectedId, controller.signal).then(user => { if (active) setSelected(user); })
      .catch(error => { if (active) setDetailError(directoryError(error)); });
    return () => { active = false; controller.abort(); };
  }, [access, selectedId, reload]);

  if (unavailable) return <section className="p-8" role="alert">Verzeichnisberechtigungen nicht verfügbar. Es werden keine Beispieldaten angezeigt. <button onClick={reloadAccess}>Erneut prüfen</button></section>;
  if (!access) return <p className="p-8" role="status">Verzeichnisberechtigungen werden geprüft …</p>;
  const resetOnly = !can('users.read') && can('users.sessions.invalidate');
  const details = <div className="flex flex-col flex-1 min-h-0" style={{ background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)' }}><div className="p-3 text-sm border-b border-white/10">Quelle: kanonischer Verzeichnisdienst{access.demoMode ? ' · Expliziter Demo-Modus' : ''}</div>
    {detailError ? <p className="p-8" role="alert">{detailError} <button onClick={refresh}>Details neu laden</button></p> :
      <UserDetailPanel key={selectedId || 'none'} user={selected} permissions={access.permissions} actorUserId={access.userId} onReload={refresh} onDenied={reloadAccess}
        onChanged={(updated, expectedId) => {
          setSelected(current => current?.id === expectedId ? updated : current);
          if (!updated) setSelectedId(current => current === expectedId ? null : current);
          refresh();
        }} />}
  </div>;
  return <>
    {can('users.read') ? <ABMShell showListColumn listColumn={<UserListColumn users={users} total={total} page={page} selectedId={selectedId} loading={loading} error={listError}
      search={search} enabled={enabled} onSelect={choose} onReload={refresh}
      onSearch={value => { setSearch(value); setPage(1); choose(null); }} onFilter={value => { setEnabled(value); setPage(1); choose(null); }}
      onPage={value => { setPage(value); choose(null); }} onCreateNew={can('users.create') && !loading && !listError ? () => setCreating(true) : undefined} />} detailPanel={details} /> :
      <section className="p-8 space-y-5"><h1 className="text-xl">Benutzerverwaltung</h1><p>Keine Berechtigung zum Lesen der Benutzerliste.</p>
        {can('users.create') && <button onClick={() => setCreating(true)}>Verzeichniseintrag erstellen</button>}
        {createdReceipt && can('users.create') && <section aria-label="Erstellter Verzeichniseintrag"><h2>Gesperrt erstellt: {createdReceipt.username}</h2><p className="break-all">Verzeichnis-ID: {createdReceipt.id}</p><p>Zugangsdaten und Anmelde-Verknüpfung sind nicht provisioniert.</p></section>}
        {resetOnly && <form className="space-y-3" onSubmit={event => { event.preventDefault(); setResetId(knownId); setResetError(''); }}>
          <p>Der Sicherheitsreset benötigt nur eine bekannte kanonische UUID; Benutzerprofile werden nicht geladen.</p>
          <label className="block">Kanonische Benutzer-ID<input className="block border rounded p-2 bg-transparent" required minLength={36} maxLength={36} value={knownId} onChange={event => setKnownId(event.target.value)} /></label>
          <button type="submit">Sicherheitsreset vorbereiten</button>
        </form>}
      </section>}
    {creating && can('users.create') && <DirectoryUserEditor onClose={() => setCreating(false)} onSaved={user => {
      setCreating(false); setCreatedReceipt(user); setPage(1); setSearch(''); setEnabled(''); choose(can('users.read') ? user.id : null); refresh();
      toast.success('Verzeichniseintrag gesperrt erstellt. Zugangsdaten werden nicht automatisch provisioniert.');
    }} />}
    {resetId && resetOnly && <DirectoryConfirmation title="Sicherheitsreset bestätigen" busy={resetBusy} error={resetError}
      onClose={() => setResetId('')} onConfirm={async () => {
        if (resetBusy || resetError) return; setResetBusy(true);
        try {
          await directoryUsers.invalidate(resetId); setResetId(''); toast.success('Sicherheitsreset bestätigt.');
          if (resetId === access.userId) void ensureSession(true).catch(() => {});
        }
        catch (error) { setResetError(directoryError(error)); }
        finally { setResetBusy(false); }
      }}><p>Alle bisherigen Anmeldeberechtigungen für <span className="break-all">{resetId}</span> werden ungültig. Passwort und Rollen bleiben unverändert.</p></DirectoryConfirmation>}
  </>;
}
