'use client';

import React, { useEffect, useRef, useState } from 'react';
import { DirectoryAccess, DirectoryUser, directoryUsers, userName, directoryError } from '@/lib/directoryUsers';
import { directoryOuMemberships, OuMember, OuMemberPage, ouMembershipError } from '@/lib/directoryOuMemberships';
import { DirectoryConfirmation } from '@/components/views/UserDetailPanel';

export default function OrganizationUnitMembers({ ouId, access, onClose }: { ouId: string; access: DirectoryAccess; onClose: () => void }) {
  const [data, setData] = useState<OuMemberPage | null>(null); const [page, setPage] = useState(1); const [loading, setLoading] = useState(true); const [busy, setBusy] = useState(false);
  const [error, setError] = useState(''); const [notice, setNotice] = useState(''); const [search, setSearch] = useState(''); const [candidates, setCandidates] = useState<DirectoryUser[]>([]);
  const [searchBusy, setSearchBusy] = useState(false); const [searchError, setSearchError] = useState(''); const [selected, setSelected] = useState(''); const [removing, setRemoving] = useState<OuMember | null>(null);
  const sequence = useRef(0); const searchSequence = useRef(0); const operationSequence = useRef(0);
  const supported = !access.demoMode && !!access.userId && access.directoryOuMembershipProtocol === 1 && access.permissions.includes('ous.read');
  const canManage = supported && access.permissions.includes('ous.members.manage'); const canSearch = canManage && access.permissions.includes('users.read');
  async function load(signal?: AbortSignal) {
    const epoch = ++sequence.current; setData(null); setError(''); setLoading(true); setRemoving(null); setSelected(''); setSearch(''); setCandidates([]);
    try { const result = await directoryOuMemberships.list(ouId, page, signal); if (epoch !== sequence.current) return; if (result.actorUserId !== access.userId) throw new Error('Zuordnungsakteur geändert'); setData(result); }
    catch (failure) { if (epoch === sequence.current) setError(ouMembershipError(failure)); }
    finally { if (epoch === sequence.current) setLoading(false); }
  }
  useEffect(() => {
    const controller = new AbortController(); operationSequence.current++; setBusy(false); setNotice(''); if (supported) void load(controller.signal); else { sequence.current++; setData(null); setLoading(false); }
    const invalid = () => { sequence.current++; searchSequence.current++; operationSequence.current++; controller.abort(); setData(null); setCandidates([]); setSelected(''); setRemoving(null); setBusy(false); setLoading(false); setNotice(''); setError('Die Sitzung hat sich geändert. Bitte erneut anmelden und neu laden.'); };
    window.addEventListener('od:session-error', invalid); return () => { sequence.current++; searchSequence.current++; operationSequence.current++; controller.abort(); window.removeEventListener('od:session-error', invalid); };
  }, [access, ouId, page, supported]);
  useEffect(() => {
    const controller = new AbortController(); const epoch = ++searchSequence.current; setCandidates([]); setSearchError(''); setSearchBusy(false);
    if (!canSearch || !data || !search.trim() || busy) return () => { searchSequence.current++; controller.abort(); };
    setSearchBusy(true); const timer = window.setTimeout(() => {
      directoryUsers.list(1, search.trim(), '', controller.signal).then(result => { if (epoch === searchSequence.current) setCandidates(result.users); })
        .catch(failure => { if (epoch === searchSequence.current) { setSelected(''); setSearchError(directoryError(failure)); } })
        .finally(() => { if (epoch === searchSequence.current) setSearchBusy(false); });
    }, 200);
    return () => { searchSequence.current++; window.clearTimeout(timer); controller.abort(); };
  }, [canSearch, data, search, busy]);
  async function save(event: React.FormEvent) {
    event.preventDefault(); if (!canManage || !data || !selected || busy || error) return; const epoch = sequence.current; const operation = ++operationSequence.current; setBusy(true); setNotice('');
    try {
      await directoryOuMemberships.add(data.unit, selected.trim().toLowerCase()); if (epoch !== sequence.current) return;
      setNotice('OU-Zuordnung gespeichert. Der aktuelle Bestand wird neu geladen.'); await load();
    } catch (failure) { if (epoch === sequence.current) { setData(null); setCandidates([]); setSelected(''); setError(ouMembershipError(failure)); } }
    finally { if (operation === operationSequence.current) setBusy(false); }
  }
  async function remove() {
    if (!canManage || !data || !removing || busy || error) return; const epoch = sequence.current; const operation = ++operationSequence.current; setBusy(true); setNotice('');
    try {
      await directoryOuMemberships.remove(data.unit, removing); if (epoch !== sequence.current) return;
      setNotice('OU-Zuordnung entfernt. Andere Mitgliedschaften und Lizenzen bleiben unverändert.'); setRemoving(null); await load();
    } catch (failure) { if (epoch === sequence.current) { setData(null); setRemoving(null); setError(ouMembershipError(failure)); } }
    finally { if (operation === operationSequence.current) setBusy(false); }
  }
  return <section aria-label="OU-Mitgliedschaften" className="space-y-5 p-4" style={{ color: 'var(--text-primary)' }}>
    <header className="flex flex-wrap justify-between gap-3"><h2 className="text-xl font-semibold">{data ? `Mitglieder von ${data.unit.name}` : 'OU-Mitgliedschaften'}</h2><button type="button" disabled={busy} onClick={onClose} className="border rounded px-4 py-2">Zur Organisationsstruktur</button></header>
    <p>Eine Person darf mehreren Einheiten angehören. Die Zuordnung verändert weder das Department-Freitextfeld noch Zugangsdaten, Rollen, Gruppen oder Lizenzen.</p>
    {!supported && <p role="alert">Mandantengebundene OU-Zuordnungen sind nicht verfügbar.</p>}
    {loading && <p role="status">Zuordnungen werden geladen …</p>}{error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
    {supported && <button type="button" disabled={loading || busy} onClick={() => { setNotice(''); void load(); }} className="border rounded px-4 py-2">Zuordnungen neu laden</button>}
    {data && !error && <>
      <p>{data.total} bestätigte Zuordnungen · OU-Version {data.unit.revision} · Seite {data.page}</p>
      {!data.members.length ? <p>Keine Zuordnungen auf dieser Seite.</p> : <ul className="space-y-3">{data.members.map(link => <li key={link.id} className="rounded border p-3 space-y-2">
        {link.profile && <><strong>{link.profile.displayName || link.profile.username}</strong><p>{link.profile.email}</p></>}
        <p className="text-xs break-all">Benutzer-ID: {link.userId}</p><p className="text-xs break-all">Zuordnungs-ID: {link.id}</p>
        {canManage && <button type="button" disabled={busy} onClick={() => setRemoving(link)} aria-label={`OU-Zuordnung ${link.profile?.displayName || link.profile?.username || link.userId} entfernen`} className="border rounded px-3 py-1">Zuordnung entfernen</button>}
      </li>)}</ul>}
      <div className="flex gap-3"><button type="button" disabled={busy || loading || page === 1} onClick={() => setPage(value => value - 1)} className="border rounded px-3 py-1">Vorherige Zuordnungsseite</button><button type="button" disabled={busy || loading || page * 25 >= data.total} onClick={() => setPage(value => value + 1)} className="border rounded px-3 py-1">Nächste Zuordnungsseite</button></div>
      {canManage && <form onSubmit={save} className="space-y-3 border-t pt-4">
        <h3 className="font-semibold">Mitarbeitende zuordnen</h3>
        {canSearch ? <>
          <label htmlFor="ou-member-search" className="block">Mitarbeitende suchen<input id="ou-member-search" maxLength={255} value={search} disabled={busy} onChange={event => { setSearch(event.target.value); setSelected(''); }} className="block w-full border rounded p-2 bg-transparent" /></label>
          <p className="text-sm">Name, Benutzername oder E-Mail eingeben. Es werden höchstens 25 eigene Treffer angezeigt, auch gesperrte Verzeichniseinträge.</p>
          {searchBusy && <p role="status">Mitarbeitende werden gesucht …</p>}{searchError && <p role="alert">{searchError}</p>}
          {!searchBusy && !!search.trim() && !searchError && !candidates.length && <p>Keine passenden Mitarbeitenden.</p>}
          <ul className="space-y-2">{candidates.map(candidate => <li key={candidate.id}><button type="button" disabled={busy || data.members.some(link => link.userId === candidate.id)} aria-pressed={selected === candidate.id} aria-label={`Mitarbeitenden ${userName(candidate)} auswählen`} onClick={() => setSelected(candidate.id)} className="border rounded px-3 py-2 text-left w-full"><strong>{userName(candidate)}</strong> · {candidate.email} · {candidate.enabled ? 'Freigegeben' : 'Gesperrt'}</button></li>)}</ul>
        </> : <label htmlFor="ou-member-id" className="block">Kanonische Benutzer-ID<input id="ou-member-id" required minLength={36} maxLength={36} value={selected} disabled={busy} onChange={event => setSelected(event.target.value)} className="block w-full border rounded p-2 bg-transparent" /></label>}
        {selected && <p className="text-xs break-all">Ausgewählte Benutzer-ID: {selected}</p>}<button disabled={busy || !selected || data.total >= 10000} className="border rounded px-4 py-2">{busy ? 'Wird gespeichert …' : 'Zuordnung hinzufügen'}</button>
      </form>}
    </>}
    {supported && canManage && data && removing && <DirectoryConfirmation title="OU-Zuordnung entfernen" busy={busy} error={error} onClose={() => { if (!busy) setRemoving(null); }} onConfirm={() => void remove()}>
      <p>{removing.profile?.displayName || removing.profile?.username || removing.userId}</p><p className="break-all">Zuordnungs-ID: {removing.id}</p><p>Nur diese genaue Zuordnung wird entfernt. Andere OU-Zugehörigkeiten und separat verwaltete Berechtigungen/Lizenzen werden nicht automatisch entzogen.</p>
    </DirectoryConfirmation>}
  </section>;
}
