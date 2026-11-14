'use client';

import React, { useEffect, useRef, useState } from 'react';
import { ViewShell } from '@/components/ui/ViewShell';
import DeviceInventoryEditor, { deviceClassLabels as classLabels, devicePlatformLabels as platformLabels, deviceOwnershipLabels as ownershipLabels, deviceLifecycleLabels as lifecycleLabels } from './DeviceInventoryEditor';
import { DataTable } from '@/components/ui/DataTable';
import { Device, DeviceCapabilities, DeviceHistoryPage, DeviceInput, DeviceInventoryClient, DevicePage, DeviceFilters, devicePlatforms, deviceLifecycles, deviceInventoryError } from '@/lib/deviceInventory';
import { UserPage, userName } from '@/lib/directoryUsers';
import { DirectoryConfirmation } from './UserDetailPanel';
import DeviceAgentPanel from './DeviceAgentPanel';

const eventLabels = { 'device.registered': 'Gerät erfasst', 'device.assigned': 'Benutzer zugewiesen', 'device.assignment.released': 'Zuweisung aufgehoben', 'device.updated': 'Stammdaten geändert', 'device.lifecycle.changed': 'Lebenszyklus geändert' };

function Pagination({ page, total, label, disabled, onPage }: { page: number; total: number; label: string; disabled?: boolean; onPage: (page: number) => void }) {
  return <nav aria-label={label + 'n'} className="flex flex-wrap items-center gap-4 py-3 text-sm">
    <button className="fluent-btn-secondary" aria-label={'Vorherige ' + label} disabled={disabled || page <= 1} onClick={() => onPage(page - 1)}>Zurück</button>
    <span>Seite {page} von {Math.max(1, Math.ceil(total / 25))} · {total} Einträge</span>
    <button className="fluent-btn-secondary" aria-label={'Nächste ' + label} disabled={disabled || page * 25 >= total} onClick={() => onPage(page + 1)}>Weiter</button>
  </nav>;
}

export default function DeviceInventoryView({ createRequested = false, onCreateHandled, selectedDeviceId }: { selectedDeviceId?: string | null; createRequested?: boolean; onCreateHandled?: () => void } = {}) {
  const client = useRef<DeviceInventoryClient | null>(null);
  const generation = useRef(0);
  const [reload, setReload] = useState(0);
  const [access, setAccess] = useState<DeviceCapabilities | null>(null);
  const [devices, setDevices] = useState<DevicePage | null>(null);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [searchDraft, setSearchDraft] = useState('');
  const [listVersion, setListVersion] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<Device | null>(null);
  const [history, setHistory] = useState<DeviceHistoryPage | null>(null);
  const [historyPage, setHistoryPage] = useState(1);
  const [historyVersion, setHistoryVersion] = useState(0);
  const [users, setUsers] = useState<UserPage | null>(null);
  const [picker, setPicker] = useState<'loading' | 'directory' | 'uuid'>('loading');
  const [userPage, setUserPage] = useState(1);
  const [userSearch, setUserSearch] = useState('');
  const [userSearchDraft, setUserSearchDraft] = useState('');
  const [targetUserId, setTargetUserId] = useState('');
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Device | null>(null);
  const [filters, setFilters] = useState<DeviceFilters>({});
  const [lifecycleChange, setLifecycleChange] = useState<{ device: Device; lifecycle: 'available' | 'maintenance' | 'retired' } | null>(null);
  const [lifecycleReason, setLifecycleReason] = useState('');
  const [pending, setPending] = useState<{ device: Device; userId: string | null } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [needsMfa, setNeedsMfa] = useState(false);
  const [notice, setNotice] = useState('');
  const canRead = access?.permissions.includes('devices.inventory.read');
  const canCreate = canRead && access?.permissions.includes('devices.inventory.create');
  const canAssign = canRead && access?.permissions.includes('devices.inventory.assign');
  const enhanced = access?.inventoryProtocol === 2;
  const filter = (key: keyof DeviceFilters, value: string) => { clearSelection(); setPage(1); setFilters(previous => ({ ...previous, [key]: value || undefined })); };
  const beginLifecycle = (device: Device, lifecycle: 'available' | 'maintenance' | 'retired') => { setLifecycleReason(''); setLifecycleChange({ device, lifecycle }); };
  useEffect(() => {
    if (createRequested && canCreate && devices) { setCreating(true); onCreateHandled?.(); }
  }, [createRequested, canCreate, devices, onCreateHandled]);

  useEffect(() => {
    if (selectedDeviceId && canRead) setSelectedId(selectedDeviceId);
  }, [selectedDeviceId, canRead]);

  const clearSelection = () => {
    setEditing(null); setLifecycleChange(null); setSelectedId(null); setSelected(null); setHistory(null); setHistoryPage(1); setPending(null);
    setUsers(null); setPicker('loading'); setTargetUserId(''); setUserPage(1); setUserSearch(''); setUserSearchDraft('');
  };
  const fail = (failure: unknown, expected: number) => {
    if (generation.current !== expected) return;
    setNeedsMfa((failure as { response?: { status?: number } })?.response?.status === 428);
    generation.current += 1; client.current?.invalidate();
    setAccess(null); setDevices(null); clearSelection(); setCreating(false); setBusy(false); setNotice('');
    setError(deviceInventoryError(failure));
  };

  useEffect(() => {
    const current = new DeviceInventoryClient();
    client.current = current;
    const expected = ++generation.current;
    setAccess(null); setDevices(null); clearSelection(); setCreating(false); setBusy(false); setError(''); setNotice('');
    const onSessionError = () => fail({ response: { status: 401 } }, expected);
    window.addEventListener('od:session-error', onSessionError);
    current.reload().then(result => { if (generation.current === expected) setAccess(result); }).catch(failure => fail(failure, expected));
    return () => { generation.current += 1; current.dispose(); window.removeEventListener('od:session-error', onSessionError); };
  }, [reload]);

  useEffect(() => {
    if (!canRead) return;
    const controller = new AbortController();
    const expected = generation.current;
    let active = true;
    setDevices(null);
    client.current.list(page, search, controller.signal, filters).then(result => { if (active && generation.current === expected) setDevices(result); })
      .catch(failure => { if (active) fail(failure, expected); });
    return () => { active = false; controller.abort(); };
  }, [access, page, search, listVersion, filters]);

  useEffect(() => {
    if (!canRead || !selectedId) return;
    const controller = new AbortController();
    const expected = generation.current;
    let active = true;
    setSelected(null);
    client.current.get(selectedId, controller.signal).then(result => { if (active && generation.current === expected) setSelected(result); })
      .catch(failure => { if (active) fail(failure, expected); });
    return () => { active = false; controller.abort(); };
  }, [access, selectedId]);

  useEffect(() => {
    if (!canRead || !selectedId) return;
    const controller = new AbortController();
    const expected = generation.current;
    let active = true;
    setHistory(null);
    client.current.history(selectedId, historyPage, controller.signal).then(result => { if (active && generation.current === expected) setHistory(result); })
      .catch(failure => { if (active) fail(failure, expected); });
    return () => { active = false; controller.abort(); };
  }, [access, selectedId, historyPage, historyVersion]);

  useEffect(() => {
    if (!canAssign || !selected) return;
    const controller = new AbortController();
    const expected = generation.current;
    let active = true;
    setUsers(null); setPicker('loading'); setTargetUserId('');
    client.current.users(userPage, userSearch, controller.signal).then(result => {
      if (active && generation.current === expected) { setUsers(result); setPicker(result ? 'directory' : 'uuid'); }
    }).catch(failure => { if (active) fail(failure, expected); });
    return () => { active = false; controller.abort(); };
  }, [access, selected?.id, userPage, userSearch]);

  const assign = async (change: { device: Device; userId: string | null }) => {
    if (busy || !canAssign) return;
    const expected = generation.current;
    setBusy(true); setNotice('');
    try {
      const result = await client.current.assign(change.device, { userId: change.userId });
      if (generation.current !== expected) return;
      setSelected(result); setPending(null); setTargetUserId(''); setListVersion(value => value + 1);
      setDevices(current => current && ({ ...current, devices: current.devices.map(device => device.id === result.id ? result : device) }));
      setHistoryPage(1); setHistoryVersion(value => value + 1);
      setNotice(change.userId === null ? 'Zuweisung aufgehoben.' : 'Inventarzuweisung gespeichert.');
    } catch (failure) { fail(failure, expected); }
    finally { if (generation.current === expected) setBusy(false); }
  };

  const saved = (result: Device) => {
    setSelected(result); setDevices(current => current && ({ ...current, devices: current.devices.map(device => device.id === result.id ? result : device) }));
    setHistoryPage(1); setHistoryVersion(value => value + 1); setListVersion(value => value + 1);
  };
  const save = async (values: DeviceInput, reason: string) => {
    if (busy || !canCreate) return; const expected = generation.current; setBusy(true); setNotice('');
    try {
      const result = editing ? await client.current.update(editing, values, reason) : await client.current.create(values);
      if (generation.current !== expected) return;
      if (editing) saved(result); else { setPage(1); setListVersion(value => value + 1); }
      setNotice(editing ? 'Stammdaten gespeichert und protokolliert.' : `Gerät ${result.assetId} im Inventar erfasst.`); setEditing(null); setCreating(false);
    } catch (failure) { fail(failure, expected); }
    finally { if (generation.current === expected) setBusy(false); }
  };
  const changeLifecycle = async () => {
    if (busy || !canCreate || !lifecycleChange || lifecycleReason.trim().length < 10) return;
    const expected = generation.current; setBusy(true); setNotice('');
    try {
      const result = await client.current.lifecycle(lifecycleChange.device, lifecycleChange.lifecycle, lifecycleReason);
      if (generation.current !== expected) return; saved(result); setLifecycleChange(null); setNotice('Gerätestatus geändert und protokolliert.');
    } catch (failure) { fail(failure, expected); }
    finally { if (generation.current === expected) setBusy(false); }
  };
  const exportCsv = async () => {
    if (busy || !canRead || !enhanced) return; const expected = generation.current; setBusy(true); setNotice('');
    try {
      const blob = await client.current.exportCsv(search, filters); if (generation.current !== expected) return;
      const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = 'opendirectory-devices.csv'; document.body.appendChild(link); link.click(); link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000); setNotice('CSV-Export bereitgestellt.');
    } catch (failure) { fail(failure, expected); }
    finally { if (generation.current === expected) setBusy(false); }
  };

  return <ViewShell title="Geräteinventar" subtitle="Geräte erfassen und genau einem Benutzer zuordnen."
    primaryAction={canCreate && devices ? { label: 'Gerät erfassen', onClick: () => { setEditing(null); setCreating(true); setNotice(''); }, disabled: busy } : undefined}
    rightContent={canRead ? <a className="fluent-btn-secondary" href="/device-returns">Geräterückgaben öffnen</a> : undefined}
    actions={[{ label: 'CSV exportieren', onClick: () => void exportCsv(), disabled: busy || !enhanced || !devices }, { label: 'Neu laden', onClick: () => { generation.current += 1; client.current?.invalidate(); setReload(value => value + 1); }, disabled: busy }]}>
    <div className="space-y-5" style={{ color: 'var(--text-primary)' }}>
      <details className="rounded-lg border p-3 text-sm" style={{ borderColor: 'var(--border)' }}><summary className="cursor-pointer">Inventar und Geräteverwaltung</summary><p className="mt-2">Inventar erfassen, Personen zuweisen und Windows-, macOS- oder Linux-Geräte über den OpenDirectory-Agenten verbinden. Compliance bleibt bis zur Richtlinienprüfung unbekannt.</p></details>
      {error ? <div role="alert" className="rounded border border-red-500/40 p-4 space-y-3"><p>{error}</p><div className="flex gap-3">{needsMfa && <a className="fluent-btn-secondary" href="/mfa?returnTo=%2Fdevices">MFA einrichten</a>}<a className="fluent-btn-primary" href="/api/auth/oidc/login?returnTo=%2Fdevices">Erneut anmelden</a></div></div> : !access ? <p role="status">Geräteberechtigungen werden geprüft …</p> : !canRead ? <p role="status">Keine Berechtigung zum Lesen des Geräteinventars.</p> : <>
        {notice && !selected && <p role="status">{notice}</p>}
        <form className="flex flex-wrap items-end gap-3" onSubmit={event => { event.preventDefault(); clearSelection(); setPage(1); setSearch(searchDraft.trim()); setListVersion(value => value + 1); }}>
          <label className="text-sm">Geräte suchen<input className="mt-1 block rounded border p-2 bg-transparent" maxLength={200} value={searchDraft} disabled={busy} onChange={event => setSearchDraft(event.target.value)} placeholder="Inventarnummer, Seriennummer, Modell" /></label>
          <button className="fluent-btn-secondary" disabled={busy} type="submit">Suchen</button>
          <label className="text-sm">Plattform filtern<select className="input-apple" value={filters.platform || ''} disabled={busy || !enhanced} onChange={event => filter('platform', event.target.value)}><option value="">Alle Plattformen</option>{devicePlatforms.map(value => <option key={value} value={value}>{platformLabels[value]}</option>)}</select></label>
          <label className="text-sm">Status filtern<select className="input-apple" value={filters.lifecycle || ''} disabled={busy || !enhanced} onChange={event => filter('lifecycle', event.target.value)}><option value="">Alle Status</option>{deviceLifecycles.map(value => <option key={value} value={value}>{lifecycleLabels[value]}</option>)}</select></label>
          <label className="text-sm">Eigentum filtern<select className="input-apple" value={filters.ownership || ''} disabled={busy || !enhanced} onChange={event => filter('ownership', event.target.value)}><option value="">Alle Eigentumsarten</option>{Object.entries(ownershipLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
          <label className="text-sm">Sortierung<select className="input-apple" disabled={busy || !enhanced} value={(filters.sort || 'createdAt') + '-' + (filters.order || 'asc')} onChange={event => { const [sort, order] = event.target.value.split('-'); clearSelection(); setPage(1); setFilters(previous => ({ ...previous, sort: sort as DeviceFilters['sort'], order: order as DeviceFilters['order'] })); }}>
            <option value="createdAt-asc">Älteste zuerst</option><option value="createdAt-desc">Neueste zuerst</option><option value="updatedAt-desc">Zuletzt geändert</option><option value="assetId-asc">Inventarnummer A–Z</option><option value="assetId-desc">Inventarnummer Z–A</option>
          </select></label>
        </form>
        {devices ? <section aria-label="Geräteliste">
          <DataTable<Device> rows={devices.devices} getRowId={device => device.id} activeRowId={selectedId} emptyMessage="Keine Geräte gefunden." columns={[
            { key: 'assetId', header: 'Inventarnummer', render: device => <button className="text-blue-500 underline" disabled={busy} onClick={() => { if (selectedId === device.id) return; clearSelection(); setSelectedId(device.id); }}>{device.assetId}</button> },
            { key: 'serialNumber', header: 'Seriennummer' },
            { key: 'model', header: 'Gerät', render: device => <span className="inline-block min-w-[12rem]">{device.manufacturer} {device.model}</span> },
            { key: 'deviceClass', header: 'Geräteklasse', render: device => classLabels[device.deviceClass] },
            { key: 'platform', header: 'Plattform', render: device => platformLabels[device.platform] },
            { key: 'lifecycle', header: 'Zuordnung', render: device => lifecycleLabels[device.lifecycle] },
          ]} />
          <Pagination label="Geräteseite" page={devices.page} total={devices.total} disabled={busy} onPage={next => { clearSelection(); setPage(next); }} />
        </section> : <p role="status">Geräte werden geladen …</p>}
        {selectedId && !selected && <p role="status">Gerätedetails werden geladen …</p>}
        {selected && <article aria-label="Gerätedetails" className="rounded-lg border border-[var(--border)] p-5 space-y-5">
          <h2 className="text-lg font-semibold">{selected.assetId} · {selected.manufacturer} {selected.model}</h2>
          <div className="flex flex-wrap items-center gap-3">
            <span className="od-badge">{lifecycleLabels[selected.lifecycle]}</span>
            {enhanced && canCreate && <><button className="fluent-btn-secondary" disabled={busy} onClick={() => { setEditing(selected); setCreating(false); }}>Stammdaten bearbeiten</button>
              {!selected.assignedUserId && <>{selected.lifecycle !== 'maintenance' && <button className="fluent-btn-secondary" disabled={busy} onClick={() => beginLifecycle(selected, 'maintenance')}>In Wartung nehmen</button>}
                {selected.lifecycle !== 'retired' && <button className="fluent-btn-secondary" disabled={busy} onClick={() => beginLifecycle(selected, 'retired')}>Archivieren</button>}
                {['retired', 'maintenance'].includes(selected.lifecycle) && <button className="fluent-btn-secondary" disabled={busy} onClick={() => beginLifecycle(selected, 'available')}>Wieder bereitstellen</button>}</>}
            </>}
            <button className="fluent-btn-ghost" disabled={busy} onClick={clearSelection}>Details schließen</button>
          </div>
          {notice && <p role="status">{notice}</p>}
          <dl className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">{Object.entries({
            'Geräte-ID': selected.id, Seriennummer: selected.serialNumber, Geräteklasse: classLabels[selected.deviceClass],
            Plattform: platformLabels[selected.platform], Betriebssystemversion: selected.osVersion || '—', Eigentum: ownershipLabels[selected.ownership],
            Kaufdatum: selected.purchaseDate || '—', Garantieende: selected.warrantyEnd || '—', Beschreibung: selected.description || '—',
            Benutzerzuordnung: selected.assignedUserId || 'Nicht zugewiesen', 'Zuweisungs-ID': selected.assignmentId || '—', Datensatzversion: selected.revision,
            'Erfasst am': selected.createdAt, 'Geändert am': selected.updatedAt,
          }).map(([label, value]) => <div key={label}><dt className="opacity-70">{label}</dt><dd className="break-words">{value}</dd></div>)}</dl>
          {canAssign && ['available', 'assigned'].includes(selected.lifecycle) && <section aria-label="Benutzerzuweisung" className="border-t border-[var(--border)] pt-4 space-y-4">
            <h3 className="font-semibold">Benutzerzuweisung</h3>
            {picker === 'loading' ? <p role="status">Verzeichnisberechtigung wird geprüft …</p> : <>
              {picker === 'directory' && <>
                <form className="flex flex-wrap items-end gap-3" onSubmit={event => { event.preventDefault(); setUserPage(1); setUserSearch(userSearchDraft.trim()); }}>
                  <label className="text-sm">Benutzer suchen<input className="block rounded border p-2 bg-transparent" maxLength={200} disabled={busy} value={userSearchDraft} onChange={event => setUserSearchDraft(event.target.value)} /></label>
                  <button className="fluent-btn-secondary" type="submit" disabled={busy}>Benutzer suchen</button>
                </form>
                <label className="block text-sm">Benutzer auswählen<select aria-label="Benutzer auswählen" className="block w-full rounded border p-2 bg-transparent" value={targetUserId} disabled={busy} onChange={event => setTargetUserId(event.target.value)}>
                  <option value="">Benutzer wählen …</option>{users?.users.map(user => <option key={user.id} value={user.id}>{userName(user)} · {user.username}{user.enabled ? '' : ' · Gesperrter Verzeichniseintrag'}</option>)}
                </select></label>
                {users && <Pagination label="Benutzerseite" page={users.page} total={users.total} disabled={busy} onPage={setUserPage} />}
              </>}
              <form className="flex flex-wrap items-end gap-3" onSubmit={event => {
                event.preventDefault(); if (!targetUserId || targetUserId === selected.assignedUserId || busy) return;
                setPending({ device: selected, userId: targetUserId });
              }}>
                {picker === 'uuid' && <div className="text-sm"><label>Kanonische Benutzer-ID
                  <input className="mt-1 block rounded border p-2 bg-transparent" aria-describedby="device-inventory-user-hint" required minLength={36} maxLength={36} pattern="[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}" value={targetUserId} disabled={busy} onChange={event => setTargetUserId(event.target.value)} />
                </label><p id="device-inventory-user-hint" className="mt-1 opacity-70">Keine Leseberechtigung für Benutzerprofile. Bekannte UUID eingeben.</p></div>}
                <button className="fluent-btn-primary" type="submit" disabled={busy || !targetUserId || targetUserId === selected.assignedUserId}>{selected.assignedUserId ? 'Benutzer neu zuweisen' : 'Benutzer zuweisen'}</button>
                {selected.assignedUserId && <button className="fluent-btn-secondary" type="button" disabled={busy} onClick={() => setPending({ device: selected, userId: null })}>Zuweisung aufheben</button>}
              </form>
            </>}
          </section>}
          {!selected.assignedUserId && ['maintenance', 'retired'].includes(selected.lifecycle) && <p className="text-sm">Für eine neue Benutzerzuweisung das Gerät zuerst wieder bereitstellen.</p>}
          <DeviceAgentPanel key={selected.id} device={selected} actor={access!.userId} canManage={Boolean(canCreate)} disabled={busy} onBusy={setBusy} onSecurityError={failure => fail(failure, generation.current)} />
          <section aria-label="Gerätehistorie" className="border-t border-[var(--border)] pt-4 space-y-3">
            <h3 className="font-semibold">Gerätehistorie</h3>
            {history ? <><ol className="space-y-4">{history.events.map(event => <li key={event.id} className="text-sm space-y-1">
              <p className="font-medium">{eventLabels[event.type]}</p><p><time dateTime={event.createdAt}>{event.createdAt}</time> · Version {event.after.revision}</p>
              <p className="break-words">Benutzer: {event.before?.assignedUserId || 'Nicht zugewiesen'} → {event.after.assignedUserId || 'Nicht zugewiesen'}</p>
              <p className="break-words">Ausgeführt von: {event.actorUserId} · Korrelations-ID: {event.correlationId}</p>
              {event.reason && <p>Begründung: {event.reason}</p>}
              {event.changes && <ul className="space-y-1">{event.changes.map(change => <li key={change.field}>{change.field === 'lifecycle' ? 'Status' : change.field}: {change.before || '—'} → {change.after || '—'}</li>)}</ul>}
              <p className="opacity-70">Ereigniszustellung ausstehend</p>
            </li>)}</ol>{history.events.length === 0 && <p>Keine Ereignisse vorhanden.</p>}
              <Pagination label="Historienseite" page={history.page} total={history.total} disabled={busy} onPage={setHistoryPage} /></> : <p role="status">Historie wird geladen …</p>}
          </section>
        </article>}
      </>}
    </div>
    {(creating || editing) && canCreate && <DeviceInventoryEditor device={editing} busy={busy} onClose={() => { setCreating(false); setEditing(null); }} onSave={save} />}
    {lifecycleChange && canCreate && <DirectoryConfirmation title={lifecycleLabels[lifecycleChange.lifecycle] + ': ' + lifecycleChange.device.assetId} busy={busy} error="" confirmDisabled={lifecycleReason.trim().length < 10} onClose={() => setLifecycleChange(null)} onConfirm={() => void changeLifecycle()}>
      <p>{lifecycleChange.device.assetId} · Version {lifecycleChange.device.revision}</p><p className="mt-3">Der Status wird auf „{lifecycleLabels[lifecycleChange.lifecycle]}“ geändert. Inventareintrag und Historie bleiben erhalten.</p>
      <label className="block mt-4">Begründung<input className="input-apple" required minLength={10} maxLength={500} value={lifecycleReason} onChange={event => setLifecycleReason(event.target.value)} /></label>
    </DirectoryConfirmation>}
    {pending && canAssign && <DirectoryConfirmation title={pending.userId === null ? 'Zuweisung aufheben' : pending.device.assignedUserId ? 'Benutzer neu zuweisen' : 'Benutzer zuweisen'} busy={busy} error="" onClose={() => setPending(null)} onConfirm={() => void assign(pending)}>
      <p>{pending.device.assetId} · Version {pending.device.revision}</p>
      <p className="mt-3 break-words">Bisher: {pending.device.assignedUserId || 'Nicht zugewiesen'}<br />Neu: {pending.userId || 'Nicht zugewiesen'}</p>
      {pending.device.assignedUserId && <p className="mt-3">Die bisherige aktive Zuweisung wird ersetzt beziehungsweise aufgehoben.</p>}
    </DirectoryConfirmation>}
  </ViewShell>;
}
