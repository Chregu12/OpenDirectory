'use client';

import React, { useEffect, useRef, useState } from 'react';
import { ViewShell } from '@/components/ui/ViewShell';
import { DataTable } from '@/components/ui/DataTable';
import { Device, DeviceCapabilities, DeviceHistoryPage, DeviceInput, DeviceInventoryClient, DevicePage, deviceClasses, devicePlatforms, deviceInventoryError, normalizeDeviceInput } from '@/lib/deviceInventory';
import { UserPage, userName } from '@/lib/directoryUsers';
import { DirectoryConfirmation } from './UserDetailPanel';

const initialValues: DeviceInput = { assetId: '', serialNumber: '', manufacturer: '', model: '', deviceClass: 'laptop', platform: 'other', osVersion: '', ownership: 'corporate', purchaseDate: '', warrantyEnd: '', description: '' };
const classLabels = { smartphone: 'Smartphone', tablet: 'Tablet', laptop: 'Laptop', desktop: 'Desktop', shared: 'Gemeinschaftsgerät', kiosk: 'Kiosk', other: 'Sonstiges' };
const platformLabels = { macos: 'macOS', ios: 'iOS', ipados: 'iPadOS', windows: 'Windows', linux: 'Linux', android: 'Android', other: 'Sonstiges' };
const ownershipLabels = { corporate: 'Unternehmen', byod: 'Privatgerät (BYOD)', shared: 'Gemeinsame Nutzung' };
const eventLabels = { 'device.registered': 'Gerät erfasst', 'device.assigned': 'Benutzer zugewiesen', 'device.assignment.released': 'Zuweisung aufgehoben' };

function Pagination({ page, total, label, disabled, onPage }: { page: number; total: number; label: string; disabled?: boolean; onPage: (page: number) => void }) {
  return <nav aria-label={label + 'n'} className="flex flex-wrap items-center gap-4 py-3 text-sm">
    <button className="fluent-btn-secondary" aria-label={'Vorherige ' + label} disabled={disabled || page <= 1} onClick={() => onPage(page - 1)}>Zurück</button>
    <span>Seite {page} von {Math.max(1, Math.ceil(total / 25))} · {total} Einträge</span>
    <button className="fluent-btn-secondary" aria-label={'Nächste ' + label} disabled={disabled || page * 25 >= total} onClick={() => onPage(page + 1)}>Weiter</button>
  </nav>;
}

export default function DeviceInventoryView() {
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
  const [values, setValues] = useState<DeviceInput>({ ...initialValues });
  const [formError, setFormError] = useState('');
  const [pending, setPending] = useState<{ device: Device; userId: string | null } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const canRead = access?.permissions.includes('devices.inventory.read');
  const canCreate = canRead && access?.permissions.includes('devices.inventory.create');
  const canAssign = canRead && access?.permissions.includes('devices.inventory.assign');

  const clearSelection = () => {
    setSelectedId(null); setSelected(null); setHistory(null); setHistoryPage(1); setPending(null);
    setUsers(null); setPicker('loading'); setTargetUserId(''); setUserPage(1); setUserSearch(''); setUserSearchDraft('');
  };
  const fail = (failure: unknown, expected: number) => {
    if (generation.current !== expected) return;
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
    client.current.list(page, search, controller.signal).then(result => { if (active && generation.current === expected) setDevices(result); })
      .catch(failure => { if (active) fail(failure, expected); });
    return () => { active = false; controller.abort(); };
  }, [access, page, search, listVersion]);

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
      setSelected(result); setPending(null); setTargetUserId('');
      setDevices(current => current && ({ ...current, devices: current.devices.map(device => device.id === result.id ? result : device) }));
      setHistoryPage(1); setHistoryVersion(value => value + 1);
      setNotice(change.userId === null ? 'Zuweisung aufgehoben.' : 'Inventarzuweisung gespeichert.');
    } catch (failure) { fail(failure, expected); }
    finally { if (generation.current === expected) setBusy(false); }
  };

  return <ViewShell title="Geräteinventar" subtitle="Geräte erfassen und genau einem Benutzer zuordnen."
    primaryAction={canCreate && devices ? { label: 'Gerät erfassen', onClick: () => { setValues({ ...initialValues }); setFormError(''); setCreating(true); setNotice(''); }, disabled: busy } : undefined}
    actions={[{ label: 'Neu laden', onClick: () => { generation.current += 1; client.current?.invalidate(); setReload(value => value + 1); }, disabled: busy }]}>
    <div className="space-y-5" style={{ color: 'var(--text-primary)' }}>
      <p className="rounded-lg border border-white/10 p-4 text-sm">Nur Inventar · Nicht registriert · Compliance unbekannt. Eine Inventarzuweisung richtet keine Geräteverwaltung ein.</p>
      {error ? <p role="alert" className="rounded border border-red-500/40 p-4">{error}</p> : !access ? <p role="status">Geräteberechtigungen werden geprüft …</p> : !canRead ? <p role="status">Keine Berechtigung zum Lesen des Geräteinventars.</p> : <>
        {notice && <p role="status">{notice}</p>}
        <form className="flex flex-wrap items-end gap-3" onSubmit={event => { event.preventDefault(); clearSelection(); setPage(1); setSearch(searchDraft.trim()); setListVersion(value => value + 1); }}>
          <label className="text-sm">Geräte suchen<input className="mt-1 block rounded border p-2 bg-transparent" maxLength={200} value={searchDraft} disabled={busy} onChange={event => setSearchDraft(event.target.value)} placeholder="Inventarnummer, Seriennummer, Modell" /></label>
          <button className="fluent-btn-secondary" disabled={busy} type="submit">Suchen</button>
        </form>
        {devices ? <section aria-label="Geräteliste">
          <DataTable<Device> rows={devices.devices} getRowId={device => device.id} activeRowId={selectedId} emptyMessage="Keine Geräte gefunden." columns={[
            { key: 'assetId', header: 'Inventarnummer', render: device => <button className="text-blue-500 underline" disabled={busy} onClick={() => { if (selectedId === device.id) return; clearSelection(); setSelectedId(device.id); }}>{device.assetId}</button> },
            { key: 'serialNumber', header: 'Seriennummer' },
            { key: 'model', header: 'Gerät', render: device => `${device.manufacturer} ${device.model}` },
            { key: 'deviceClass', header: 'Geräteklasse', render: device => classLabels[device.deviceClass] },
            { key: 'platform', header: 'Plattform', render: device => platformLabels[device.platform] },
            { key: 'lifecycle', header: 'Zuordnung', render: device => device.lifecycle === 'assigned' ? 'Zugewiesen' : 'Verfügbar' },
          ]} />
          <Pagination label="Geräteseite" page={devices.page} total={devices.total} disabled={busy} onPage={next => { clearSelection(); setPage(next); }} />
        </section> : <p role="status">Geräte werden geladen …</p>}
        {selectedId && !selected && <p role="status">Gerätedetails werden geladen …</p>}
        {selected && <article aria-label="Gerätedetails" className="rounded-lg border border-white/10 p-5 space-y-5">
          <div className="flex items-start justify-between gap-4"><div><h2 className="text-xl font-semibold">{selected.assetId}</h2><p>{selected.manufacturer} {selected.model}</p></div><button className="fluent-btn-secondary" disabled={busy} onClick={clearSelection}>Details schließen</button></div>
          <dl className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">{Object.entries({
            'Geräte-ID': selected.id, Seriennummer: selected.serialNumber, Geräteklasse: classLabels[selected.deviceClass],
            Plattform: platformLabels[selected.platform], Betriebssystemversion: selected.osVersion || '—', Eigentum: ownershipLabels[selected.ownership],
            Kaufdatum: selected.purchaseDate || '—', Garantieende: selected.warrantyEnd || '—', Beschreibung: selected.description || '—',
            Benutzerzuordnung: selected.assignedUserId || 'Nicht zugewiesen', 'Zuweisungs-ID': selected.assignmentId || '—', Datensatzversion: selected.revision,
            'Erfasst am': selected.createdAt, 'Geändert am': selected.updatedAt, 'Zuletzt gesehen': 'Keine Telemetrie',
          }).map(([label, value]) => <div key={label}><dt className="opacity-70">{label}</dt><dd className="break-words">{value}</dd></div>)}</dl>
          {canAssign && <section aria-label="Benutzerzuweisung" className="border-t border-white/10 pt-4 space-y-4">
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
          <section aria-label="Gerätehistorie" className="border-t border-white/10 pt-4 space-y-3">
            <h3 className="font-semibold">Gerätehistorie</h3>
            {history ? <><ol className="space-y-4">{history.events.map(event => <li key={event.id} className="text-sm space-y-1">
              <p className="font-medium">{eventLabels[event.type]}</p><p><time dateTime={event.createdAt}>{event.createdAt}</time> · Version {event.after.revision}</p>
              <p className="break-words">Benutzer: {event.before?.assignedUserId || 'Nicht zugewiesen'} → {event.after.assignedUserId || 'Nicht zugewiesen'}</p>
              <p className="break-words">Ausgeführt von: {event.actorUserId} · Korrelations-ID: {event.correlationId}</p>
              <p className="opacity-70">Ereigniszustellung ausstehend</p>
            </li>)}</ol>{history.events.length === 0 && <p>Keine Ereignisse vorhanden.</p>}
              <Pagination label="Historienseite" page={history.page} total={history.total} disabled={busy} onPage={setHistoryPage} /></> : <p role="status">Historie wird geladen …</p>}
          </section>
        </article>}
      </>}
    </div>
    {creating && canCreate && <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-5" role="dialog" aria-modal="true" aria-label="Gerät erfassen">
      <form className="w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-xl p-6 space-y-5" style={{ background: 'var(--bg-surface, #161b22)', color: 'var(--text-primary, #e4e6ea)' }} onSubmit={async event => {
        event.preventDefault(); if (busy) return;
        let normalized: DeviceInput;
        try { normalized = normalizeDeviceInput(values); } catch { setFormError('Bitte Pflichtfelder, Datumswerte und Garantiezeitraum prüfen.'); return; }
        const expected = generation.current; setBusy(true); setFormError(''); setNotice('');
        try {
          const result = await client.current.create(normalized);
          if (generation.current !== expected) return;
          setCreating(false); setNotice(`Gerät ${result.assetId} im Inventar erfasst.`); setPage(1); setListVersion(value => value + 1);
        } catch (failure) { fail(failure, expected); }
        finally { if (generation.current === expected) setBusy(false); }
      }}>
        <h2 className="text-xl font-semibold">Gerät erfassen</h2><p className="text-sm">Der neue Eintrag ist verfügbar und keinem Benutzer zugewiesen.</p>
        <fieldset disabled={busy} className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {([{ field: 'assetId', label: 'Inventarnummer' }, { field: 'serialNumber', label: 'Seriennummer' }, { field: 'manufacturer', label: 'Hersteller' }, { field: 'model', label: 'Modell' }, { field: 'osVersion', label: 'Betriebssystemversion' }] as const).map(({ field, label }) => <label key={field} className="text-sm">{label}
            <input className="mt-1 block w-full rounded border p-2 bg-transparent" name={field} required={field !== 'osVersion'} maxLength={120} value={values[field]} onChange={event => setValues(previous => ({ ...previous, [field]: event.target.value }))} />
          </label>)}
          <label className="text-sm">Geräteklasse<select aria-label="Geräteklasse" className="mt-1 block w-full rounded border p-2 bg-transparent" value={values.deviceClass} onChange={event => setValues(previous => ({ ...previous, deviceClass: event.target.value as DeviceInput['deviceClass'] }))}>{deviceClasses.map(value => <option key={value} value={value}>{classLabels[value]}</option>)}</select></label>
          <label className="text-sm">Plattform<select aria-label="Plattform" className="mt-1 block w-full rounded border p-2 bg-transparent" value={values.platform} onChange={event => setValues(previous => ({ ...previous, platform: event.target.value as DeviceInput['platform'] }))}>{devicePlatforms.map(value => <option key={value} value={value}>{platformLabels[value]}</option>)}</select></label>
          <label className="text-sm">Eigentum<select aria-label="Eigentum" className="mt-1 block w-full rounded border p-2 bg-transparent" value={values.ownership} onChange={event => setValues(previous => ({ ...previous, ownership: event.target.value as DeviceInput['ownership'] }))}>{Object.entries(ownershipLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
          {([{ field: 'purchaseDate', label: 'Kaufdatum' }, { field: 'warrantyEnd', label: 'Garantieende' }] as const).map(({ field, label }) => <label className="text-sm" key={field}>{label}<input className="mt-1 block w-full rounded border p-2 bg-transparent" type="date" value={values[field]} onChange={event => setValues(previous => ({ ...previous, [field]: event.target.value }))} /></label>)}
          <label className="text-sm md:col-span-2">Beschreibung<input className="mt-1 block w-full rounded border p-2 bg-transparent" maxLength={2000} value={values.description} onChange={event => setValues(previous => ({ ...previous, description: event.target.value }))} /></label>
        </fieldset>
        {formError && <p role="alert">{formError}</p>}
        <div className="flex justify-end gap-4"><button className="fluent-btn-secondary" type="button" disabled={busy} onClick={() => setCreating(false)}>Abbrechen</button><button className="fluent-btn-primary" type="submit" disabled={busy}>{busy ? 'Wird gespeichert …' : 'Im Inventar speichern'}</button></div>
      </form>
    </div>}
    {pending && canAssign && <DirectoryConfirmation title={pending.userId === null ? 'Zuweisung aufheben' : pending.device.assignedUserId ? 'Benutzer neu zuweisen' : 'Benutzer zuweisen'} busy={busy} error="" onClose={() => setPending(null)} onConfirm={() => void assign(pending)}>
      <p>{pending.device.assetId} · Version {pending.device.revision}</p>
      <p className="mt-3 break-words">Bisher: {pending.device.assignedUserId || 'Nicht zugewiesen'}<br />Neu: {pending.userId || 'Nicht zugewiesen'}</p>
      {pending.device.assignedUserId && <p className="mt-3">Die bisherige aktive Zuweisung wird ersetzt beziehungsweise aufgehoben.</p>}
    </DirectoryConfirmation>}
  </ViewShell>;
}
