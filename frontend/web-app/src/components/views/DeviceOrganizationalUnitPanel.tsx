'use client';

import React, { useEffect, useRef, useState } from 'react';
import type { Device } from '@/lib/deviceInventory';
import { readDeviceOu, readDeviceOuChoices, writeDeviceOu, readDeviceOuHistory, deviceOuError, type DeviceOuAssignment, type DeviceOuChoices, type DeviceOuHistory, type DeviceOrganizationalUnit } from '@/lib/deviceOrganizationalUnits';
import { DirectoryConfirmation } from './UserDetailPanel';
const date = (value: string) => new Date(value).toLocaleString('de-CH');

export default function DeviceOrganizationalUnitPanel({ device, actor, canManage, disabled, onBusy, onSecurityError }: {
  device: Device; actor: string; canManage: boolean; disabled: boolean; onBusy: (value: boolean) => void; onSecurityError: (error: unknown) => void;
}) {
  const [data, setData] = useState<DeviceOuAssignment | null>(null), [unsupported, setUnsupported] = useState(false), [error, setError] = useState(''), [notice, setNotice] = useState('');
  const [reload, setReload] = useState(0), [editing, setEditing] = useState(false), [choices, setChoices] = useState<DeviceOuChoices | null>(null), [selection, setSelection] = useState<DeviceOrganizationalUnit | null>(null);
  const [page, setPage] = useState(1), [search, setSearch] = useState(''), [draft, setDraft] = useState(''), [reason, setReason] = useState('');
  const [confirmation, setConfirmation] = useState<{ ou: DeviceOrganizationalUnit | null } | null>(null), [history, setHistory] = useState<DeviceOuHistory | null>(null), [historyPage, setHistoryPage] = useState(1), [busy, setBusy] = useState(false);
  const generation = useRef(0), command = useRef<AbortController | null>(null), writing = useRef(false), callbacks = useRef({ onBusy, onSecurityError }); callbacks.current = { onBusy, onSecurityError };
  const fail = (failure: unknown) => { setData(null); setChoices(null); setHistory(null); setEditing(false); setConfirmation(null); setError(deviceOuError(failure)); if ([401, 403, 428].includes((failure as any)?.response?.status)) callbacks.current.onSecurityError(failure); };
  useEffect(() => {
    const controller = new AbortController(), expected = ++generation.current; setData(null); setUnsupported(false); setError(''); setEditing(false); setConfirmation(null); setChoices(null); setHistory(null); setBusy(false); setNotice('');
    void readDeviceOu(device, actor, controller.signal).then(value => { if (!controller.signal.aborted && expected === generation.current) { setData(value); setUnsupported(value === null); } }).catch(failure => { if (!controller.signal.aborted && expected === generation.current) fail(failure); });
    const session = () => { controller.abort(); command.current?.abort(); generation.current += 1; setData(null); setChoices(null); setHistory(null); setEditing(false); setConfirmation(null); setBusy(false); setNotice(''); setError(deviceOuError({ response: { status: 401 } })); if (writing.current) { writing.current = false; callbacks.current.onBusy(false); } };
    window.addEventListener('od:session-error', session);
    return () => { generation.current += 1; controller.abort(); command.current?.abort(); if (writing.current) { writing.current = false; callbacks.current.onBusy(false); } window.removeEventListener('od:session-error', session); };
  }, [device.id, device.revision, actor, canManage, reload]);
  useEffect(() => {
    if (!editing || !data || !canManage) return;
    const controller = new AbortController(), expected = generation.current; setChoices(null); setError('');
    void readDeviceOuChoices(device, actor, page, search, controller.signal).then(value => { if (!controller.signal.aborted && expected === generation.current) { const last = Math.max(1, Math.ceil(value.total / 25)); if (page > last) setPage(last); else setChoices(value); } }).catch(failure => {
      if (controller.signal.aborted || expected !== generation.current) return;
      if ((failure as any)?.response?.status === 403) setError('Für die OU-Auswahl wird zusätzlich die Berechtigung „Organisationseinheiten lesen“ benötigt. Die bestehenden Geräteberechtigungen bleiben nutzbar.');
      else fail(failure);
    });
    return () => controller.abort();
  }, [editing, data, canManage, page, search]);
  const save = async () => {
    if (!data || !confirmation || busy || disabled || !canManage || writing.current) return;
    const controller = new AbortController(), expected = generation.current; command.current?.abort(); command.current = controller; writing.current = true; callbacks.current.onBusy(true); setBusy(true); setError('');
    try {
      const result = await writeDeviceOu(device, actor, data, confirmation.ou, reason, controller.signal);
      if (!controller.signal.aborted && generation.current === expected) { setData(result); setConfirmation(null); setEditing(false); setChoices(null); setHistory(null); setNotice('OU-Zuordnung gespeichert und protokolliert.'); }
    } catch (failure) { if (!controller.signal.aborted && generation.current === expected) fail(failure); }
    finally { if (generation.current === expected) setBusy(false); if (command.current === controller) command.current = null; if (writing.current) { writing.current = false; callbacks.current.onBusy(false); } }
  };
  const showHistory = async (selectedPage: number) => {
    const controller = new AbortController(), expected = generation.current; command.current?.abort(); command.current = controller; setHistory(null);
    try { const value = await readDeviceOuHistory(device, actor, selectedPage, controller.signal); if (!controller.signal.aborted && expected === generation.current) { setHistory(value); setHistoryPage(selectedPage); } }
    catch (failure) { if (!controller.signal.aborted && expected === generation.current) fail(failure); }
    finally { if (command.current === controller) command.current = null; }
  };
  if (unsupported) return null;
  return <section aria-label="Geräte-Organisationseinheit" className="border-t border-[var(--border)] pt-4 space-y-3">
    <h3 className="font-semibold">Organisationseinheit</h3>
    {error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
    {!data && !error && <p role="status">OU-Zuordnung wird geladen …</p>}
    {data && <>
      <p>{data.ou ? data.ou.name : 'Keine Organisationseinheit zugeordnet.'}</p>
      {data.updatedAt && <p className="text-xs opacity-70 break-words">Zuordnung vom {date(data.updatedAt)} · {data.updatedBy}. Name und Version der OU sind der Stand dieser Änderung.</p>}
      <p className="text-sm opacity-70">Die Benutzerzuweisung bleibt unabhängig. Eine OU-Zuordnung erteilt keine zusätzlichen Geräte- oder PIM-Rechte.</p>
      <div className="flex flex-wrap gap-3">
        {canManage && <button className="fluent-btn-secondary" disabled={busy || disabled} onClick={() => { setEditing(value => !value); setSelection(null); setPage(1); setSearch(''); setDraft(''); setError(''); }}>Zuordnung ändern</button>}
        {canManage && data.ou && <button className="fluent-btn-secondary" disabled={busy || disabled} onClick={() => { setReason(''); setConfirmation({ ou: null }); }}>OU-Zuordnung aufheben</button>}
        <button className="fluent-btn-secondary" disabled={busy || disabled} onClick={() => void showHistory(1)}>OU-Verlauf</button>
      </div>
      {editing && canManage && <div className="rounded border border-[var(--border)] p-3 space-y-3">
        <form className="flex flex-wrap items-end gap-3" onSubmit={event => { event.preventDefault(); setPage(1); setSearch(draft.trim()); }}><label className="text-sm">Organisationseinheit suchen<input className="input-apple block" maxLength={255} value={draft} disabled={busy || disabled} onChange={event => setDraft(event.target.value)} /></label><button className="fluent-btn-secondary" type="submit" disabled={busy || disabled}>OU suchen</button></form>
        {!choices && !error ? <p role="status">Eigene Organisationseinheiten werden geladen …</p> : choices && <>
          <label className="block text-sm">Organisationseinheit auswählen<select className="input-apple block w-full" value={selection?.id || ''} disabled={busy || disabled} onChange={event => setSelection(choices.units.find(value => value.id === event.target.value) || null)}><option value="">Organisationseinheit wählen …</option>{selection && !choices.units.some(value => value.id === selection.id) && <option value={selection.id}>{selection.name} · bisherige Auswahl</option>}{choices.units.map(value => <option key={value.id} value={value.id}>{value.name}</option>)}</select></label>
          <nav aria-label="OU-Auswahlseiten" className="flex flex-wrap items-center gap-3 text-sm"><button className="fluent-btn-secondary" disabled={busy || disabled || page <= 1} onClick={() => setPage(value => value - 1)}>Zurück</button><span>Seite {page} von {Math.max(1, Math.ceil(choices.total / 25))}</span><button className="fluent-btn-secondary" disabled={busy || disabled || page * 25 >= choices.total} onClick={() => setPage(value => value + 1)}>Weiter</button></nav>
          <button className="fluent-btn-primary" disabled={busy || disabled || !selection || selection.id === data.ou?.id && selection.generation === data.ou.generation && selection.revision === data.ou.revision} onClick={() => { setReason(''); setConfirmation({ ou: selection }); }}>OU-Zuordnung prüfen</button>
        </>}
      </div>}
    </>}
    <button className="fluent-btn-secondary" disabled={busy || disabled} onClick={() => setReload(value => value + 1)}>OU-Zuordnung neu laden</button>
    {history && <div aria-label="OU-Zuordnungsverlauf" className="space-y-3"><h4 className="font-medium">OU-Verlauf</h4>{!history.total && <p>Noch keine OU-Zuordnung geändert.</p>}<ol className="space-y-3 text-sm">{history.events.map(event => <li key={event.id} className="break-words"><p>{event.before?.ou?.name || 'Keine OU'} → {event.after.ou?.name || 'Keine OU'}</p><p>{event.reason}</p><p className="text-xs opacity-70">{date(event.createdAt)} · {event.actorUserId} · {event.correlationId}</p></li>)}</ol><nav aria-label="OU-Verlaufsseiten" className="flex items-center gap-3 text-sm"><button className="fluent-btn-secondary" disabled={busy || disabled || historyPage <= 1} onClick={() => void showHistory(historyPage - 1)}>Zurück</button><span>Seite {historyPage} von {Math.max(1, Math.ceil(history.total / 25))}</span><button className="fluent-btn-secondary" disabled={busy || disabled || historyPage * 25 >= history.total} onClick={() => void showHistory(historyPage + 1)}>Weiter</button></nav></div>}
    {confirmation && <DirectoryConfirmation title={confirmation.ou ? 'Geräte-OU-Zuordnung bestätigen' : 'Geräte-OU-Zuordnung aufheben'} busy={busy} error="" confirmDisabled={Array.from(reason.trim()).length < 10 || Array.from(reason.trim()).length > 500} onClose={() => setConfirmation(null)} onConfirm={() => void save()}>
      <p>{device.assetId}: {data?.ou?.name || 'Keine OU'} → {confirmation.ou?.name || 'Keine OU'}. Die Änderung wird mit deiner Identität und Begründung protokolliert.</p>
      <label className="block mt-3">Begründung für OU-Zuordnung<input className="input-apple" value={reason} maxLength={500} disabled={busy} onChange={event => setReason(event.target.value)} /></label>
    </DirectoryConfirmation>}
  </section>;
}
