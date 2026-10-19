'use client';

import React, { useEffect, useRef, useState } from 'react';
import { directoryUsers } from '@/lib/directoryUsers';
import {
  DeviceReturnsClient, DeviceReturnPage, DeviceReturnRequest, DeviceReturnHistory, DeviceReturnIntent,
  DeviceReturnDecisionResult, DeviceReturnStatus, deviceReturnStatuses, deviceReturnsError, deviceReturnsIdentifier,
} from '@/lib/deviceReturns';
import { DirectoryConfirmation } from './UserDetailPanel';

const states = { requested: 'Rückgabe angefordert – weiterhin zugewiesen', returned: 'Physische Rückgabe manuell bestätigt', cancelled: 'Auftrag storniert – keine Inventaränderung', assignment_changed: 'Ursprüngliche Zuweisung geändert' };
const eventLabels = { 'device.return.requested': 'Rückgabe angefordert', 'device.return.confirmed': 'Physische Rückgabe manuell bestätigt', 'device.return.cancelled': 'Rückgabeauftrag storniert' };
function Proof({ values }: { values: Record<string, string> }) {
  return <details><summary>Nachweis</summary><dl className="mt-2 space-y-2 text-sm">{Object.entries(values).map(([label, value]) => <div key={label}><dt>{label}</dt><dd className="break-all">{value}</dd></div>)}</dl></details>;
}
function Pages({ page, total, busy, label, onPage }: { page: number; total: number; busy: boolean; label: string; onPage: (value: number) => void }) {
  return <nav aria-label={label} className="flex flex-wrap gap-4"><button disabled={busy || page <= 1} onClick={() => onPage(page - 1)}>Zurück</button><span>Seite {page} · {total} Einträge</span><button disabled={busy || page >= 1000000 || page * 25 >= total} onClick={() => onPage(page + 1)}>Weiter</button></nav>;
}

export default function DeviceReturnsView() {
  const client = useRef<DeviceReturnsClient | null>(null);
  const actor = useRef<string | null>(null); const generation = useRef(0); const running = useRef(false);
  const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [formError, setFormError] = useState('');
  const [list, setList] = useState<DeviceReturnPage | null>(null); const [filter, setFilter] = useState<DeviceReturnStatus | ''>('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<DeviceReturnRequest | null>(null); const [history, setHistory] = useState<DeviceReturnHistory | null>(null);
  const [reason, setReason] = useState(''); const [readback, setReadback] = useState(false);
  const [confirmation, setConfirmation] = useState<{ intent: DeviceReturnIntent; recovery: boolean } | null>(null);
  const [confirmed, setConfirmed] = useState(false); const [attempt, setAttempt] = useState<DeviceReturnIntent | null>(null);
  const [outcome, setOutcome] = useState<DeviceReturnDecisionResult | null>(null);

  const run = async <Value,>(operation: () => Promise<Value>, apply: (value: Value) => void) => {
    if (running.current) return;
    const expected = generation.current; running.current = true; setBusy(true); setError(''); setFormError('');
    try { const value = await operation(); if (generation.current === expected) apply(value); }
    catch (failure) {
      if (generation.current === expected) {
        client.current?.invalidate(); setList(null); setDetail(null); setHistory(null); setConfirmation(null); setConfirmed(false);
        setReadback(true); setError(deviceReturnsError(failure));
      }
    } finally { if (generation.current === expected) { running.current = false; setBusy(false); } }
  };
  const load = (page = list?.page || 1, nextFilter = filter, requestId = selectedId, historyPage = 1) => {
    if (running.current) return;
    const expected = generation.current;
    setList(null); setDetail(null); setHistory(null); setConfirmation(null); setConfirmed(false);
    void run(async () => {
      const access = await directoryUsers.access();
      if (generation.current !== expected || access.demoMode || !access.userId) throw new Error('Identität nicht bestätigt.');
      const userId = deviceReturnsIdentifier(access.userId);
      if (actor.current !== null && actor.current !== userId) {
        client.current?.dispose(); client.current = null; actor.current = null; setAttempt(null); setOutcome(null);
        throw new Error('Sitzung geändert.');
      }
      if (!client.current) { client.current = new DeviceReturnsClient(userId); actor.current = userId; }
      const current = client.current;
      const capability = await current.capabilities(); const nextList = await current.list(page, nextFilter || undefined);
      const nextDetail = requestId ? await current.get(requestId) : null;
      const nextHistory = requestId ? await current.history(requestId, historyPage) : null;
      return { capability, nextList, nextDetail, nextHistory };
    }, value => {
      setList(value.nextList); setDetail(value.nextDetail); setHistory(value.nextHistory); setSelectedId(requestId); setFilter(nextFilter); setReadback(false);
    });
  };
  useEffect(() => {
    generation.current++; load(1, '', null);
    const sessionError = () => {
      generation.current++; client.current?.dispose(); client.current = null; actor.current = null; running.current = false;
      setBusy(false); setList(null); setDetail(null); setHistory(null); setSelectedId(null); setConfirmation(null);
      setConfirmed(false); setAttempt(null); setOutcome(null); setReason(''); setReadback(true);
      setError(deviceReturnsError({ response: { status: 401 } }));
    };
    window.addEventListener('od:session-error', sessionError);
    return () => { generation.current++; client.current?.dispose(); client.current = null; running.current = false; window.removeEventListener('od:session-error', sessionError); };
  }, []);

  const begin = (action: 'returned' | 'cancelled') => {
    if (busy || readback || !detail || !client.current) return;
    try {
      const intent = client.current.capture(detail, { action, reason, confirm: true });
      setConfirmation({ intent, recovery: false }); setConfirmed(false); setFormError('');
    } catch { setFormError('Eine aktuelle Zuweisung und eine Begründung mit 10 bis 500 Zeichen ohne Steuerzeichen sind erforderlich.'); }
  };
  const confirm = () => {
    if (busy || !confirmed || !confirmation || !client.current) return;
    const pending = confirmation; const current = client.current;
    setAttempt(pending.intent); setOutcome(null); setReadback(true);
    void run(() => current.decide(pending.intent, pending.recovery), value => {
      setOutcome(value); setDetail(null); setHistory(null); setList(null); setConfirmation(null); setConfirmed(false);
    });
  };
  const canRecover = !busy && !readback && !!attempt && !!client.current?.canRecover(attempt);

  return <section aria-label="Geräterückgaben" className="p-6 max-w-6xl space-y-5 min-w-0" style={{ color: 'var(--text-primary)' }}>
    <header><h1 className="text-2xl font-semibold">Geräterückgaben</h1><p className="mt-2">Echte Inventaraufträge unabhängig vom späteren Kontostatus bearbeiten. Eine Anforderung bestätigt keine physische Rückgabe. Keine externen Gerätebefehle.</p></header>
    <div className="flex flex-wrap gap-4 items-center">
      <label>Statusfilter<select className="ml-2 rounded border p-2 bg-transparent" value={filter} disabled={busy || !!confirmation} onChange={event => {
        const nextFilter = event.target.value as DeviceReturnStatus | ''; setAttempt(null); setOutcome(null); setReason(''); setSelectedId(null); load(1, nextFilter, null);
      }}><option value="">Alle</option>{deviceReturnStatuses.map(value => <option key={value} value={value}>{states[value]}</option>)}</select></label>
      <button className="fluent-btn-secondary" disabled={busy || !!confirmation} onClick={() => load()}>Rückgaben und Historie neu laden</button>
    </div>
    {busy && <p role="status">Rückgabeaufträge werden geprüft …</p>}{error && <p role="alert">{error}</p>}{formError && <p role="alert">{formError}</p>}
    {readback && <p role="status">Tatsächliche Rückgaben und Historie ausdrücklich neu laden. Kein automatischer Wiederholungsversuch.</p>}
    {list && <section aria-label="Rückgabeauftragsliste" className="space-y-4">
      <Proof values={{ Mandant: list.tenantId, 'Aktueller Benutzer': list.actorUserId }} />
      {!list.requests.length && <p>Auf dieser Seite sind keine Rückgabeaufträge vorhanden.</p>}
      <ul className="space-y-3">{list.requests.map(request => <li key={request.id} className="rounded border p-3 space-y-2 break-words">
        <p>{request.assetId} · Seriennummer {request.serialNumber} · {states[request.status]}</p>
        <p className="break-all">Ursprünglicher Mitarbeiter: {request.userId}</p>
        <button className="fluent-btn-secondary" disabled={busy || !!confirmation} onClick={() => {
          setAttempt(null); setOutcome(null); setReason(''); setSelectedId(request.id); load(list.page, filter, request.id);
        }}>Rückgabe {request.assetId} öffnen</button>
      </li>)}</ul>
      <Pages page={list.page} total={list.total} busy={busy || !!confirmation} label="Rückgabeauftragsseiten" onPage={page => load(page)} />
    </section>}
    {detail && <section aria-label="Rückgabeauftragdetails" className="rounded border p-4 space-y-4 break-words">
      <h2 className="text-lg font-semibold">{detail.assetId} · {detail.serialNumber}</h2><p>{states[detail.status]}</p>
      {detail.status === 'requested' && <p>Die ursprüngliche Gerätezuweisung besteht weiterhin. Erst eine ausdrücklich bestätigte physische Rückgabe gibt genau diese Zuweisung im Inventar frei.</p>}
      {detail.status === 'assignment_changed' && <p>Die ursprüngliche Zuweisung wurde durch eine gewöhnliche Inventaraktion beendet. Kein Rückgabeereignis und keine physische Rückgabe behauptet. Keine Entscheidung möglich; eine neue Zuweisung bleibt unberührt.</p>}
      {detail.status === 'returned' && <p>Historischer Rückgabenachweis. Das Gerät kann inzwischen erneut zugewiesen sein; dieser Nachweis bestätigt keine aktuelle Verfügbarkeit.</p>}
      {detail.status === 'cancelled' && <p>Nur der Auftrag wurde storniert. Keine Gerätezuweisung wurde durch diese Entscheidung geändert.</p>}
      <p>Ursprüngliche Begründung: {detail.reason} · Ereigniszustellung ausstehend</p>
      <Proof values={{ 'Rückgabeauftrag-ID': detail.id, 'Benutzer-ID': detail.userId, 'Vorgangs-ID der Kontosperre': detail.workflowId,
        'Geräte-ID': detail.deviceId, 'Ursprüngliche Zuweisungs-ID': detail.assignmentId, 'Auftragsversion': detail.revision,
        'Geräteversion bei Anforderung': detail.deviceRevision, 'Aktuelle Geräteversion': detail.currentDeviceRevision,
        'Berechtigungsversion bei Anforderung': detail.eligibilityRevision, 'Angefordert von': detail.actorUserId, 'Angefordert am': detail.requestedAt,
        'Abgeschlossen am': detail.closedAt || 'Nicht abgeschlossen', 'Abgeschlossen von': detail.closedByUserId || 'Nicht abgeschlossen',
        'Anforderungsereignis': detail.operationId, 'Entscheidungsereignis': detail.closingOperationId || 'Keines', 'Inventarereignis': detail.inventoryOperationId || 'Keines' }} />
      {detail.status === 'requested' && !readback && <div className="space-y-3">
        <label className="block">Begründung für Rückgabeentscheidung<textarea className="block w-full rounded border p-2 bg-transparent" value={reason} maxLength={1000} disabled={busy || !!confirmation} onChange={event => setReason(event.target.value)} /></label>
        <div className="flex flex-wrap gap-4"><button className="fluent-btn-secondary" disabled={busy || !!confirmation} onClick={() => begin('returned')}>Physische Rückgabe bestätigen</button><button className="fluent-btn-secondary" disabled={busy || !!confirmation} onClick={() => begin('cancelled')}>Rückgabeauftrag stornieren</button></div>
      </div>}
    </section>}
    {attempt && <section aria-label="Wiederherstellung der Rückgabeentscheidung" className="space-y-3">
      <p>Nach tatsächlichem Abruf nur denselben ursprünglichen Auftrag mit ursprünglichem ETag und derselben Entscheidung wiederherstellen. Keine neue Zuweisung als Ersatz und keine Aussage über aktuelle Geräteverfügbarkeit.</p>
      <button className="fluent-btn-secondary" disabled={!canRecover || !!confirmation} onClick={() => { setConfirmation({ intent: attempt, recovery: true }); setConfirmed(false); }}>Ursprünglichen Versuch wiederherstellen</button>
    </section>}
    {outcome && <section aria-label="Ergebnis der Rückgabeentscheidung" className="space-y-3">
      <p role="status">{outcome.outcome.startsWith('already_') ? 'Ursprünglicher historischer Entscheidungsnachweis wiederhergestellt.' : outcome.outcome === 'returned' ? 'Physische Rückgabe manuell bestätigt.' : 'Auftrag storniert. Keine Inventaränderung.'} Keine Aussage über aktuelle Geräteverfügbarkeit. Arbeitsstand und Historie ausdrücklich neu laden.</p>
      <Proof values={{ 'Rückgabeauftrag-ID': outcome.request.id, 'Entscheidungsereignis': outcome.operationId, 'Inventarereignis': outcome.request.inventoryOperationId || 'Keines' }} />
    </section>}
    {history && <section aria-label="Rückgabeereignishistorie" className="space-y-3">
      <h2 className="text-lg font-semibold">Tatsächliche Rückgabeereignisse</h2>
      <p>Nur ursprüngliche Rückgabeereignisse. Gewöhnliche Inventarfreigaben erzeugen hier kein erfundenes Rückgabeereignis.</p>
      {!history.events.length && <p>Auf dieser Seite sind keine Ereignisse vorhanden.</p>}
      <ol className="space-y-3">{history.events.map(event => <li key={event.id}><p>{eventLabels[event.type]} · {new Date(event.createdAt).toLocaleString('de-CH')} · {event.reason}</p>
        <Proof values={{ 'Ereignis-ID': event.id, 'Ausgeführt von': event.actorUserId, 'Korrelations-ID': event.correlationId, 'Auftragsversion vorher': event.before?.revision || 'Nicht vorhanden', 'Auftragsversion nachher': event.after.revision, 'Inventarereignis': event.inventoryOperationId || 'Keines', Zustellung: 'Ausstehend' }} />
      </li>)}</ol>
      <Pages page={history.page} total={history.total} busy={busy || !!confirmation || readback} label="Rückgabeereignisseiten" onPage={page => load(list?.page || 1, filter, selectedId, page)} />
    </section>}
    {confirmation && <DirectoryConfirmation title={confirmation.recovery ? 'Ursprüngliche Rückgabeentscheidung bestätigen' : confirmation.intent.body.action === 'returned' ? 'Physische Rückgabe bestätigen' : 'Rückgabeauftrag stornieren'} busy={busy} error={confirmed ? '' : 'Bitte genau diese Rückgabeentscheidung bestätigen.'} onClose={() => { setConfirmation(null); setConfirmed(false); }} onConfirm={confirm}>
      <div className="max-h-[55vh] overflow-y-auto space-y-3 break-words">
        <p>{confirmation.intent.request.assetId} · Seriennummer {confirmation.intent.request.serialNumber}</p>
        <p>{confirmation.intent.body.action === 'returned' ? 'Nur nach tatsächlicher physischer Rückgabe bestätigen. Genau die ursprüngliche aktive Zuweisung wird im Inventar freigegeben.' : 'Nur den Rückgabeauftrag stornieren. Keine Inventaränderung.'}</p>
        <p>Begründung: {confirmation.intent.body.reason}</p>
        <Proof values={{ 'Rückgabeauftrag-ID': confirmation.intent.request.id, 'Ursprünglicher Mitarbeiter': confirmation.intent.request.userId, 'Geräte-ID': confirmation.intent.request.deviceId,
          'Ursprüngliche Zuweisungs-ID': confirmation.intent.request.assignmentId, 'Ursprünglicher ETag': confirmation.intent.etag }} />
        {confirmation.recovery && <p>Nur derselbe ursprüngliche Versuch. Ein historischer Nachweis darf eine spätere neue Zuweisung nicht ändern und bestätigt keine aktuelle Verfügbarkeit.</p>}
        <label className="flex gap-3"><input type="checkbox" checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)} /><span>Ich bestätige genau diese Rückgabeentscheidung.</span></label>
      </div>
    </DirectoryConfirmation>}
  </section>;
}
