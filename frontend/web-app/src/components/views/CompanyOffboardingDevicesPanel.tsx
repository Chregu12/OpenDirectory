'use client';

import React, { useEffect, useId, useRef, useState } from 'react';
import {
  CompanyOffboardingDevicesClient, OffboardingDevicesBinding, OffboardingDevicesPreview, OffboardingDevicesHistory,
  OffboardingDevicesIntent, OffboardingDevicesOutcome, deviceReturnsError,
} from '@/lib/deviceReturns';
import { DirectoryConfirmation } from './UserDetailPanel';

const results = { requested: 'Angefordert', already_requested: 'Bereits angefordert – ursprünglicher Nachweis', unconfirmed: 'Nicht bestätigt', not_attempted: 'Nicht versucht' };
const states = { requested: 'Rückgabe angefordert – Zuweisung bleibt bestehen', returned: 'Physische Rückgabe manuell bestätigt', cancelled: 'Auftrag storniert – keine Inventaränderung', assignment_changed: 'Ursprüngliche Zuweisung geändert – keine physische Rückgabe bestätigt' };
function Proof({ values }: { values: Record<string, string> }) {
  return <details><summary>Nachweis</summary><dl className="mt-2 space-y-2 text-sm">{Object.entries(values).map(([label, value]) => <div key={label}><dt>{label}</dt><dd className="break-all">{value}</dd></div>)}</dl></details>;
}
function Pages({ page, total, disabled, label, onPage }: { page: number; total: number; disabled: boolean; label: string; onPage: (value: number) => void }) {
  return <nav aria-label={label} className="flex flex-wrap gap-4"><button disabled={disabled || page <= 1} onClick={() => onPage(page - 1)}>Zurück</button><span>Seite {page} · {total} Einträge</span><button disabled={disabled || page >= 1000000 || page * 25 >= total} onClick={() => onPage(page + 1)}>Weiter</button></nav>;
}

export default function CompanyOffboardingDevicesPanel(props: OffboardingDevicesBinding) {
  return <BoundDevicesPanel key={[props.actorUserId, props.tenantId, props.workflowId, props.userId, props.eligibilityRevision].join(':')} {...props} />;
}

function BoundDevicesPanel(props: OffboardingDevicesBinding) {
  const contentId = useId();
  const client = useRef<CompanyOffboardingDevicesClient | null>(null);
  const generation = useRef(0); const running = useRef(false);
  const [open, setOpen] = useState(false); const [busy, setBusy] = useState(false);
  const [error, setError] = useState(''); const [formError, setFormError] = useState('');
  const [preview, setPreview] = useState<OffboardingDevicesPreview | null>(null);
  const [history, setHistory] = useState<OffboardingDevicesHistory | null>(null);
  const [selected, setSelected] = useState<string[]>([]); const [reason, setReason] = useState('');
  const [confirmation, setConfirmation] = useState<{ intent: OffboardingDevicesIntent; recovery: boolean } | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [attempt, setAttempt] = useState<OffboardingDevicesIntent | null>(null);
  const [outcome, setOutcome] = useState<OffboardingDevicesOutcome | null>(null);
  const [readback, setReadback] = useState(false);

  const reset = () => {
    setPreview(null); setHistory(null); setSelected([]); setReason(''); setConfirmation(null); setConfirmed(false);
    setAttempt(null); setOutcome(null); setReadback(false); setBusy(false); setError(''); setFormError('');
  };
  const run = async <Value,>(operation: (current: CompanyOffboardingDevicesClient) => Promise<Value>, apply: (value: Value) => void) => {
    if (running.current || !client.current) return;
    const current = client.current; const expected = generation.current;
    running.current = true; setBusy(true); setError(''); setFormError('');
    try { const value = await operation(current); if (generation.current === expected) apply(value); }
    catch (failure) {
      if (generation.current === expected) {
        current.invalidate(); setPreview(null); setSelected([]); setConfirmation(null); setConfirmed(false);
        setReadback(true); setError(deviceReturnsError(failure));
      }
    } finally { if (generation.current === expected) { running.current = false; setBusy(false); } }
  };
  const load = (page = 1, historyPage = 1) => {
    if (running.current) return;
    setPreview(null); setHistory(null); setSelected([]); setConfirmation(null); setConfirmed(false);
    void run(async current => {
      await current.capabilities(); const nextPreview = await current.preview(page); const nextHistory = await current.history(historyPage);
      return { nextPreview, nextHistory };
    }, value => { setPreview(value.nextPreview); setHistory(value.nextHistory); setReadback(false); });
  };
  useEffect(() => {
    if (!open) return;
    generation.current++; running.current = false;
    try { client.current = new CompanyOffboardingDevicesClient(props); }
    catch { setError(deviceReturnsError(null)); return; }
    const current = client.current;
    const sessionError = () => {
      generation.current++; current.dispose(); client.current = null; running.current = false;
      reset(); setOpen(false); setError(deviceReturnsError({ response: { status: 401 } }));
    };
    window.addEventListener('od:session-error', sessionError); load();
    return () => {
      generation.current++; current.dispose(); client.current = null; running.current = false;
      window.removeEventListener('od:session-error', sessionError);
    };
  }, [open, props.actorUserId, props.tenantId, props.workflowId, props.userId, props.eligibilityRevision]);

  const begin = () => {
    if (busy || readback || !preview || !client.current) return;
    try {
      const intent = client.current.capture(preview, selected, { reason, confirm: true });
      setConfirmation({ intent, recovery: false }); setConfirmed(false); setFormError('');
    } catch { setFormError('Eine erlaubte Auswahl und eine Begründung mit 10 bis 500 Zeichen ohne Steuerzeichen sind erforderlich.'); }
  };
  const confirm = () => {
    if (busy || !confirmed || !confirmation) return;
    const pending = confirmation; setAttempt(pending.intent); setOutcome(null); setReadback(true); setPreview(null); setSelected([]);
    void run(current => current.request(pending.intent, pending.recovery), value => { setOutcome(value); setConfirmation(null); setConfirmed(false); });
  };
  const parent = { 'Vorgangs-ID der Kontosperre': props.workflowId, 'Benutzer-ID': props.userId, 'Berechtigungsversion der Kontosperre': props.eligibilityRevision, Mandant: props.tenantId };
  const canRecover = !busy && !readback && !!attempt && !!client.current?.canRecover(attempt);

  return <section aria-label="Geräterückgaben beim Austritt" className="rounded border border-white/10 p-4 space-y-4 min-w-0">
    <button className="fluent-btn-secondary" aria-expanded={open} aria-controls={contentId} onClick={() => {
      generation.current++; client.current?.dispose(); client.current = null; running.current = false; reset(); setOpen(value => !value);
    }}>Geräterückgaben beim Austritt planen</button>
    {error && !open && <p role="alert">{error}</p>}
    {open && <div id={contentId} className="space-y-4">
      <p>Separater Schritt nach belegter Kontosperre, auch bei noch offener lokaler Lizenzrückgabe. Nur ausgewählte aktuelle Gerätezuweisungen erhalten einen Rückgabeauftrag.</p>
      <p>Eine Anforderung ist keine physische Rückgabe. Die Geräte bleiben zugewiesen. Keine MDM-Befehle, keine Sperre, kein Wipe und kein vollständiger Austritt (WF004).</p>
      <p>Die ursprüngliche Kontosperre, aktuelle Berechtigung und frische MFA werden serverseitig geprüft. Bereits angeforderte Schritte bleiben bei späteren Fehlern erhalten. Keine automatische Wiederholung.</p>
      <Proof values={parent} />
      <a href="/device-returns" className="underline">Geräterückgaben bearbeiten</a>
      <div><button className="fluent-btn-secondary" disabled={busy || !!confirmation} onClick={() => load()}>Gerätevorschau und Rückgabehistorie neu laden</button></div>
      {busy && <p role="status">Geräterückgaben werden geprüft …</p>}
      {error && <p role="alert">{error}</p>}{formError && <p role="alert">{formError}</p>}
      {readback && <p role="status">Vor einem weiteren Schreibschritt Gerätevorschau und Rückgabehistorie ausdrücklich neu laden. Keine automatische Wiederholung.</p>}
      {preview && <section aria-label="Gerätevorschau für Rückgaben" className="space-y-3">
        <h4 className="font-semibold">Aktuell zugewiesene Geräte</h4>
        <p>{preview.devices.length} angezeigte von {preview.total} Zuweisungen. Nur die ausdrücklich ausgewählte Teilmenge dieser Seite, höchstens 25 Geräte, wird angefordert.</p>
        {!preview.devices.length && <p>Auf dieser Seite sind keine aktuellen Zuweisungen vorhanden. Dies bestätigt keine physische Rückgabe.</p>}
        <ul className="space-y-4">{preview.devices.map(device => <li key={device.deviceId}>
          <label className="flex items-start gap-3"><input type="checkbox" aria-label={`Rückgabe für ${device.assetId} auswählen`} checked={selected.includes(device.deviceId)} disabled={busy || !!confirmation || device.openRequestId !== null} onChange={event => setSelected(values => event.target.checked ? [...values, device.deviceId] : values.filter(value => value !== device.deviceId))} /><span className="break-words">{device.assetId} · Seriennummer {device.serialNumber} · Geräteversion {device.deviceRevision}</span></label>
          {device.openRequestId && <p>Rückgabe bereits angefordert – nicht erneut auswählbar.</p>}
          <Proof values={{ 'Geräte-ID': device.deviceId, 'Ursprüngliche Zuweisungs-ID': device.assignmentId, 'Offener Rückgabeauftrag': device.openRequestId || 'Keiner' }} />
        </li>)}</ul>
        <Pages page={preview.page} total={preview.total} disabled={busy || !!confirmation} label="Gerätevorschauseiten" onPage={page => load(page)} />
        <label className="block">Begründung für Rückgabeauftrag<textarea className="block w-full rounded border p-2 bg-transparent" value={reason} maxLength={1000} disabled={busy || !!confirmation} onChange={event => setReason(event.target.value)} /></label>
        <button className="fluent-btn-secondary" disabled={busy || !!confirmation || !selected.length} onClick={begin}>Ausgewählte Rückgaben anfordern</button>
      </section>}
      {attempt && <section aria-label="Wiederherstellung ursprünglicher Rückgabeaufträge" className="space-y-3">
        <p>Nach tatsächlicher Vorschau und Historie nur dieselben ursprünglichen Auftrags-IDs, Zuweisungen, Versionen und dieselbe Begründung wiederherstellen. Neue Zuweisungen bleiben unberührt und nicht ausgewählt.</p>
        <button className="fluent-btn-secondary" disabled={!canRecover || !!confirmation} onClick={() => { setConfirmation({ intent: attempt, recovery: true }); setConfirmed(false); }}>Ursprünglichen Versuch wiederherstellen</button>
      </section>}
      {outcome && <section aria-label="Ergebnis der Rückgabeanforderung" className="space-y-3">
        <h4 className="font-semibold">Letztes Anforderungsergebnis</h4>
        <p role="status">{outcome.results.some(result => result.status === 'unconfirmed') ? 'Anforderung nicht vollständig bestätigt. Bereits bestätigte Teilschritte bleiben bestehen.' : 'Ausgewählte ursprüngliche Rückgabeaufträge bestätigt. Keine physische Rückgabe bestätigt.'}</p>
        <ul className="space-y-3">{outcome.results.map(result => <li key={result.requestId}><p>{results[result.status]}{result.code !== null ? ` · Status ${result.code}` : ''}</p><Proof values={{ 'Geräte-ID': result.deviceId, 'Zuweisungs-ID': result.assignmentId, 'Rückgabeauftrag-ID': result.requestId, 'Operations-ID': result.operationId || 'Nicht bestätigt' }} /></li>)}</ul>
        <Proof values={{ 'Korrelations-ID': outcome.correlationId }} />
      </section>}
      <section aria-label="Rückgabehistorie beim Austritt" className="space-y-3">
        <h4 className="font-semibold">Dauerhafte Rückgabeaufträge</h4>
        {!history ? <p>Rückgabehistorie ausdrücklich neu laden.</p> : <>
          {readback && <p>Historie vom letzten Abruf; nach dem Schreibversuch ausdrücklich neu laden.</p>}
          {!history.requests.length && <p>Auf dieser Seite sind keine Rückgabeaufträge vorhanden.</p>}
          <ol className="space-y-4">{history.requests.map(request => <li key={request.id}>
            <p>{request.assetId} · Seriennummer {request.serialNumber} · {states[request.status]}</p><p>Begründung: {request.reason} · Ereigniszustellung ausstehend</p>
            <Proof values={{ 'Rückgabeauftrag-ID': request.id, 'Geräte-ID': request.deviceId, 'Ursprüngliche Zuweisungs-ID': request.assignmentId, 'Benutzer-ID': request.userId,
              'Auftragsversion': request.revision, 'Geräteversion bei Anforderung': request.deviceRevision, 'Aktuelle Geräteversion': request.currentDeviceRevision,
              'Angefordert von': request.actorUserId, 'Angefordert am': request.requestedAt, 'Abgeschlossen am': request.closedAt || 'Nicht abgeschlossen',
              'Abgeschlossen von': request.closedByUserId || 'Nicht abgeschlossen', 'Anforderungsereignis': request.operationId,
              'Entscheidungsereignis': request.closingOperationId || 'Keines', 'Inventarereignis': request.inventoryOperationId || 'Keines' }} />
          </li>)}</ol>
          <Pages page={history.page} total={history.total} disabled={busy || !!confirmation || readback} label="Rückgabehistorienseiten" onPage={page => load(preview?.page || 1, page)} />
        </>}
      </section>
      {confirmation && <DirectoryConfirmation title={confirmation.recovery ? 'Ursprüngliche Rückgabeaufträge bestätigen' : 'Rückgabeaufträge bestätigen'} busy={busy} error={confirmed ? '' : 'Bitte genau diese ursprünglichen Gerätezuweisungen bestätigen.'} onClose={() => { setConfirmation(null); setConfirmed(false); }} onConfirm={confirm}>
        <div className="max-h-[55vh] overflow-y-auto space-y-3 break-words">
          <p>{confirmation.recovery ? 'Denselben ursprünglichen Versuch wiederherstellen:' : 'Genau diese Rückgabeaufträge anfordern:'} {confirmation.intent.items.length}.</p>
          <ul className="space-y-3">{confirmation.intent.items.map(item => {
            const device = confirmation.intent.snapshot.devices.find(value => value.deviceId === item.deviceId);
            return <li key={item.requestId}><p>{device.assetId} · Seriennummer {device.serialNumber}</p><Proof values={{ 'Geräte-ID': item.deviceId, 'Geräteversion': item.deviceRevision, 'Ursprüngliche Zuweisungs-ID': item.assignmentId, 'Rückgabeauftrag-ID': item.requestId }} /></li>;
          })}</ul>
          <p>Begründung: {confirmation.intent.reason}</p><Proof values={parent} />
          <p>Keine Freigabe oder physische Rückgabe des Geräts. Keine neuen Zuweisungen als Ersatz. Bereits bestätigte Teilschritte bleiben bestehen.</p>
          <label className="flex gap-3"><input type="checkbox" checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)} /><span>Ich bestätige genau diese ursprünglichen Gerätezuweisungen.</span></label>
        </div>
      </DirectoryConfirmation>}
    </div>}
  </section>;
}
