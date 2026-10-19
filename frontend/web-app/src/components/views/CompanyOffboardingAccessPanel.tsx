'use client';

import React, { useEffect, useId, useRef, useState } from 'react';
import {
  CompanyOffboardingAccessClient, OffboardingAccessBinding, OffboardingAccessCapabilities, OffboardingAccessHistory,
  OffboardingAccessIntent, OffboardingAccessKind, OffboardingAccessOutcome, OffboardingAccessPreview, offboardingAccessError,
} from '@/lib/companyOffboardingAccess';
import { DirectoryConfirmation } from './UserDetailPanel';

const labels = { role: 'Rollen', eligibility: 'PIM-Berechtigungen' };
const statuses = { revoked: 'Widerrufen', already_revoked: 'Bereits widerrufen – ursprünglicher Nachweis', unconfirmed: 'Nicht bestätigt', not_attempted: 'Nicht versucht' };
const date = (value: string) => new Date(value).toLocaleString('de-CH');

function Proof({ values }: { values: Record<string, string> }) {
  return <details><summary className="cursor-pointer">Nachweis</summary><dl className="mt-3 space-y-2 text-sm">{Object.entries(values).map(([label, value]) => <div key={label}><dt className="opacity-70">{label}</dt><dd className="break-all">{value}</dd></div>)}</dl></details>;
}
function Pages({ page, total, busy, label, onPage }: { page: number; total: number; busy: boolean; label: string; onPage: (page: number) => void }) {
  return <nav aria-label={label} className="flex flex-wrap gap-4 text-sm">
    <button disabled={busy || page <= 1} onClick={() => onPage(page - 1)}>Zurück</button>
    <span>Seite {page} · {total} Einträge</span>
    <button disabled={busy || page >= 1000000 || page * 25 >= total} onClick={() => onPage(page + 1)}>Weiter</button>
  </nav>;
}

export default function CompanyOffboardingAccessPanel(props: OffboardingAccessBinding) {
  return <BoundAccessPanel key={[props.expectedActorUserId, props.tenantId, props.userId, props.workflowId, props.eligibilityRevision].join(':')} {...props} />;
}

function BoundAccessPanel(props: OffboardingAccessBinding) {
  const contentId = useId();
  const client = useRef<CompanyOffboardingAccessClient | null>(null);
  const generation = useRef(0);
  const running = useRef(false);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [formError, setFormError] = useState('');
  const [capabilities, setCapabilities] = useState<OffboardingAccessCapabilities | null>(null);
  const [selectedKind, setSelectedKind] = useState<OffboardingAccessKind>('role');
  const [preview, setPreview] = useState<OffboardingAccessPreview | null>(null);
  const [history, setHistory] = useState<OffboardingAccessHistory | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [reason, setReason] = useState('');
  const [confirmation, setConfirmation] = useState<{ intent: OffboardingAccessIntent; recovery: boolean } | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [attempt, setAttempt] = useState<OffboardingAccessIntent | null>(null);
  const [outcome, setOutcome] = useState<{ intent: OffboardingAccessIntent; result: OffboardingAccessOutcome } | null>(null);
  const [readback, setReadback] = useState(false);

  const run = async <Value,>(operation: (current: CompanyOffboardingAccessClient) => Promise<Value>, apply: (value: Value) => void) => {
    if (running.current || !client.current) return;
    const current = client.current; const expected = generation.current;
    running.current = true; setBusy(true); setError(''); setFormError('');
    try { const value = await operation(current); if (generation.current === expected) apply(value); }
    catch (failure) {
      if (generation.current === expected) {
        current.invalidate(); setCapabilities(null); setPreview(null); setSelected([]); setConfirmation(null); setConfirmed(false);
        setReadback(true); setError(offboardingAccessError(failure));
      }
    } finally { if (generation.current === expected) { running.current = false; setBusy(false); } }
  };
  const load = (requestedKind?: OffboardingAccessKind, page = 1, historyPage = 1) => {
    if (running.current) return;
    setPreview(null); setHistory(null); setSelected([]); setConfirmation(null); setConfirmed(false);
    void run(async current => {
      const access = await current.capabilities();
      const nextKind = requestedKind && access.supportedKinds.includes(requestedKind) ? requestedKind : access.supportedKinds[0];
      const nextPreview = await current.preview(nextKind, page); const nextHistory = await current.history(nextKind, historyPage);
      return { access, nextKind, nextPreview, nextHistory };
    }, value => { setCapabilities(value.access); setSelectedKind(value.nextKind); setPreview(value.nextPreview); setHistory(value.nextHistory); setReadback(false); });
  };
  useEffect(() => {
    if (!open) return;
    generation.current += 1; running.current = false;
    let current: CompanyOffboardingAccessClient;
    try { current = new CompanyOffboardingAccessClient(props); }
    catch { setError(offboardingAccessError(null)); return; }
    client.current = current;
    const onSessionError = () => {
      generation.current += 1; current.invalidate(); running.current = false; setBusy(false);
      setCapabilities(null); setPreview(null); setHistory(null); setSelected([]); setConfirmation(null); setConfirmed(false);
      setAttempt(null); setOutcome(null); setReason(''); setReadback(true); setError(offboardingAccessError({ response: { status: 401 } }));
    };
    window.addEventListener('od:session-error', onSessionError); load();
    return () => {
      generation.current += 1; current.dispose(); client.current = null;
      window.removeEventListener('od:session-error', onSessionError);
    };
  }, [open, props.expectedActorUserId, props.tenantId, props.userId, props.workflowId, props.eligibilityRevision]);

  const begin = () => {
    if (busy || !preview || readback || !client.current) return;
    try {
      const intent = client.current.capture(preview, preview.items.filter(item => selected.includes(item.id)).map(item => item.id), { reason, confirm: true });
      setConfirmation({ intent, recovery: false }); setConfirmed(false); setFormError('');
    } catch { setFormError('Eine erlaubte Auswahl und eine Begründung mit 10 bis 500 Zeichen ohne Steuerzeichen sind erforderlich.'); }
  };
  const confirm = () => {
    if (busy || !confirmation || !confirmed) return;
    const pending = confirmation;
    setAttempt(pending.intent); setPreview(null); setReadback(true); setSelected([]);
    void run(current => current.revoke(pending.intent, pending.recovery), result => {
      setOutcome({ intent: pending.intent, result }); setConfirmation(null); setConfirmed(false);
      if (!result.results.some(item => item.status === 'unconfirmed')) setAttempt(null);
    });
  };
  const parentProof = { 'Vorgangs-ID der Kontosperre': props.workflowId, 'Benutzer-ID': props.userId, 'Ausgeführt von': props.expectedActorUserId,
    Mandant: capabilities?.tenantId || props.tenantId || 'Noch nicht bestätigt',
    'Berechtigungsversion der Kontosperre': capabilities?.target.eligibilityRevision || props.eligibilityRevision || 'Noch nicht bestätigt' };
  const canRecover = !!attempt && !busy && !readback && !!preview?.canRevoke && preview.kind === attempt.snapshot.kind && history?.kind === attempt.snapshot.kind;

  return <section aria-label="Rollen- und PIM-Bereinigung beim Austritt" className="rounded border border-white/10 p-4 space-y-4 min-w-0">
    <button className="fluent-btn-secondary" aria-expanded={open} aria-controls={contentId} disabled={busy} onClick={() => {
      setOpen(value => !value); setCapabilities(null); setPreview(null); setHistory(null); setSelected([]); setConfirmation(null); setConfirmed(false);
      setAttempt(null); setOutcome(null); setError(''); setFormError(''); setReason('');
    }}>Rollen und PIM beim Austritt bereinigen</button>
    {open && <div id={contentId} className="space-y-4">
      <p>Separater Schritt nach belegter Kontosperre, auch bei offener oder pausierter Lizenzrückgabe. Nur ausdrücklich ausgewählte ursprüngliche Zuweisungen werden widerrufen, nicht automatisch alle Rollen oder alle Seiten.</p>
      <p>Separate kanonische Lese- und Verwaltungsrechte je Bereich sind erforderlich. Firmen-Ownership verleiht keine Adminrechte. Geschützte Rollen bleiben ohne tatsächliche Adminberechtigung gesperrt.</p>
      <p className="text-sm">Der Server prüft die ursprüngliche menschliche Sitzung, frische MFA (höchstens 300 Sekunden), Mandant und negative Kontogeneration bei jedem Schritt erneut. PIM-Widerruf verwendet die bestehende Kaskade für verknüpfte Aktivierungen. Keine manuellen Ersatzaktionen oder automatische Wiederholung.</p>
      <p className="text-sm">Gruppen, OU, Geräte, externe Zugangsdaten und übrige Austrittsschritte werden hier nicht bereinigt. Dies bestätigt keinen vollständigen Berechtigungsentzug oder Austritt (WF004). Bereits bestätigte Teilschritte bleiben wirksam.</p>
      <Proof values={parentProof} />
      <button className="fluent-btn-secondary" disabled={busy || !!confirmation} onClick={() => load(selectedKind)}>Vorschau und Historie neu laden</button>
      {busy && <p role="status">Berechtigungsarbeitsstand wird geprüft …</p>}
      {error && <p role="alert">{error}</p>}{formError && <p role="alert">{formError}</p>}
      {readback && <p role="status">Vor einem weiteren Schreibschritt Vorschau und Historie ausdrücklich neu laden. Ein unbestätigter Versuch kann bereits wirksam sein.</p>}
      {capabilities && <div role="tablist" aria-label="Berechtigungsbereich" className="flex gap-4">{capabilities.supportedKinds.map(value => <button key={value} role="tab" aria-selected={selectedKind === value} disabled={busy || !!confirmation} onClick={() => { setReason(''); load(value); }}>{labels[value]}</button>)}</div>}
      {preview && <section aria-label="Rollen- und PIM-Vorschau" className="space-y-3">
        <h4 className="font-semibold">{labels[preview.kind]} – nicht widerrufene Zuweisungen</h4>
        <p>{preview.items.length} angezeigte von {preview.total} nicht widerrufenen Zuweisungen. Auch abgelaufene Einträge sind enthalten; „nicht widerrufen“ bedeutet nicht „aktuell wirksam“.</p>
        {!preview.canRevoke && <p>Nur Lesezugriff. Das separate Verwaltungsrecht für diesen Bereich fehlt.</p>}
        {!preview.items.length && <p>Auf dieser Seite sind keine nicht widerrufenen Zuweisungen vorhanden. Das bestätigt keinen vollständigen Zugriffsverlust.</p>}
        <ul className="space-y-3">{preview.items.map(item => <li key={item.id} className="break-words rounded border border-white/10 p-3">
          <label className="flex items-start gap-3"><input type="checkbox" aria-label={`Zuweisung auswählen: ${item.role} · ${item.id}`} disabled={busy || !!confirmation || !item.canRevoke} checked={selected.includes(item.id)} onChange={event => setSelected(values => event.target.checked ? [...values, item.id] : values.filter(value => value !== item.id))} /><span>{item.role}</span></label>
          <p>Erstellt: {date(item.createdAt)} · {item.expiresAt === null ? 'Kein Ablaufdatum' : `${Date.parse(item.expiresAt) <= Date.now() ? 'Abgelaufen' : 'Ablauf'}: ${date(item.expiresAt)}`}</p>
          {item.blockedReason && <p>{item.blockedReason === 'protected_role' ? 'Geschützte Rolle – tatsächliche Adminberechtigung erforderlich.' : 'Verwaltungsberechtigung fehlt.'}</p>}
          <Proof values={{ 'Zuweisungs-ID': item.id, 'Ursprüngliche Version (SHA-256)': item.version }} />
        </li>)}</ul>
        <Pages page={preview.page} total={preview.total} busy={busy || !!confirmation} label="Berechtigungsvorschauseiten" onPage={page => load(selectedKind, page)} />
        <label className="block text-sm">Begründung für Berechtigungsentzug<input className="mt-1 block w-full rounded border p-2 bg-transparent" value={reason} maxLength={1000} disabled={busy || !!confirmation || !preview.canRevoke} onChange={event => setReason(event.target.value)} /></label>
        <p>{selected.length} von höchstens 25 ursprünglichen Zuweisungen ausgewählt.</p>
        <button className="fluent-btn-secondary" disabled={busy || !!confirmation || !preview.canRevoke || !selected.length} onClick={begin}>Ausgewählte Zuweisungen widerrufen</button>
      </section>}
      {attempt && <section aria-label="Wiederherstellung des ursprünglichen Versuchs" className="space-y-3">
        <p>Nur dieselben ursprünglichen IDs und Versionen wiederherstellen. Neue Zuweisungen werden nicht als Ersatz verwendet. Zuerst den betreffenden Bereich, Vorschau und Historie ausdrücklich neu laden.</p>
        <button className="fluent-btn-secondary" disabled={!canRecover || !!confirmation} onClick={() => { setConfirmation({ intent: attempt, recovery: true }); setConfirmed(false); }}>Ursprünglichen Versuch wiederherstellen</button>
      </section>}
      {outcome && <section aria-label="Ergebnis des Berechtigungsentzugs" className="space-y-3">
        <h4 className="font-semibold">Letztes Ergebnis – {labels[outcome.intent.snapshot.kind]}</h4>
        <p role="status">{outcome.result.results.some(result => result.status === 'unconfirmed') ? 'Berechtigungsentzug nicht vollständig bestätigt. Bestätigte Teilschritte bleiben wirksam.' : 'Nur die ausgewählten ursprünglichen Zuweisungen sind bestätigt widerrufen.'} Vorschau und Historie ausdrücklich neu laden.</p>
        <ul className="space-y-3">{outcome.result.results.map((result, index) => <li key={result.id} className="break-words">
          <p>{outcome.intent.items[index].role} · {statuses[result.status]}{result.code !== null ? ` · Status ${result.code}` : ''}</p>
          <Proof values={{ 'Zuweisungs-ID': result.id, 'Ursprüngliche Version (SHA-256)': outcome.intent.items[index].version, 'Checkpoint-ID': result.checkpointId || 'Kein bestätigter Nachweis' }} />
        </li>)}</ul>
        <Proof values={{ ...parentProof, 'Korrelations-ID': outcome.result.correlationId }} />
      </section>}
      <section aria-label="Berechtigungsentzugs-Historie" className="space-y-3">
        <h4 className="font-semibold">Dauerhafte Nachweise</h4>
        {!history ? <p>Historie über „Vorschau und Historie neu laden“ abrufen.</p> : <>
          {readback && <p>Historie vom letzten Abruf; nach dem Schreibversuch ausdrücklich neu laden.</p>}
          {!history.receipts.length && <p>Auf dieser Seite sind keine Widerrufsnachweise vorhanden.</p>}
          <ol className="space-y-3">{history.receipts.map(receipt => <li key={receipt.id} className="break-words">
            <p>{receipt.role} · {labels[receipt.kind]} · {date(receipt.createdAt)} · Ereigniszustellung ausstehend</p>
            <p>Begründung: {receipt.reason}</p>
            <Proof values={{ 'Nachweis-ID': receipt.id, 'Zuweisungs-ID': receipt.resourceId, 'Ursprüngliche Version (SHA-256)': receipt.version,
              'Checkpoint-ID': receipt.checkpointId, 'Ausgeführt von': receipt.actorUserId, 'Korrelations-ID': receipt.correlationId }} />
          </li>)}</ol>
          <Pages page={history.page} total={history.total} busy={busy || !!confirmation || readback} label="Berechtigungshistorienseiten" onPage={page => load(selectedKind, preview?.page || 1, page)} />
        </>}
      </section>
      {confirmation && <DirectoryConfirmation title={confirmation.recovery ? 'Ursprünglichen Versuch bestätigen' : 'Berechtigungsentzug bestätigen'} busy={busy} error={confirmed ? '' : 'Bitte genau diese ursprüngliche Auswahl bestätigen.'} onClose={() => { setConfirmation(null); setConfirmed(false); }} onConfirm={confirm}>
        <div className="max-h-[55vh] overflow-y-auto space-y-3 break-words">
          <p>{confirmation.recovery ? 'Nur denselben ursprünglichen Versuch wiederherstellen:' : 'Genau diese ursprünglichen Zuweisungen widerrufen:'} {confirmation.intent.items.length} · {labels[confirmation.intent.snapshot.kind]}.</p>
          <ul className="space-y-3">{confirmation.intent.items.map(item => <li key={item.id}><p>{item.role}</p><Proof values={{ 'Zuweisungs-ID': item.id, 'Ursprüngliche Version (SHA-256)': item.version }} /></li>)}</ul>
          <p>Begründung: {confirmation.intent.reason}</p><Proof values={parentProof} />
          {confirmation.intent.snapshot.kind === 'eligibility' && <p>Die bestehende PIM-Kaskade kann verknüpfte Aktivierungen und zugehörige Rollenzuweisungen widerrufen. Keine pauschale Aussage über andere Berechtigungen.</p>}
          <p>Bereits bestätigte Teilschritte bleiben wirksam. Keine automatische Wiederholung und keine neuen Zuweisungen als Ersatz.</p>
          <label className="flex gap-3"><input type="checkbox" checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)} /><span>Ich bestätige genau diese ursprünglichen Zuweisungen.</span></label>
        </div>
      </DirectoryConfirmation>}
    </div>}
  </section>;
}
