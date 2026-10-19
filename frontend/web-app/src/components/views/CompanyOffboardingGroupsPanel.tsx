'use client';

import React, { useEffect, useId, useRef, useState } from 'react';
import type { OffboardingContext } from '@/lib/companyOffboarding';
import { CompanyOffboardingGroupsClient, OffboardingGroupsPreview, OffboardingGroupsHistory, OffboardingGroupsOutcome, offboardingGroupsError, offboardingGroupsReason } from '@/lib/companyOffboardingGroups';
import { DirectoryConfirmation } from './UserDetailPanel';

type Props = { context: OffboardingContext; workflowId: string; userId: string; eligibilityRevision: string };
type Confirmation = { preview: OffboardingGroupsPreview; reason: string };
type Outcome = { preview: OffboardingGroupsPreview; result: OffboardingGroupsOutcome };
const statuses = { removed: 'Entfernt', already_removed: 'Bereits entfernt – ursprünglicher Nachweis', unconfirmed: 'Nicht bestätigt', not_attempted: 'Nicht versucht' };

function Proof({ values }: { values: Record<string, string> }) {
  return <details><summary className="cursor-pointer">Nachweis</summary><dl className="mt-3 space-y-2 text-sm">{Object.entries(values).map(([label, value]) => <div key={label}><dt className="opacity-70">{label}</dt><dd className="break-all">{value}</dd></div>)}</dl></details>;
}
function Pages({ page, total, busy, label, onPage }: { page: number; total: number; busy: boolean; label: string; onPage: (page: number) => void }) {
  return <nav aria-label={label} className="flex flex-wrap items-center gap-4 text-sm">
    <button disabled={busy || page <= 1} onClick={() => onPage(page - 1)}>Zurück</button>
    <span>Seite {page} · {total} Einträge</span>
    <button disabled={busy || page * 25 >= total} onClick={() => onPage(page + 1)}>Weiter</button>
  </nav>;
}

export default function CompanyOffboardingGroupsPanel(props: Props) {
  return <BoundGroupsPanel key={[props.context.actorUserId, props.context.tenantId, props.workflowId, props.userId, props.eligibilityRevision].join(':')} {...props} />;
}

function BoundGroupsPanel({ context, workflowId, userId, eligibilityRevision }: Props) {
  const contentId = useId();
  const client = useRef<CompanyOffboardingGroupsClient | null>(null);
  const generation = useRef(0);
  const running = useRef(false);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [formError, setFormError] = useState('');
  const [preview, setPreview] = useState<OffboardingGroupsPreview | null>(null);
  const [history, setHistory] = useState<OffboardingGroupsHistory | null>(null);
  const [reason, setReason] = useState('');
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [readback, setReadback] = useState(false);

  const run = async <Value,>(operation: (current: CompanyOffboardingGroupsClient) => Promise<Value>, apply: (value: Value) => void) => {
    if (running.current || !client.current) return;
    const current = client.current; const expected = generation.current;
    running.current = true; setBusy(true); setError(''); setFormError('');
    try { const value = await operation(current); if (generation.current === expected) apply(value); }
    catch (failure) {
      if (generation.current === expected) { current.invalidate(); setPreview(null); setConfirmation(null); setReadback(true); setError(offboardingGroupsError(failure)); }
    } finally { if (generation.current === expected) { running.current = false; setBusy(false); } }
  };
  const load = (page = 1, historyPage = 1) => {
    if (running.current) return;
    setPreview(null); setConfirmation(null);
    void run(async current => {
      const nextPreview = await current.preview(page); const nextHistory = await current.history(historyPage);
      return { nextPreview, nextHistory };
    }, ({ nextPreview, nextHistory }) => { setPreview(nextPreview); setHistory(nextHistory); setReadback(false); });
  };
  useEffect(() => {
    if (!open) return;
    generation.current += 1; running.current = false;
    let current: CompanyOffboardingGroupsClient;
    try { current = new CompanyOffboardingGroupsClient({ ...context, workflowId, userId, eligibilityRevision }); }
    catch { setError(offboardingGroupsError(null)); return; }
    client.current = current;
    const onSessionError = () => {
      generation.current += 1; current.invalidate(); running.current = false; setBusy(false);
      setPreview(null); setHistory(null); setConfirmation(null); setOutcome(null); setReason(''); setReadback(true);
      setError(offboardingGroupsError({ response: { status: 401 } }));
    };
    window.addEventListener('od:session-error', onSessionError);
    load();
    return () => {
      generation.current += 1; current.dispose(); client.current = null;
      window.removeEventListener('od:session-error', onSessionError);
    };
  }, [open, context.actorUserId, context.tenantId, workflowId, userId, eligibilityRevision]);

  const begin = () => {
    if (busy || !preview || !preview.groups.length || readback) return;
    try { setConfirmation({ preview, reason: offboardingGroupsReason(reason) }); setFormError(''); }
    catch { setFormError('Bitte eine Begründung mit 10 bis 500 Zeichen ohne Steuerzeichen eingeben.'); }
  };
  const confirm = () => {
    if (busy || !confirmation) return;
    const pending = confirmation;
    setPreview(null); setReadback(true);
    void run(current => current.remove(pending.preview, { reason: pending.reason, confirm: true }), result => {
      setOutcome({ preview: pending.preview, result }); setConfirmation(null);
    });
  };
  const parentProof = { 'Vorgangs-ID der Kontosperre': workflowId, 'Benutzer-ID': userId, 'Berechtigungsversion der Kontosperre': eligibilityRevision, 'Ausgeführt von': context.actorUserId, Mandant: context.tenantId };

  return <section aria-label="Gruppenbereinigung beim Austritt" className="rounded border border-white/10 p-4 space-y-4 min-w-0">
    <button className="fluent-btn-secondary" aria-expanded={open} aria-controls={contentId} disabled={busy} onClick={() => {
      setOpen(value => !value); setPreview(null); setHistory(null); setConfirmation(null); setError(''); setFormError('');
    }}>Gruppen beim Austritt entfernen</button>
    {open && <div id={contentId} className="space-y-4">
      <p>Separater, ausdrücklich bestätigter Schritt nach belegter Kontosperre, auch bei noch offener oder pausierter lokaler Lizenzrückgabe. Nur die angezeigten kanonischen Gruppenmitgliedschaften werden mit dem ursprünglichen Austrittsvorgang verknüpft entfernt.</p>
      <p className="text-sm">Rollen, PIM, Organisationseinheiten (OU), Geräte und Zugangsdaten externer Anbieter werden nicht entfernt. Entfernt werden nur die aufgeführten kanonischen Gruppenmitgliedschaften; das bestätigt keinen vollständigen Berechtigungsentzug oder Austritt (WF004).</p>
      <p className="text-sm">Der Server prüft bei jedem Schritt die tatsächliche Quellfreigabe, Berechtigung, frische MFA, Kontogeneration und Mitgliedschaft erneut. Spätere neue Mitgliedschaften werden durch die Wiederherstellung eines ursprünglichen Nachweises nicht entfernt. Bereits bestätigte Schritte bleiben bei Fehlern wirksam.</p>
      <Proof values={parentProof} />
      <button className="fluent-btn-secondary" disabled={busy || !!confirmation} onClick={() => load()}>Gruppenvorschau und Historie neu laden</button>
      {busy && <p role="status">Gruppenarbeitsstand wird geprüft …</p>}
      {error && <p role="alert">{error}</p>}
      {formError && <p role="alert">{formError}</p>}
      {readback && <p role="status">Vor einem weiteren Schreibschritt Gruppenvorschau und Historie ausdrücklich neu laden. Keine automatische Wiederholung.</p>}
      {preview && <section aria-label="Gruppenvorschau" className="space-y-3">
        <h4 className="font-semibold">Aktuelle Gruppenmitgliedschaften</h4>
        <p>{preview.groups.length} angezeigte von {preview.total} derzeitigen Gruppenmitgliedschaften. Bestätigt wird nur diese Seite mit höchstens 25 Gruppen.</p>
        {!preview.groups.length && <p>Auf dieser Seite sind derzeit keine Gruppenmitgliedschaften vorhanden. Daraus folgt kein vollständiger Zugriffsverlust.</p>}
        <ul className="space-y-3">{preview.groups.map(group => <li key={group.groupId} className="break-words">
          <p>{group.name} · Gruppenversion {group.groupRevision}</p>
          <Proof values={{ 'Gruppen-ID': group.groupId, 'Mitgliedschafts-ID': group.membershipId }} />
        </li>)}</ul>
        <Pages page={preview.page} total={preview.total} busy={busy || !!confirmation} label="Gruppenvorschauseiten" onPage={page => load(page)} />
        <label className="block text-sm">Begründung für Gruppenentfernung<input className="mt-1 block w-full rounded border p-2 bg-transparent" value={reason} maxLength={1000} disabled={busy || !!confirmation} onChange={event => setReason(event.target.value)} /></label>
        <button className="fluent-btn-secondary" disabled={busy || !!confirmation || !preview.groups.length} onClick={begin}>Angezeigte Gruppen entfernen</button>
      </section>}
      {outcome && <section aria-label="Ergebnis der Gruppenentfernung" className="space-y-3">
        <h4 className="font-semibold">Letztes Gruppenergebnis</h4>
        <p role="status">{outcome.result.results.some(result => result.status === 'unconfirmed')
          ? outcome.result.results.some(result => result.status === 'removed' || result.status === 'already_removed')
            ? 'Gruppenentfernung teilweise bestätigt. Bereits bestätigte Schritte bleiben wirksam. Vorschau und Historie ausdrücklich neu laden.'
            : 'Keine Gruppenentfernung bestätigt. Vorschau und Historie ausdrücklich neu laden. Frühere bestätigte Schritte bleiben wirksam.'
          : 'Angezeigte Gruppenentfernungen bestätigt. Vorschau und Historie ausdrücklich neu laden.'}</p>
        <ul className="space-y-3">{outcome.result.results.map((result, index) => <li key={result.groupId} className="break-words">
          <p>{outcome.preview.groups[index].name} · {statuses[result.status]}{result.code !== null ? ` · Status ${result.code}` : ''}</p>
          <Proof values={{ 'Gruppen-ID': result.groupId, 'Mitgliedschafts-ID': result.membershipId, 'Operations-ID': result.operationId || 'Kein bestätigter Nachweis' }} />
        </li>)}</ul>
        <Proof values={{ ...parentProof, 'Korrelations-ID': outcome.result.correlationId }} />
      </section>}
      <section aria-label="Gruppenentfernungs-Historie" className="space-y-3">
        <h4 className="font-semibold">Dauerhafte Gruppenhistorie</h4>
        <p>Ursprüngliche Nachweise bleiben erhalten. Frühere Gruppenentfernungen werden bei späteren Fehlern nicht zurückgerollt.</p>
        {readback && history && <p>Historie vom letzten Abruf; nach dem Schreibversuch ausdrücklich neu laden.</p>}
        {!history ? <p>Historie über „Gruppenvorschau und Historie neu laden“ abrufen.</p> : <>
          {!history.receipts.length && <p>Auf dieser Seite sind keine Gruppenentfernungsnachweise vorhanden.</p>}
          <ol className="space-y-3">{history.receipts.map(receipt => <li key={receipt.id} className="break-words">
            <p>{receipt.name} · Gruppenversion {receipt.beforeGroupRevision} → {receipt.afterGroupRevision}</p>
            <p>{new Date(receipt.createdAt).toLocaleString('de-CH')} · Ereigniszustellung ausstehend</p>
            <p>Begründung: {receipt.reason}</p>
            <Proof values={{ 'Nachweis-ID': receipt.id, 'Gruppen-ID': receipt.groupId, 'Mitgliedschafts-ID': receipt.membershipId, 'Operations-ID': receipt.operationId, 'Ausgeführt von': receipt.actorUserId }} />
          </li>)}</ol>
          <Pages page={history.page} total={history.total} busy={busy || !!confirmation || readback} label="Gruppenhistorienseiten" onPage={page => {
            setConfirmation(null); void run(current => current.history(page), setHistory);
          }} />
        </>}
      </section>
      {confirmation && <DirectoryConfirmation title="Gruppenentfernung bestätigen" busy={busy} error="" onClose={() => setConfirmation(null)} onConfirm={confirm}>
        <div className="max-h-[55vh] overflow-y-auto space-y-3 break-words">
          <p>Genau diese {confirmation.preview.groups.length} angezeigten Gruppenmitgliedschaften entfernen. Weitere Seiten benötigen eine neue Vorschau und Bestätigung.</p>
          <ul className="space-y-2">{confirmation.preview.groups.map(group => <li key={group.groupId}>
            <p>{group.name} · Gruppenversion {group.groupRevision}</p>
            <Proof values={{ 'Gruppen-ID': group.groupId, 'Mitgliedschafts-ID': group.membershipId }} />
          </li>)}</ul>
          <p>Begründung: {confirmation.reason}</p>
          <Proof values={parentProof} />
          <p>Nur diese Mitgliedschaften im verknüpften Austrittsvorgang. Rollen, PIM, OU, Geräte und externe Zugangsdaten bleiben unverändert. Bereits gespeicherte Schritte bleiben bei Fehlern wirksam; keine automatische Wiederholung.</p>
        </div>
      </DirectoryConfirmation>}
    </div>}
  </section>;
}
