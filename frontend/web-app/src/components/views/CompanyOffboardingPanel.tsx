'use client';

import React, { useEffect, useRef, useState } from 'react';
import { CompanyOffboardingClient, OffboardingContext, OffboardingHistory, OffboardingJob, OffboardingPage, OffboardingPreview, needsOffboardingPreview, offboardingError, offboardingReason, offboardingTargetChanged, offboardingUserId } from '@/lib/companyOffboarding';
import { DirectoryConfirmation } from './UserDetailPanel';
import CompanyOffboardingGroupsPanel from './CompanyOffboardingGroupsPanel';
import CompanyOffboardingAccessPanel from './CompanyOffboardingAccessPanel';
import CompanyOffboardingDevicesPanel from './CompanyOffboardingDevicesPanel';

const phases = { pending: 'Kontosperre ausstehend', licenses: 'Lokale Lizenzrückgabe läuft', paused: 'Pausiert – Prüfung erforderlich', completed_local: 'Kontosperre und lokale Lizenzen geprüft' };
const steps = { account: 'Kontosperre', capture: 'Erfassung der lokalen Lizenzen', licenses: 'Lokale Lizenzrückgabe', verify: 'Abschlussprüfung' };
const date = (value: string) => new Date(value).toLocaleString('de-CH', { dateStyle: 'medium', timeStyle: 'short' });
type Confirmation = { kind: 'create'; preview: OffboardingPreview; reason: string } | { kind: 'continue'; job: OffboardingJob; preview?: OffboardingPreview; reason: string };

function Pages({ page, total, busy, label, onPage }: { page: number; total: number; busy: boolean; label: string; onPage: (page: number) => void }) {
  return <nav aria-label={label} className="flex gap-4 items-center text-sm">
    <button disabled={busy || page <= 1} onClick={() => onPage(page - 1)}>Zurück</button>
    <span>Seite {page} · {total} Einträge</span>
    <button disabled={busy || page * 25 >= total} onClick={() => onPage(page + 1)}>Weiter</button>
  </nav>;
}
function Proof({ values }: { values: Record<string, string | null> }) {
  return <details><summary className="cursor-pointer">Nachweis</summary><dl className="text-sm space-y-2 mt-3">{Object.entries(values).map(([label, value]) => <div key={label}><dt className="opacity-70">{label}</dt><dd className="break-all">{value || '—'}</dd></div>)}</dl></details>;
}

export default function CompanyOffboardingPanel({ context }: { context: OffboardingContext }) {
  const client = useRef<CompanyOffboardingClient | null>(null);
  const generation = useRef(0);
  const running = useRef(false);
  const [open, setOpen] = useState(false);
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [formError, setFormError] = useState('');
  const [queue, setQueue] = useState<OffboardingPage | null>(null);
  const [targetId, setTargetId] = useState('');
  const [preview, setPreview] = useState<OffboardingPreview | null>(null);
  const [resumePreview, setResumePreview] = useState<OffboardingPreview | null>(null);
  const [reason, setReason] = useState('');
  const [job, setJob] = useState<OffboardingJob | null>(null);
  const [snapshotReady, setSnapshotReady] = useState(false);
  const [history, setHistory] = useState<OffboardingHistory | null>(null);
  const [workflowId, setWorkflowId] = useState('');
  const [recoveryId, setRecoveryId] = useState<string | null>(null);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);

  const clear = () => { setQueue(null); setPreview(null); setResumePreview(null); setJob(null); setHistory(null); setSnapshotReady(false); setConfirmation(null); };
  const run = async <Value,>(operation: (current: CompanyOffboardingClient) => Promise<Value>, apply: (value: Value) => void) => {
    if (running.current || !client.current) return;
    const current = client.current; const expected = generation.current;
    running.current = true; setBusy(true); setError(''); setFormError('');
    try { const result = await operation(current); if (generation.current === expected) apply(result); }
    catch (failure) {
      if (generation.current === expected) { current.invalidate(); clear(); setReady(false); setError(offboardingError(failure)); }
    } finally {
      if (generation.current === expected) { running.current = false; setBusy(false); setRecoveryId(current.knownIdRecovery); }
    }
  };
  useEffect(() => {
    const value = new URLSearchParams(window.location.search).get('offboard');
    if (value && offboardingUserIdSafe(value)) { setTargetId(value); setOpen(true); }
  }, []);
  useEffect(() => {
    const current = new CompanyOffboardingClient(context); client.current = current; generation.current += 1;
    running.current = false; clear(); setReady(false); setBusy(false); setError(''); setRecoveryId(current.knownIdRecovery);
    const onSessionError = () => {
      generation.current += 1; current.invalidate(); running.current = false; clear(); setReady(false); setBusy(false);
      setTargetId(''); setReason(''); setRecoveryId(current.knownIdRecovery); setError(offboardingError({ response: { status: 401 } }));
    };
    window.addEventListener('od:session-error', onSessionError);
    if (open) void run(async active => { await active.reload(); return active.list(); }, value => { setQueue(value); setReady(true); });
    return () => { generation.current += 1; current.dispose(); window.removeEventListener('od:session-error', onSessionError); };
  }, [open, context.actorUserId, context.tenantId]);

  const loadWorkflow = (id: string) => {
    if (!offboardingUserIdSafe(id)) { setFormError('Bitte eine gültige Vorgangs-ID eingeben.'); return; }
    void run(async current => { if (!ready) await current.reload(); const result = await current.get(id); const events = await current.history(id); return { result, events }; }, ({ result, events }) => {
      setReady(true); setJob(result); setHistory(events); setWorkflowId(result.workflow.id); setSnapshotReady(true); setResumePreview(null); setConfirmation(null); setPreview(null);
    });
  };
  const prepare = () => {
    if (busy || !ready || recoveryId) return;
    if (!offboardingUserIdSafe(targetId)) { setFormError('Bitte eine kanonische Mitarbeiter-ID eingeben.'); return; }
    setPreview(null);
    void run(current => current.preview(targetId), value => { setPreview(value); setConfirmation(null); });
  };
  const begin = (kind: 'create' | 'continue') => {
    if (busy || !ready) return;
    try {
      const normalized = kind === 'continue' && job ? job.workflow.reason : offboardingReason(reason); setFormError('');
      if (kind === 'create' && preview && !recoveryId) setConfirmation({ kind, preview, reason: normalized });
      if (kind === 'continue' && job && snapshotReady && !offboardingTargetChanged(job) && (!needsOffboardingPreview(job) || resumePreview)) setConfirmation({ kind, job, preview: resumePreview || undefined, reason: normalized });
    } catch { setFormError('Bitte eine Begründung mit 10 bis 500 Zeichen eingeben.'); }
  };
  const confirm = () => {
    if (!confirmation || busy) return;
    const pending = confirmation;
    void run(current => pending.kind === 'create' ? current.create(pending.preview, { reason: pending.reason, confirm: true })
      : current.continue(pending.job, { reason: pending.reason, confirm: true }, pending.preview), result => {
      setJob(result); setWorkflowId(result.workflow.id); setHistory(null); setSnapshotReady(false); setPreview(null); setResumePreview(null); setQueue(null); setConfirmation(null);
    });
  };
  const rows = job ? job.workflow.phase === 'paused' ? snapshotReady ? job.workflow.reviewAssignments : [] : job.workflow.nextAssignments : [];
  const stopped = job && offboardingTargetChanged(job);
  const newWorkflowRequired = job?.workflow.failure?.code === 409 && job.workflow.failure.step === 'verify';
  const previewChanged = job && resumePreview && (resumePreview.user.eligibilityRevision !== job.currentTarget.eligibilityRevision || resumePreview.user.enabled !== job.currentTarget.enabled);
  const canContinue = job && ready && snapshotReady && job.workflow.phase !== 'completed_local' && !stopped && !newWorkflowRequired
    && (!recoveryId || recoveryId === job.workflow.id) && !previewChanged && (!needsOffboardingPreview(job) || !!resumePreview) && (job.workflow.phase !== 'paused' || !job.workflow.nextAssignments.length || !!job.workflow.reviewAssignments.length);

  return <section id="company-offboarding" aria-label="Mitarbeiter-Offboarding" className="rounded border border-white/10 p-4 space-y-4">
    <button className="fluent-btn-secondary" aria-expanded={open} aria-controls="company-offboarding-content" disabled={busy} onClick={() => setOpen(value => !value)}>Mitarbeiter-Offboarding</button>
    {open && <div id="company-offboarding-content" className="space-y-5">
      <p>Kanonisches Konto sperren und die beim Start erfassten lokalen Lizenzen zurückgeben. Der Vorgang und seine Teilschritte werden dauerhaft gespeichert und können nach erneuter Anmeldung mit frischer MFA fortgesetzt werden.</p>
      <p className="text-sm">Umfang: kanonische Kontosperre und erfasste lokale Lizenzen. Gruppenmitgliedschaften werden nur im separat verknüpften, ausdrücklich bestätigten Gruppenschritt nach belegter Kontosperre entfernt, unabhängig vom Stand der Lizenzrückgaben. Rollen, PIM, Organisationseinheiten (OU), Geräte, Remote-Befehle und Zugangsdaten externer Anbieter werden nicht entfernt. Keine Abrechnungsänderung; kein vollständiger Austrittsprozess.</p>
      {error && <p role="alert">{error}</p>}
      {formError && <p role="alert">{formError}</p>}
      <button className="fluent-btn-secondary" disabled={busy} onClick={() => {
        clear(); setReady(false);
        void run(async current => { await current.reload(); return current.list(); }, value => { setQueue(value); setReady(true); });
      }}>Berechtigungen und Vorgänge neu laden</button>
      {busy && <p role="status">Arbeitsstand wird geprüft …</p>}
      {recoveryId && <aside aria-label="Unbestätigter Offboarding-Vorgang" className="rounded border border-amber-500/40 p-3 space-y-3">
        <p>Ein Schreibergebnis ist noch nicht bestätigt. Diesen Vorgang per Abruf wiederherstellen; kein erneutes Anlegen und keine automatische Wiederholung.</p>
        <Proof values={{ 'Vorgangs-ID': recoveryId }} />
        <button disabled={busy} onClick={() => loadWorkflow(recoveryId)}>Vorgang wiederherstellen</button>
      </aside>}
      {ready && !recoveryId && <div className="space-y-3">
        <h3 className="font-semibold">Neuen Vorgang vorbereiten</h3>
        <form className="flex flex-wrap gap-3 items-end" onSubmit={event => { event.preventDefault(); prepare(); }}>
          <label className="text-sm">Mitarbeiter-ID<input className="block rounded border p-2 bg-transparent" value={targetId} maxLength={36} disabled={busy || !!confirmation} onChange={event => { setTargetId(event.target.value); setPreview(null); setConfirmation(null); }} /></label>
          <button className="fluent-btn-secondary" type="submit" disabled={busy || !!confirmation}>Mitarbeitervorschau laden</button>
        </form>
        {preview && <div aria-label="Offboarding-Vorschau" className="space-y-3">
          <p>{preview.user.name} · {preview.user.enabled ? 'Freigegeben' : 'Gesperrt'} · {preview.licenseCount} lokale Lizenzzuweisungen zum Vorschauzeitpunkt.</p>
          <Proof values={{ 'Benutzer-ID': preview.user.id, Datensatzversion: preview.user.userRevision, Berechtigungsversion: preview.user.eligibilityRevision }} />
          <button className="fluent-btn-secondary" disabled={busy} onClick={() => begin('create')}>Kontosperre und Lizenzrückgabe starten</button>
        </div>}
        <label className="block text-sm">Begründung für neuen Offboarding-Vorgang<input className="mt-1 block w-full rounded border p-2 bg-transparent" value={reason} maxLength={1000} disabled={busy || !!confirmation} onChange={event => setReason(event.target.value)} /></label>
      </div>}
      <form className="flex flex-wrap gap-3 items-end" onSubmit={event => { event.preventDefault(); loadWorkflow(workflowId); }}>
        <label className="text-sm">Bekannte Vorgangs-ID<input className="block rounded border p-2 bg-transparent" value={workflowId} maxLength={36} disabled={busy} onChange={event => setWorkflowId(event.target.value)} /></label>
        <button className="fluent-btn-secondary" type="submit" disabled={busy}>Arbeitsstand neu laden</button>
      </form>
      {queue && <section aria-label="Gespeicherte Offboarding-Vorgänge" className="space-y-3">
        <h3 className="font-semibold">Gespeicherte Vorgänge</h3>
        {queue.workflows.length === 0 && <p>Keine gespeicherten Vorgänge vorhanden.</p>}
        <ul className="space-y-3">{queue.workflows.map(workflow => <li key={workflow.id}>
          <button className="fluent-btn-secondary" disabled={busy} onClick={() => loadWorkflow(workflow.id)}>{date(workflow.createdAt)} · {phases[workflow.phase]} · {workflow.completedLicenses} / {workflow.totalLicenses ?? 'noch nicht erfasst'}</button>
          <Proof values={{ 'Vorgangs-ID': workflow.id, 'Benutzer-ID': workflow.userId }} />
        </li>)}</ul>
        <Pages page={queue.page} total={queue.total} busy={busy} label="Offboarding-Vorgangsseiten" onPage={page => { void run(current => current.list(page), setQueue); }} />
      </section>}
      {job && <article aria-label="Offboarding-Arbeitsstand" className="space-y-4 border-t border-white/10 pt-4">
        <h3 className="font-semibold">{phases[job.workflow.phase]}</h3>
        <p>{job.workflow.totalLicenses === null ? 'Lokale Lizenzzuweisungen noch nicht erfasst.' : `${job.workflow.completedLicenses} von ${job.workflow.totalLicenses} erfassten lokalen Lizenzzuweisungen zurückgegeben.`}</p>
        <p>Kontostatus beim letzten Abruf: {job.currentTarget.deleted ? 'Gelöscht' : job.currentTarget.enabled ? 'Freigegeben' : 'Gesperrt'}.</p>
        {job.workflow.phase === 'completed_local' && <p>Historischer Abschluss für Konto und erfasste lokale Lizenzen. Der aktuelle Kontostatus kann sich danach ändern.</p>}
        {job.workflow.failure && <p role="status">Pausengrund: {steps[job.workflow.failure.step]} · Fehler {job.workflow.failure.code}. Bereits bestätigte Teilschritte bleiben gespeichert.</p>}
        {stopped && <p role="alert">Kontostatus oder Berechtigungsgeneration geändert. Fortsetzen ist gesperrt; bei einer neuen Kontogeneration ist ein neuer Vorgang erforderlich.</p>}
        {newWorkflowRequired && !stopped && <p role="alert">Die Abschlussprüfung steht im Konflikt. Erfasste Zuweisungen werden nicht erweitert; ein neuer, ausdrücklich geprüfter Vorgang ist erforderlich.</p>}
        <label className="block text-sm">Ursprüngliche Begründung für Fortsetzung<input className="mt-1 block w-full rounded border p-2 bg-transparent" readOnly value={job.workflow.reason} /></label>
        <Proof values={{ 'Vorgangs-ID': job.workflow.id, 'Benutzer-ID': job.workflow.userId, 'Erstellt von': job.workflow.createdBy, Mandant: job.tenantId, Vorgangsversion: job.workflow.revision, 'Angeforderte Datensatzversion': job.workflow.requestedRevision, 'Aktuelle Berechtigungsversion': job.currentTarget.eligibilityRevision }} />
        {job.workflow.checkpoint && <section aria-label="Nachweis der Kontosperre" className="space-y-3">
          <p>{job.workflow.checkpoint.action === 'disabled' ? 'Kontosperre bestätigt' : 'Bereits gesperrtes Konto bestätigt'} · {date(job.workflow.checkpoint.createdAt)} · Ereigniszustellung ausstehend.</p>
          <Proof values={{ 'Vorgangs-ID': job.workflow.checkpoint.workflowId, 'Operations-ID': job.workflow.checkpoint.operationId, 'Ausgeführt von': job.workflow.checkpoint.actorUserId, 'Datensatzversion vorher': job.workflow.checkpoint.beforeRevision, 'Datensatzversion nachher': job.workflow.checkpoint.afterRevision, 'Berechtigungsversion vorher': job.workflow.checkpoint.beforeEligibilityRevision, 'Berechtigungsversion nachher': job.workflow.checkpoint.afterEligibilityRevision }} />
        </section>}
        {job.workflow.phase !== 'completed_local' && !stopped && !newWorkflowRequired && <div className="space-y-3">
          {!snapshotReady && <p>Weitere Schritte sind noch offen. Vor dem Fortsetzen den Arbeitsstand neu laden und prüfen.</p>}
          {snapshotReady && needsOffboardingPreview(job) && <>
            <p>Die Kontosperre wurde wegen einer geänderten Datensatzversion abgelehnt. Mitarbeitervorschau ausdrücklich neu laden und die neue Version bestätigen. Eine geänderte Kontogeneration bleibt serverseitig gesperrt.</p>
            <button disabled={busy} onClick={() => { setResumePreview(null); void run(current => current.preview(job.workflow.userId), setResumePreview); }}>Mitarbeitervorschau für Fortsetzung laden</button>
            {resumePreview && <p>{resumePreview.user.name} · Datensatzversion {job.workflow.requestedRevision} → {resumePreview.user.userRevision} · {resumePreview.licenseCount} lokale Lizenzzuweisungen zum Vorschauzeitpunkt.</p>}
            {previewChanged && <p role="alert">Kontogeneration oder Status seit dem Abruf geändert. Fortsetzen gesperrt; Arbeitsstand ausdrücklich neu laden.</p>}
          </>}
          {rows.length > 0 && <><p>{rows.length} erfasste Zuweisungen für den nächsten bestätigten Schritt:</p><ul>{rows.map(row => <li key={row.assignmentId}>{row.name} · {row.vendor}<Proof values={{ 'Pool-ID': row.poolId, 'Zuweisungs-ID': row.assignmentId, 'Grant-ID': row.grantId, Poolversion: row.poolRevision }} /></li>)}</ul></>}
          <button className="fluent-btn-secondary" disabled={busy || !canContinue} onClick={() => begin('continue')}>{job.workflow.phase === 'paused' ? 'Geprüften Vorgang fortsetzen' : 'Nächsten Schritt fortsetzen'}</button>
        </div>}
        {job.workflow.checkpoint && !stopped && <CompanyOffboardingGroupsPanel context={{ actorUserId: job.actorUserId, tenantId: job.tenantId }} workflowId={job.workflow.checkpoint.workflowId} userId={job.workflow.checkpoint.userId} eligibilityRevision={job.workflow.checkpoint.afterEligibilityRevision} />}
        {job.workflow.checkpoint && !stopped && <CompanyOffboardingAccessPanel expectedActorUserId={job.actorUserId} tenantId={job.tenantId} workflowId={job.workflow.checkpoint.workflowId} userId={job.workflow.checkpoint.userId} eligibilityRevision={job.workflow.checkpoint.afterEligibilityRevision} />}
        {job.workflow.checkpoint && !stopped && <CompanyOffboardingDevicesPanel actorUserId={job.actorUserId} tenantId={job.tenantId} workflowId={job.workflow.checkpoint.workflowId} userId={job.workflow.checkpoint.userId} eligibilityRevision={job.workflow.checkpoint.afterEligibilityRevision} />}
        <section aria-label="Offboarding-Historie" className="space-y-3">
          <h4 className="font-semibold">Dauerhafte Historie</h4>
          {!history ? <p>Historie über „Arbeitsstand neu laden“ abrufen.</p> : <>
            {history.events.length === 0 && <p>Keine Historieneinträge vorhanden.</p>}
            <ol className="space-y-3">{history.events.map(event => <li key={event.id}>
              <p>{date(event.createdAt)} · {phases[event.phase]} · {event.completedLicenses} / {event.totalLicenses ?? 'noch nicht erfasst'} · Ereigniszustellung ausstehend</p>
              {event.failure && <p>{steps[event.failure.step]} · Fehler {event.failure.code}</p>}
              <Proof values={{ 'Ereignis-ID': event.id, Vorgangsversion: event.revision, 'Ausgeführt von': event.actorUserId }} />
            </li>)}</ol>
            <Pages page={history.page} total={history.total} busy={busy} label="Offboarding-Historienseiten" onPage={page => { void run(current => current.history(job.workflow.id, page), setHistory); }} />
          </>}
        </section>
      </article>}
      {confirmation && ready && <DirectoryConfirmation title={confirmation.kind === 'create' ? 'Mitarbeiter-Offboarding bestätigen' : confirmation.job.workflow.phase === 'paused' ? 'Geprüfte Fortsetzung bestätigen' : 'Fortsetzung bestätigen'} busy={busy} error="" onClose={() => setConfirmation(null)} onConfirm={confirm}>
        {confirmation.kind === 'create' ? <><p>{confirmation.preview.user.name}: Konto sperren und alle dann tatsächlich vorhandenen lokalen Lizenzzuweisungen erfassen. Zunächst werden höchstens 25 zurückgegeben; weitere Schritte bleiben ausdrücklich zu bestätigen.</p><p>Vorschau: {confirmation.preview.licenseCount} lokale Zuweisungen.</p></> : <>
          <p>{confirmation.job.workflow.phase === 'paused' ? 'Den ausdrücklich neu geladenen Arbeitsstand und die angezeigten aktuellen Poolversionen verwenden.' : 'Den nächsten Schritt mit den angezeigten erfassten Zuweisungen ausführen.'} Höchstens 25 lokale Lizenzrückgaben.</p>
          <p>Datensatzversion: {confirmation.preview ? `${confirmation.job.workflow.requestedRevision} → ${confirmation.preview.user.userRevision}` : confirmation.job.workflow.requestedRevision}. Ohne bestätigten Versionskonflikt wird die ursprüngliche Version zur Wiederherstellung des Kontonachweises beibehalten.</p>
          {confirmation.job.workflow.totalLicenses === null && <p>Nach bestätigter Kontosperre werden alle dann tatsächlich vorhandenen lokalen Lizenzzuweisungen erfasst und zunächst höchstens 25 zurückgegeben.</p>}
          <ul>{rows.map(row => <li key={row.assignmentId}>{row.name} · {row.vendor} · Poolversion {row.poolRevision}</li>)}</ul>
        </>}
        <p className="mt-3">Begründung: {confirmation.reason}</p>
        <Proof values={confirmation.kind === 'create' ? { 'Benutzer-ID': confirmation.preview.user.id } : { 'Vorgangs-ID': confirmation.job.workflow.id, 'Benutzer-ID': confirmation.job.workflow.userId }} />
        <p className="mt-3 text-sm">Die Kontosperre gilt für das kanonische Konto. Externe Zugangsdaten werden nicht gelöscht. Bestehende Rollen und Gruppen, Geräte, Remote-Befehle und externe Lizenzanbieter werden nicht bearbeitet.</p>
        <p className="mt-3 text-sm">Der Server prüft Ziel, Berechtigung, frische MFA und Versionen erneut. Bereits gespeicherte Schritte bleiben bei Fehlern wirksam. Keine automatische Wiederholung.</p>
      </DirectoryConfirmation>}
    </div>}
  </section>;
}

function offboardingUserIdSafe(value: string) { try { offboardingUserId(value); return true; } catch { return false; } }
