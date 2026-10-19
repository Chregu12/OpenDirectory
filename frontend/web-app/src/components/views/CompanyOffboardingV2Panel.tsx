'use client';

import React, { useEffect, useRef, useState } from 'react';
import { CompanyWorkflowContext, companyUuid, companyWorkflowError, companyWorkflowUnsafe } from '@/lib/companyAssignmentProtocol';
import { CompanyOffboardingV2Client, CompanyOffboardingV2Job, CompanyOffboardingV2Preview, CompanyOffboardingV2Intent, CompanyOffboardingV2Page,
  CompanyOffboardingV2Event, companyOffboardingV2TargetChanged } from '@/lib/companyOffboardingV2';
import { CompanyLicenseSources } from './CompanyApplicationAssignmentsPanel';
import { DirectoryConfirmation } from './UserDetailPanel';

const phases = { pending: 'Kontosperre ausstehend', licenses: 'Rückgabe bereit', paused: 'Pausiert – Prüfung erforderlich', completed_local: 'Lokaler Abschluss bestätigt' };
const inputClass = 'mt-1 block w-full rounded border border-white/20 bg-transparent p-2';
export default function CompanyOffboardingV2Panel({ context }: { context: CompanyWorkflowContext }) {
  const client = useRef<CompanyOffboardingV2Client | null>(null); const generation = useRef(0); const running = useRef(false);
  const [open, setOpen] = useState(false); const [ready, setReady] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  const [formError, setFormError] = useState(''); const [userId, setUserId] = useState(''); const [reason, setReason] = useState(''); const [workflowId, setWorkflowId] = useState('');
  const [preview, setPreview] = useState<CompanyOffboardingV2Preview | null>(null); const [refreshed, setRefreshed] = useState<CompanyOffboardingV2Preview | null>(null);
  const [job, setJob] = useState<CompanyOffboardingV2Job | null>(null); const [queue, setQueue] = useState<CompanyOffboardingV2Page | null>(null);
  const [history, setHistory] = useState<{ events: CompanyOffboardingV2Event[]; total: number; page: number } | null>(null);
  const [intent, setIntent] = useState<CompanyOffboardingV2Intent | null>(null); const [confirmation, setConfirmation] = useState<CompanyOffboardingV2Intent | null>(null);
  const [confirmed, setConfirmed] = useState(false); const [snapshotReady, setSnapshotReady] = useState(false); const [recoveryId, setRecoveryId] = useState<string | null>(null);
  const recoveryKey = `od:company-offboarding-v2:${context.tenantId}:${context.actorUserId}`;
  const clear = () => { setPreview(null); setRefreshed(null); setJob(null); setQueue(null); setHistory(null); setIntent(null); setConfirmation(null); setConfirmed(false); setSnapshotReady(false); };
  const run = async <Value,>(operation: (current: CompanyOffboardingV2Client) => Promise<Value>, apply: (value: Value) => void) => {
    if (running.current || !client.current) return;
    const expected = generation.current; const current = client.current; running.current = true; setBusy(true); setError(''); setFormError('');
    try { const value = await operation(current); if (expected === generation.current) apply(value); }
    catch (failure) {
      if (expected === generation.current) {
        setError(companyWorkflowError(failure)); setConfirmation(null); setConfirmed(false); setSnapshotReady(false);
        if (companyWorkflowUnsafe(failure)) { current.invalidate(); clear(); setReady(false); setUserId(''); setReason(''); }
        else if ([400, 404, 409, 412].includes(failure?.response?.status)) setIntent(null);
      }
    } finally { if (expected === generation.current) { running.current = false; setBusy(false); } }
  };
  const reload = () => {
    generation.current++; client.current?.dispose(); client.current = new CompanyOffboardingV2Client(context); running.current = false; clear(); setReady(false);
    void run(async current => { await current.access(); return current.list(); }, value => { setQueue(value); setReady(true); });
  };
  useEffect(() => {
    const target = new URLSearchParams(window.location.search).get('offboard');
    if (companyUuid.safeParse(target).success) { setUserId(target); setOpen(true); }
  }, []);
  useEffect(() => {
    generation.current++; const current = new CompanyOffboardingV2Client(context); client.current = current; running.current = false;
    clear(); setReady(false); setBusy(false); setError(''); setUserId(previous => companyUuid.safeParse(previous).success ? previous : '');
    try { const saved = window.localStorage.getItem(recoveryKey); setRecoveryId(companyUuid.safeParse(saved).success ? saved : null); } catch { setRecoveryId(null); }
    const sessionError = () => { generation.current++; current.invalidate(); running.current = false; clear(); setReady(false); setBusy(false); setUserId(''); setReason(''); setError(companyWorkflowError({ response: { status: 401 } })); };
    window.addEventListener('od:session-error', sessionError);
    if (open) void run(async active => { await active.access(); return active.list(); }, value => { setQueue(value); setReady(true); });
    return () => { generation.current++; current.dispose(); running.current = false; window.removeEventListener('od:session-error', sessionError); };
  }, [open, context.actorUserId, context.tenantId]);
  const load = (id: string) => {
    if (!companyUuid.safeParse(id).success) { setFormError('Bitte eine kanonische Vorgangs-ID eingeben.'); return; }
    setJob(null); setSnapshotReady(false); setHistory(null); setPreview(null); setRefreshed(null); setIntent(null); setConfirmation(null);
    void run(async current => { if (!ready) await current.access(); return { job: await current.get(id), history: await current.history(id) }; }, value => {
      setJob(value.job); setHistory(value.history as typeof history); setWorkflowId(id); setSnapshotReady(true); setReady(true);
      if (recoveryId === id) { try { window.localStorage.removeItem(recoveryKey); setRecoveryId(null); } catch {} }
    });
  };
  const prepare = (action: 'create' | 'continue') => {
    if (busy || !ready) return;
    try {
      const captured = action === 'create' ? client.current.captureCreate(preview, reason) : client.current.captureContinue(job, refreshed || undefined);
      setConfirmation(captured); setConfirmed(false); setFormError('');
    } catch { setFormError('Bitte aktuellen Arbeitsstand, ursprüngliche Kontogeneration und eine Begründung mit 10 bis 500 Zeichen prüfen.'); }
  };
  const write = () => {
    if (busy || !confirmation || !confirmed) return;
    const captured = confirmation;
    try { window.localStorage.setItem(recoveryKey, captured.workflowId); setRecoveryId(captured.workflowId); }
    catch { setFormError('Vorgangs-ID konnte nicht für die Wiederherstellung gespeichert werden. Keine Anfrage gesendet.'); return; }
    setIntent(captured);
    void run(current => current.write(captured), value => {
      setJob(value); setWorkflowId(value.workflow.id); setHistory(null); setQueue(null); setPreview(null); setRefreshed(null); setSnapshotReady(false);
      setIntent(null); setConfirmation(null); setConfirmed(false);
      try { window.localStorage.removeItem(recoveryKey); setRecoveryId(null); } catch {}
    });
  };
  const targetChanged = job && companyOffboardingV2TargetChanged(job);
  const needsPreview = job && !job.workflow.checkpoint && job.workflow.failure?.code === 412 && job.workflow.failure.step === 'account';
  const stopped = targetChanged || job?.workflow.failure?.code === 409 && job.workflow.failure.step === 'verify';
  const rows = job ? job.workflow.phase === 'paused' ? job.workflow.reviewAssignments : job.workflow.nextAssignments : [];
  const blocked = busy || !!intent || !!confirmation;
  return <section id="company-offboarding-v2" aria-label="Offboarding mit Blueprint-Rückgabe" className="rounded border border-white/10 p-4 space-y-4">
    <button className="fluent-btn-secondary" aria-expanded={open} disabled={busy} onClick={() => setOpen(value => !value)}>Offboarding mit Blueprint-Rückgabe</button>
    {open && <div className="space-y-4">
      <p>Konto sperren, alle erfassten lokalen Lizenzquellen gemeinsam zurückgeben und die erfassten Blueprint-Bindungen beenden – auch Bindungen ohne Apps. Die ursprüngliche Kontosperre und Kontogeneration bleiben verbindlich. Keine Gerätebefehle, Gruppen-/Rollenänderungen oder externe Abrechnung.</p>
      {error && <p role="alert">{error}</p>}{formError && <p role="alert">{formError}</p>}{busy && <p role="status">Offboarding-Arbeitsstand wird geprüft …</p>}
      <button className="fluent-btn-secondary" disabled={busy || !!confirmation} onClick={reload}>Blueprint-Offboarding-Berechtigung neu prüfen</button>
      {recoveryId && <aside aria-label="Unbestätigtes Blueprint-Offboarding" className="space-y-2"><p>Vorgang {recoveryId} ist noch nicht bestätigt. Per Abruf wiederherstellen; kein neuer Vorgang und keine automatische Wiederholung.</p><button className="fluent-btn-secondary" disabled={busy || !!confirmation} onClick={() => load(recoveryId)}>Blueprint-Offboarding wiederherstellen</button></aside>}
      {ready && !recoveryId && !intent && <section aria-label="Blueprint-Offboarding vorbereiten" className="space-y-3">
        <form onSubmit={event => { event.preventDefault(); setPreview(null); setJob(null); setSnapshotReady(false); void run(current => current.preview(userId), setPreview); }} className="flex flex-wrap items-end gap-3">
          <label>Blueprint-Offboarding Mitarbeiter-ID<input className={inputClass} maxLength={36} disabled={blocked} value={userId} onChange={event => { setUserId(event.target.value); setPreview(null); setConfirmation(null); }} /></label>
          <button className="fluent-btn-secondary" disabled={blocked || !userId}>Blueprint-Offboarding-Vorschau laden</button>
        </form>
        {preview && <div aria-label="Blueprint-Offboarding-Vorschau" className="space-y-3"><p>{preview.user.name} · {preview.user.enabled ? 'Aktiv' : 'Gesperrt'} · {preview.licenseCount} lokale Lizenzplätze · {preview.bindingCount} Blueprint-Bindungen.</p>
          <p className="break-all">Mitarbeiter {preview.user.id} · Datensatzrevision {preview.user.userRevision} · Kontogeneration {preview.user.eligibilityRevision}</p>
          <label>Begründung des Blueprint-Offboardings<input className={inputClass} maxLength={500} disabled={blocked} value={reason} onChange={event => setReason(event.target.value)} /></label>
          <button className="fluent-btn-primary" disabled={blocked || reason.trim().length < 10} onClick={() => prepare('create')}>Blueprint-Offboarding starten</button>
        </div>}
      </section>}
      <form onSubmit={event => { event.preventDefault(); load(workflowId); }} className="flex flex-wrap items-end gap-3"><label>Blueprint-Offboarding Vorgangs-ID<input className={inputClass} maxLength={36} disabled={blocked} value={workflowId} onChange={event => setWorkflowId(event.target.value)} /></label><button className="fluent-btn-secondary" disabled={busy || !!confirmation}>Blueprint-Offboarding-Arbeitsstand laden</button></form>
      {queue && <section aria-label="Gespeicherte Blueprint-Offboardings" className="space-y-3"><h3 className="font-semibold">Gespeicherte Vorgänge</h3>
        {!queue.workflows.length && <p>Keine Blueprint-Offboarding-Vorgänge vorhanden.</p>}
        <ul className="space-y-2">{queue.workflows.map(value => <li key={value.id}><button className="fluent-btn-secondary" disabled={blocked} onClick={() => load(value.id)}>{phases[value.phase]} · {new Date(value.createdAt).toLocaleString('de-CH')}</button><p className="break-all text-sm">{value.userId} · {value.completedLicenses}/{value.totalLicenses ?? 'offen'} Lizenzplätze · {value.completedBindings}/{value.totalBindings ?? 'offen'} Bindungen</p></li>)}</ul>
        <nav aria-label="Blueprint-Offboarding-Seiten" className="flex gap-4"><button disabled={blocked || queue.page <= 1} onClick={() => { void run(current => current.list(queue.page - 1), setQueue); }}>Zurück</button><span>Seite {queue.page} · {queue.total} Vorgänge</span><button disabled={blocked || queue.page * 25 >= queue.total} onClick={() => { void run(current => current.list(queue.page + 1), setQueue); }}>Weiter</button></nav>
      </section>}
      {job && <article aria-label="Blueprint-Offboarding-Arbeitsstand" className="border-t border-white/20 pt-3 space-y-3">
        <h3 className="font-semibold">{phases[job.workflow.phase]}</h3><p>{job.workflow.completedLicenses}/{job.workflow.totalLicenses ?? 'noch nicht erfasst'} lokale Lizenzplätze zurückgegeben · {job.workflow.completedBindings}/{job.workflow.totalBindings ?? 'noch nicht erfasst'} Bindungen beendet.</p>
        <p className="break-all">Vorgang {job.workflow.id} · Revision {job.workflow.revision} · Mitarbeiter {job.workflow.userId}</p><p>Kontostatus beim Abruf: {job.currentTarget.deleted ? 'Gelöscht' : job.currentTarget.enabled ? 'Aktiv' : 'Gesperrt'}.</p>
        {job.workflow.checkpoint && <details><summary>Ursprünglicher Kontosperrnachweis</summary><p className="break-all">Identity-Vorgang {job.workflow.checkpoint.workflowId} · Kontogeneration {job.workflow.checkpoint.afterEligibilityRevision} · {job.workflow.checkpoint.action === 'disabled' ? 'Konto gesperrt' : 'Bereits gesperrtes Konto bestätigt'}</p></details>}
        {!snapshotReady && <p>Historischer Änderungsnachweis, nicht der aktuelle Stand. Vor weiteren Schritten den Arbeitsstand ausdrücklich neu laden.</p>}
        {job.workflow.phase === 'completed_local' && <p>Historischer lokaler Abschluss: erfasste Lizenzquellen und Blueprint-Bindungen beendet. Keine Bestätigung externer Konten, Geräte oder eines vollständigen Austritts.</p>}
        {job.workflow.failure && <p role="status">Pausiert: {job.workflow.failure.step} · Fehler {job.workflow.failure.code}. Bereits bestätigte Schritte bleiben erhalten.</p>}
        {job.currentTarget.deleted && job.workflow.phase !== 'completed_local'
          ? <p role="alert">Gelöschtes Konto: Die kanonische Lifecycle-Historie für diesen ursprünglichen Kontosperrnachweis ist noch nicht unterstützt. Die gemeinsame Blueprint-Rückgabe bleibt gesperrt; der aktuelle Stand darf den ursprünglichen Nachweis nicht ersetzen.</p>
          : stopped && job.workflow.phase !== 'completed_local' && <p role="alert">Kontogeneration oder Abschlussprüfung steht im Konflikt. Fortsetzung gesperrt; ein neuer ausdrücklich geprüfter Vorgang ist erforderlich.</p>}
        {snapshotReady && !stopped && job.workflow.phase !== 'completed_local' && <>
          <p>{rows.length} Lizenzpools und {job.workflow.nextBindings.length} Bindungen werden als vollständiger erfasster Satz gemeinsam zurückgenommen. Keine automatische Seitenauswahl oder Erweiterung um spätere Quellen.</p>
          <details><summary>Vollständigen Rückgabesatz anzeigen</summary><ul className="space-y-3">{rows.map(row => <li key={row.id}><p>{row.name} · {row.vendor} · Pool-Revision {row.poolRevision}</p><CompanyLicenseSources sources={row.sources} /></li>)}</ul><ul>{job.workflow.nextBindings.map(binding => <li className="break-all" key={binding.id}>Bindung {binding.id} · Blueprint {binding.blueprintId} · Version {binding.version} · {binding.poolIds.length} App-Pools</li>)}</ul></details>
          {needsPreview && <><button className="fluent-btn-secondary" disabled={blocked} onClick={() => { setRefreshed(null); void run(current => current.preview(job.workflow.userId), setRefreshed); }}>Blueprint-Offboarding-Kontovorschau neu laden</button>{refreshed && <p>Neue Datensatzrevision {refreshed.user.userRevision} · unveränderte Kontogeneration {refreshed.user.eligibilityRevision} erforderlich.</p>}</>}
          <button className="fluent-btn-primary" disabled={blocked || needsPreview && !refreshed} onClick={() => prepare('continue')}>Erfasste Rückgabe gemeinsam fortsetzen</button>
        </>}
        <button className="fluent-btn-secondary" disabled={busy || !!confirmation} onClick={() => load(job.workflow.id)}>Diesen Blueprint-Offboarding-Stand neu laden</button>
      </article>}
      {history && <section aria-label="Blueprint-Offboarding-Historie" className="space-y-3"><h3 className="font-semibold">Dauerhafte Historie</h3><ol className="space-y-2">{history.events.map(event => <li key={event.id}>{phases[event.phase]} · Revision {event.revision} · {event.completedLicenses}/{event.totalLicenses ?? 'offen'} Lizenzplätze · {event.completedBindings}/{event.totalBindings ?? 'offen'} Bindungen · Ereigniszustellung ausstehend</li>)}</ol>
        <nav aria-label="Blueprint-Offboarding-Historienseiten" className="flex gap-4"><button disabled={blocked || history.page <= 1} onClick={() => { void run(current => current.history(job.workflow.id, history.page - 1), value => setHistory(value as typeof history)); }}>Zurück</button><span>Seite {history.page} · {history.total} Ereignisse</span><button disabled={blocked || history.page * 25 >= history.total} onClick={() => { void run(current => current.history(job.workflow.id, history.page + 1), value => setHistory(value as typeof history)); }}>Weiter</button></nav>
      </section>}
      {intent && <aside aria-label="Unbestätigter Blueprint-Offboarding-Versuch" className="space-y-3"><p>Der exakt ursprüngliche Schritt könnte bereits gespeichert sein. Keine automatische Wiederholung.</p><p className="break-all">Vorgang {intent.workflowId} · Operation {intent.operationId}</p><button className="fluent-btn-secondary" disabled={busy || !client.current?.canRetry(intent)} onClick={() => { setConfirmation(intent); setConfirmed(false); }}>Ursprünglichen Blueprint-Offboarding-Schritt prüfen</button></aside>}
      {confirmation && <DirectoryConfirmation title="Blueprint-Offboarding bestätigen" busy={busy} error={confirmed ? '' : 'Bitte genau diesen Schritt bestätigen.'} onClose={() => { setConfirmation(null); setConfirmed(false); }} onConfirm={write}>
        <p>{confirmation.action === 'create' ? 'Konto sperren und den vollständigen tatsächlichen Rückgabesatz erfassen.' : 'Den vollständigen erfassten Lizenz- und Blueprint-Satz gemeinsam zurücknehmen.'}</p><p>{String(confirmation.body.reason)}</p><p className="break-all">Vorgang {confirmation.workflowId} · Operation {confirmation.operationId}</p><p>Auch Blueprint-Bindungen ohne Apps werden beendet. Neuere Quellen und reaktivierte Kontogenerationen dürfen durch diesen ursprünglichen Vorgang nicht entfernt werden. Keine Geräte- oder externe Aktion.</p>
        <label className="flex gap-3 mt-3"><input type="checkbox" checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)} />Ich bestätige diesen Blueprint-Offboarding-Schritt.</label>
      </DirectoryConfirmation>}
    </div>}
  </section>;
}
