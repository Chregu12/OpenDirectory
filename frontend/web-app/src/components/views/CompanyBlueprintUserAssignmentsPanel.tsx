'use client';

import React, { useEffect, useRef, useState } from 'react';
import { CompanyBlueprintVersionDetail } from '@/lib/companyBlueprints';
import { CompanyWorkflowContext, companyWorkflowError, companyWorkflowUnsafe } from '@/lib/companyAssignmentProtocol';
import { CompanyBlueprintAssignmentsClient, CompanyBlueprintAssignmentPage, CompanyBlueprintAssignmentPreview, CompanyBlueprintEffective,
  CompanyBlueprintAssignmentIntent, CompanyBlueprintAssignmentReceipt, CompanyBlueprintBinding } from '@/lib/companyBlueprintAssignments';
import { UserPage, userName } from '@/lib/directoryUsers';
import { DirectoryConfirmation } from './UserDetailPanel';

const labels = { screen_lock: 'Bildschirmsperre', filevault: 'FileVault', software_update: 'Software-Updates' };
const inputClass = 'mt-1 block w-full rounded border border-white/20 bg-transparent p-2';
export default function CompanyBlueprintUserAssignmentsPanel({ context, blueprintId, version, disabled = false }: {
  context: CompanyWorkflowContext; blueprintId: string; version: CompanyBlueprintVersionDetail; disabled?: boolean;
}) {
  const client = useRef<CompanyBlueprintAssignmentsClient | null>(null); const generation = useRef(0); const running = useRef(false);
  const [open, setOpen] = useState(false); const [ready, setReady] = useState(false); const [busy, setBusy] = useState(false);
  const [error, setError] = useState(''); const [formError, setFormError] = useState(''); const [users, setUsers] = useState<UserPage | null>(null);
  const [pickerReady, setPickerReady] = useState(false); const [search, setSearch] = useState(''); const [userId, setUserId] = useState('');
  const [preview, setPreview] = useState<CompanyBlueprintAssignmentPreview | null>(null); const [effective, setEffective] = useState<CompanyBlueprintEffective | null>(null);
  const [list, setList] = useState<CompanyBlueprintAssignmentPage | null>(null); const [reason, setReason] = useState('');
  const [intent, setIntent] = useState<CompanyBlueprintAssignmentIntent | null>(null); const [confirmation, setConfirmation] = useState<CompanyBlueprintAssignmentIntent | null>(null);
  const [receipt, setReceipt] = useState<CompanyBlueprintAssignmentReceipt | null>(null); const [confirmed, setConfirmed] = useState(false); const [needsReload, setNeedsReload] = useState(false);
  const clear = () => { setPreview(null); setEffective(null); setList(null); setIntent(null); setConfirmation(null); setConfirmed(false); setReceipt(null); setReason(''); };
  const run = async <Value,>(operation: (current: CompanyBlueprintAssignmentsClient) => Promise<Value>, apply: (value: Value) => void) => {
    if (running.current || !client.current) return;
    const expected = generation.current; const current = client.current; running.current = true; setBusy(true); setError(''); setFormError('');
    try { const value = await operation(current); if (expected === generation.current) apply(value); }
    catch (failure) {
      if (expected === generation.current) {
        setError(companyWorkflowError(failure)); setConfirmation(null); setConfirmed(false); setNeedsReload(true);
        if (companyWorkflowUnsafe(failure)) { current.invalidate(); clear(); setReady(false); setUsers(null); setPickerReady(false); setUserId(''); }
        else if ([400, 404, 409, 412].includes(failure?.response?.status)) setIntent(null);
      }
    } finally { if (expected === generation.current) { running.current = false; setBusy(false); } }
  };
  useEffect(() => {
    generation.current++; const current = new CompanyBlueprintAssignmentsClient(context); client.current = current;
    running.current = false; clear(); setReady(false); setBusy(false); setUsers(null); setPickerReady(false); setUserId(''); setSearch(''); setError(''); setNeedsReload(false);
    const sessionError = () => { generation.current++; current.invalidate(); running.current = false; clear(); setReady(false); setBusy(false); setUsers(null); setPickerReady(false); setUserId(''); setError(companyWorkflowError({ response: { status: 401 } })); };
    window.addEventListener('od:session-error', sessionError);
    if (open) void run(async active => { await active.access(); return active.users(); }, value => { setUsers(value); setPickerReady(true); setReady(true); });
    return () => { generation.current++; current.dispose(); running.current = false; window.removeEventListener('od:session-error', sessionError); };
  }, [open, context.actorUserId, context.tenantId, blueprintId, version.version]);
  const inspect = (candidate = false) => {
    if (!ready || busy || intent || disabled) return;
    setPreview(null); setReceipt(null); setNeedsReload(false);
    if (candidate) void run(current => current.preview({ userId, blueprintId, version: version.version }, version.draft.appPoolIds), setPreview);
    else void run(async current => ({ list: await current.list(userId), effective: await current.effective(userId) }), value => { setList(value.list); setEffective(value.effective); });
  };
  const prepare = () => {
    try { const value = client.current.captureAssign(preview, reason); setConfirmation(value); setConfirmed(false); setFormError(''); }
    catch { setFormError('Bitte konfliktfreie Vorschau, ausreichenden Bestand und eine Begründung mit 10 bis 500 Zeichen prüfen.'); }
  };
  const remove = (binding: CompanyBlueprintBinding) => {
    if (busy || disabled || intent || needsReload) return;
    void run(async current => {
      const checked = await current.removalPreview(binding.id);
      return current.captureRemove(checked, reason);
    }, value => { setConfirmation(value); setConfirmed(false); });
  };
  const write = () => {
    if (!confirmation || !confirmed || busy || disabled) return;
    const captured = confirmation; setIntent(captured);
    void run(current => current.write(captured), value => {
      setReceipt(value); setIntent(null); setConfirmation(null); setConfirmed(false); setPreview(null); setEffective(null); setList(null); setNeedsReload(true);
    });
  };
  const blocked = busy || disabled || !!intent || !!confirmation;
  return <section aria-label="Blueprint-Mitarbeiterzuweisungen" className="border-t border-white/20 pt-4 space-y-4">
    <button className="fluent-btn-secondary" aria-expanded={open} disabled={busy || disabled} onClick={() => setOpen(value => !value)}>Mitarbeitenden zuweisen</button>
    {open && <div className="space-y-4">
      <p>Version {version.version} wird unveränderlich an einen Mitarbeiter gebunden. Apps belegen echte lokale Lizenzen, pro Mitarbeiter und Pool höchstens einen Platz. Überlappende und manuelle Quellen bleiben getrennt erhalten. Konfigurationen sind nur gewünschte lokale Vorgaben, keine bestätigte Gerätewirkung und kein MDM-Befehl.</p>
      {error && <p role="alert">{error}</p>}{formError && <p role="alert">{formError}</p>}{busy && <p role="status">Zuweisung wird geprüft …</p>}
      <button className="fluent-btn-secondary" disabled={busy || disabled || !!confirmation} onClick={() => {
        generation.current++; client.current?.dispose(); client.current = new CompanyBlueprintAssignmentsClient(context); running.current = false;
        clear(); setReady(false); setNeedsReload(false); setUsers(null); setPickerReady(false);
        void run(async current => { await current.access(); return current.users(); }, value => { setUsers(value); setPickerReady(true); setReady(true); });
      }}>Zuweisungsberechtigung neu prüfen</button>
      {ready && pickerReady && <>
        {users ? <><form onSubmit={event => { event.preventDefault(); clear(); setUserId(''); void run(current => current.users(1, search), value => setUsers(value)); }} className="flex flex-wrap gap-3 items-end">
          <label>Blueprint-Mitarbeiter suchen<input className={inputClass} maxLength={100} disabled={blocked || needsReload} value={search} onChange={event => setSearch(event.target.value)} /></label>
          <button className="fluent-btn-secondary" disabled={blocked || needsReload}>Blueprint-Mitarbeiter suchen</button>
        </form><label className="block">Blueprint-Mitarbeiter auswählen<select className={inputClass} disabled={blocked || needsReload} value={userId} onChange={event => { setUserId(event.target.value); clear(); }}>
          <option value="">Mitarbeiter wählen …</option>{users.users.map(user => <option key={user.id} value={user.id}>{userName(user)} · {user.username}</option>)}</select></label>
          <nav aria-label="Blueprint-Mitarbeiterseiten" className="flex gap-4"><button disabled={blocked || needsReload || users.page <= 1} onClick={() => { clear(); setUserId(''); void run(current => current.users(users.page - 1, search), setUsers); }}>Zurück</button><span>Seite {users.page} · {users.total} Mitarbeiter</span><button disabled={blocked || needsReload || users.page * 25 >= users.total} onClick={() => { clear(); setUserId(''); void run(current => current.users(users.page + 1, search), setUsers); }}>Weiter</button></nav>
        </> : <label>Bekannte Blueprint-Mitarbeiter-ID<input className={inputClass} maxLength={36} disabled={blocked || needsReload} value={userId} onChange={event => { setUserId(event.target.value); clear(); }} /><span className="text-sm">Keine Profil-Leseberechtigung. Nur bekannte eigene UUID; der Server prüft das Ziel.</span></label>}
        <div className="flex flex-wrap gap-3"><button className="fluent-btn-secondary" disabled={blocked || needsReload || !userId} onClick={() => inspect()}>Mitarbeiterzuweisungen laden</button>
          <button className="fluent-btn-secondary" disabled={blocked || needsReload || !userId} onClick={() => inspect(true)}>Neue Zuweisung prüfen</button></div>
      </>}
      {preview && <section aria-label="Blueprint-Zuweisungsvorschau" className="rounded border border-white/20 p-3 space-y-3">
        <h4 className="font-semibold">Version {preview.version} · Mitarbeiter {preview.userId}</h4><p>Berechtigungsgeneration {preview.eligibilityRevision}. Keine Änderung durch diese Vorschau.</p>
        <p>{preview.hasConflicts ? 'Widersprüchliche Vorgaben: Zuweisung gesperrt.' : 'Keine widersprüchlichen Vorgaben in dieser Vorschau.'}</p>
        <ul>{preview.pools.map(pool => <li key={pool.poolId} className="break-all">Pool {pool.poolId} · Revision {pool.poolRevision} · {pool.availableSeats} verfügbar · {pool.additionalSeats} zusätzlicher Lizenzplatz erforderlich{pool.additionalSeats > pool.availableSeats ? ' · Lizenzmangel' : ''}</li>)}</ul>
        {!preview.pools.length && <p>Nur Konfigurationen, keine App-Lizenz. Auch diese Bindung wird im Offboarding zurückgenommen.</p>}
        {preview.effectiveConfigurations.map(config => <details key={config.configType}><summary>Geplante {labels[config.configType]} · {config.sources.length} Quellen</summary><pre className="whitespace-pre-wrap break-all">{config.payloadJson}</pre><ul>{config.sources.map(source => <li className="break-all" key={source.blueprintId + ':' + source.configurationId}>{source.blueprintId} · {source.configurationId}</li>)}</ul></details>)}
        {preview.conflicts.map(conflict => <details key={conflict.configType}><summary>Konflikt: {labels[conflict.configType]}</summary>{conflict.variants.map((variant, index) => <pre className="whitespace-pre-wrap break-all" key={index}>{variant.payloadJson}</pre>)}</details>)}
        <button className="fluent-btn-primary" disabled={blocked || needsReload || preview.hasConflicts || preview.pools.some(pool => pool.additionalSeats > pool.availableSeats)} onClick={prepare}>Blueprint-Zuweisung vorbereiten</button>
      </section>}
      {ready && <label className="block">Begründung der Blueprint-Zuweisung<input className={inputClass} maxLength={500} disabled={blocked || needsReload} value={reason} onChange={event => setReason(event.target.value)} /></label>}
      {list && <section aria-label="Gespeicherte Blueprint-Zuweisungen" className="space-y-3"><h4 className="font-semibold">Gespeicherte Zuweisungen</h4>
        {!list.assignments.length && <p>Noch keine Blueprint-Bindungen für diesen Mitarbeiter.</p>}
        <ul className="space-y-3">{list.assignments.map(binding => <li key={binding.id} className="space-y-2"><p className="break-all">Blueprint {binding.blueprintId} · Version {binding.version} · {binding.status === 'active' ? 'Aktiv' : 'Zurückgenommen'} · {binding.appPoolIds.length} App-Pools</p>
          <details><summary>Bindungsnachweis</summary><p className="break-all">Bindung: {binding.id} · Revision {binding.revision} · Berechtigungsgeneration {binding.eligibilityRevision}</p></details>
          {binding.status === 'active' && <button className="fluent-btn-secondary" disabled={blocked || needsReload || reason.trim().length < 10} onClick={() => remove(binding)}>Zuweisung entfernen</button>}</li>)}</ul>
        <nav aria-label="Blueprint-Zuweisungsseiten" className="flex gap-4"><button disabled={blocked || needsReload || list.page <= 1} onClick={() => { void run(current => current.list(userId, list.page - 1), setList); }}>Zurück</button><span>Seite {list.page} · {list.total} Bindungen</span><button disabled={blocked || needsReload || list.page * 25 >= list.total} onClick={() => { void run(current => current.list(userId, list.page + 1), setList); }}>Weiter</button></nav>
      </section>}
      {effective && <section aria-label="Wirksame lokale Blueprint-Planung" className="space-y-3"><h4 className="font-semibold">Gewünschte Konfigurationen aller aktiven Versionen</h4>
        {effective.hasConflicts && <p role="status">Widersprüchliche aktive Vorgaben. Keine Gerätewirkung wird bestätigt.</p>}
        {effective.effectiveConfigurations.map(config => <details key={config.configType}><summary>{labels[config.configType]} · {config.sources.length} Quellen</summary><pre className="whitespace-pre-wrap break-all">{config.payloadJson}</pre><ul>{config.sources.map(source => <li className="break-all" key={source.configurationId}>{source.blueprintId} · {source.configurationId}</li>)}</ul></details>)}
        {!effective.effectiveConfigurations.length && <p>Keine konfliktfreie lokale Konfiguration vorhanden.</p>}
        {effective.conflicts.map(conflict => <details key={conflict.configType}><summary>Aktiver Konflikt: {labels[conflict.configType]}</summary>{conflict.variants.map((variant, index) => <pre className="whitespace-pre-wrap break-all" key={index}>{variant.payloadJson}</pre>)}</details>)}
        <p>{effective.applications.length} durch aktive Blueprints referenzierte App-Pools. Kein Nachweis einer Installation oder physischen Gerätewirkung.</p>
        {effective.applications.map(app => <details key={app.poolId}><summary className="break-all">App-Pool {app.poolId} · {app.sources.length} Quellen</summary><ul>{app.sources.map(source => <li className="break-all" key={source.grantId}>{source.sourceType === 'direct' ? 'Manuell' : 'Blueprint'} · {source.sourceId} · Grant {source.grantId}</li>)}</ul></details>)}
      </section>}
      {receipt && <section aria-label="Blueprint-Zuweisungsnachweis" className="rounded border border-green-500/30 p-3 space-y-2"><h4>{receipt.action === 'assigned' ? 'Lokale Zuweisung bestätigt' : 'Lokale Rücknahme bestätigt'}</h4>
        <p>{receipt.outcome === 'already_applied' ? 'Ursprünglicher Versuch bereits gespeichert.' : 'Vorgang gespeichert.'} Historischer Nachweis, nicht der aktuelle Stand. Ereigniszustellung ausstehend.</p>
        <p className="break-all">Bindung {receipt.assignmentId} · Vorgang {receipt.operationId}</p>
        <ul>{receipt.pools.map(pool => <li className="break-all" key={pool.poolId}>{pool.poolId} · {pool.sourceAdded ? 'Blueprint-Quelle hinzugefügt' : 'Blueprint-Quelle entfernt'} · {pool.seatAllocated ? 'Lizenzplatz belegt' : pool.seatReleased ? 'Lizenzplatz freigegeben' : 'Lizenzplatz bleibt durch andere Quellen belegt'}</li>)}</ul>
        <p>Aktuellen Stand über „Zuweisungsberechtigung neu prüfen“ ausdrücklich laden.</p>
      </section>}
      {intent && <aside aria-label="Unbestätigte Blueprint-Zuweisung" className="space-y-3"><p>Das Ergebnis könnte bereits gespeichert sein. Keine automatische Wiederholung.</p><p className="break-all">Vorgang {intent.operationId}</p>
        <button className="fluent-btn-secondary" disabled={busy || disabled || !client.current?.canRetry(intent)} onClick={() => { setConfirmation(intent); setConfirmed(false); }}>Ursprüngliche Zuweisung wiederaufnehmen</button>
      </aside>}
      {userId && <a className="text-blue-400 underline" href={'/applications?licenseView=source-aware&offboard=' + encodeURIComponent(userId)}>Gesperrte Mitarbeiter: Offboarding mit Blueprint-Rückgabe</a>}
      {confirmation && <DirectoryConfirmation title={confirmation.action === 'assigned' ? 'Blueprint-Zuweisung bestätigen' : 'Blueprint-Rücknahme bestätigen'} busy={busy} error={confirmed ? '' : 'Bitte genau diesen Vorgang bestätigen.'} onClose={() => { setConfirmation(null); setConfirmed(false); }} onConfirm={write}>
        <p className="break-all">Mitarbeiter {String(confirmation.body.userId)} · Bindung {confirmation.assignmentId}</p><p>{String(confirmation.body.reason)}</p>
        <p>{confirmation.action === 'assigned' ? 'Alle erfassten App-Pools werden gemeinsam geprüft und lokal zugewiesen.' : 'Nur Quellen dieser exakten Bindung werden entfernt. Andere Blueprints und manuelle Zuweisungen bleiben erhalten.'} Keine Installation und kein MDM-Befehl.</p>
        <label className="flex gap-3 mt-3"><input type="checkbox" checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)} />Ich bestätige diese lokale Zuweisung.</label>
      </DirectoryConfirmation>}
    </div>}
  </section>;
}
