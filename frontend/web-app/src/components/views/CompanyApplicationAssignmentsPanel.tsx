'use client';

import React, { useEffect, useRef, useState } from 'react';
import { CompanyPool } from '@/lib/companyApplications';
import { CompanyWorkflowContext, CompanyLicenseSource, companyWorkflowError, companyWorkflowUnsafe } from '@/lib/companyAssignmentProtocol';
import { CompanyApplicationsV2Client, CompanyAssignmentsV2Page, CompanyAssignmentV2Preview, CompanyAssignmentV2Intent, CompanyAssignmentV2Receipt } from '@/lib/companyApplicationsV2';
import { UserPage, userName } from '@/lib/directoryUsers';
import { DirectoryConfirmation } from './UserDetailPanel';

export function CompanyLicenseSources({ sources }: { sources: CompanyLicenseSource[] }) {
  return <ul className="space-y-2">{sources.map(source => <li key={source.grantId}>
    <p>{source.sourceType === 'direct' ? 'Manuell' : 'Blueprint-Version'}</p>
    <details><summary>Quellennachweis</summary><p className="break-all">Quelle: {source.sourceId}</p><p className="break-all">Grant: {source.grantId}</p></details>
  </li>)}</ul>;
}
const inputClass = 'mt-1 block w-full rounded border border-white/20 bg-transparent p-2';
export default function CompanyApplicationAssignmentsPanel({ context, pool, onReload }: { context: CompanyWorkflowContext; pool: CompanyPool; onReload: () => void }) {
  const client = useRef<CompanyApplicationsV2Client | null>(null); const generation = useRef(0); const running = useRef(false);
  const [ready, setReady] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [formError, setFormError] = useState('');
  const [rows, setRows] = useState<CompanyAssignmentsV2Page | null>(null); const [users, setUsers] = useState<UserPage | null>(null); const [pickerReady, setPickerReady] = useState(false);
  const [userId, setUserId] = useState(''); const [search, setSearch] = useState(''); const [reason, setReason] = useState(''); const [needsReload, setNeedsReload] = useState(false);
  const [preview, setPreview] = useState<CompanyAssignmentV2Preview | null>(null); const [intent, setIntent] = useState<CompanyAssignmentV2Intent | null>(null);
  const [confirmation, setConfirmation] = useState<CompanyAssignmentV2Intent | null>(null); const [confirmed, setConfirmed] = useState(false); const [receipt, setReceipt] = useState<CompanyAssignmentV2Receipt | null>(null);
  const clear = () => { setRows(null); setUsers(null); setPickerReady(false); setPreview(null); setIntent(null); setConfirmation(null); setConfirmed(false); setReceipt(null); setUserId(''); setReason(''); setSearch(''); };
  const run = async <Value,>(operation: (current: CompanyApplicationsV2Client) => Promise<Value>, apply: (value: Value) => void) => {
    if (!client.current || running.current) return;
    const current = client.current; const expected = generation.current; running.current = true; setBusy(true); setError(''); setFormError('');
    try { const value = await operation(current); if (expected === generation.current) apply(value); }
    catch (failure) {
      if (expected === generation.current) {
        setError(companyWorkflowError(failure)); setConfirmation(null); setConfirmed(false); setNeedsReload(true);
        if (companyWorkflowUnsafe(failure)) { current.invalidate(); clear(); setReady(false); }
        else if ([400, 404, 409, 412].includes(failure?.response?.status)) setIntent(null);
      }
    } finally { if (expected === generation.current) { running.current = false; setBusy(false); } }
  };
  const reload = (parent = false) => {
    generation.current++; client.current?.dispose(); client.current = new CompanyApplicationsV2Client(context); running.current = false;
    clear(); setReady(false); setNeedsReload(false);
    if (parent) onReload();
    void run(async current => { await current.access(); return { rows: await current.assignments(pool.id), users: await current.users() }; }, value => {
      setReady(true); setRows(value.rows); setUsers(value.users); setPickerReady(true);
    });
  };
  useEffect(() => {
    reload();
    const sessionError = () => { generation.current++; client.current?.invalidate(); running.current = false; clear(); setReady(false); setBusy(false); setNeedsReload(true); setError(companyWorkflowError({ response: { status: 401 } })); };
    window.addEventListener('od:session-error', sessionError);
    return () => { generation.current++; client.current?.dispose(); running.current = false; window.removeEventListener('od:session-error', sessionError); };
  }, [context.actorUserId, context.tenantId, pool.id]);
  const inspect = (target = userId) => {
    if (!ready || busy || intent || confirmation || needsReload) return;
    setPreview(null); setUserId(target); setReceipt(null);
    void run(current => current.preview(pool.id, target), setPreview);
  };
  const prepare = (action: 'manual_assign' | 'manual_revoke') => {
    try { setConfirmation(client.current.capture(action, preview, reason)); setConfirmed(false); setFormError(''); }
    catch { setFormError('Bitte aktuelle Zielvorschau, passende Quelle und eine Begründung mit 10 bis 500 Zeichen prüfen.'); }
  };
  const write = () => {
    if (!confirmation || !confirmed || busy) return;
    const captured = confirmation; setIntent(captured);
    void run(current => current.write(captured), value => {
      setReceipt(value); setIntent(null); setConfirmation(null); setConfirmed(false); setPreview(null); setRows(null); setNeedsReload(true);
    });
  };
  const blocked = busy || !!intent || !!confirmation || needsReload;
  return <section aria-label="Quellenbasierte Lizenzverwaltung" className="border-t border-white/20 pt-4 space-y-4">
    <h3 className="font-semibold">Aktuelle Lizenzzuweisungen · alle Quellen</h3>
    <p>Ein Lizenzplatz je Mitarbeiter und Pool, auch bei mehreren Blueprints. Eine manuelle Rücknahme entfernt nur die manuelle Quelle. Blueprint-Quellen werden an ihrer Bindung oder im bestätigten Offboarding zurückgenommen.</p>
    {error && <p role="alert">{error}</p>}{formError && <p role="alert">{formError}</p>}{busy && <p role="status">Lizenzquellen werden geprüft …</p>}
    <button className="fluent-btn-secondary" disabled={busy || !!confirmation} onClick={() => reload(true)}>Zuweisungen und Pool neu laden</button>
    {rows && <section aria-label="Vollständige Lizenzquellen" className="space-y-3">
      <p>Pool-Revision {rows.poolRevision} · {rows.total} belegte Benutzerplätze.</p>
      {!rows.assignments.length && <p>Keine Lizenzzuweisungen vorhanden.</p>}
      <ul className="space-y-4">{rows.assignments.map(assignment => <li className="rounded border border-white/10 p-3 space-y-2" key={assignment.id}>
        <p className="break-all">{users?.users.find(user => user.id === assignment.userId) ? userName(users.users.find(user => user.id === assignment.userId)) : assignment.userId} · 1 Lizenzplatz</p>
        <CompanyLicenseSources sources={assignment.sources} />
        <details><summary>Zuweisungsnachweis</summary><p className="break-all">Zuweisung {assignment.id} · Generation {assignment.eligibilityRevision}</p><p>{new Date(assignment.assignedAt).toLocaleString('de-CH')}</p></details>
        <button className="fluent-btn-secondary" disabled={blocked} onClick={() => inspect(assignment.userId)}>Lizenzquellen dieses Mitarbeiters prüfen</button>
      </li>)}</ul>
      <nav aria-label="Quellenbasierte Zuweisungsseiten" className="flex gap-4"><button disabled={blocked || rows.page <= 1} onClick={() => { setPreview(null); void run(current => current.assignments(pool.id, rows.page - 1), setRows); }}>Zurück</button><span>Seite {rows.page} · {rows.total} Einträge</span><button disabled={blocked || rows.page * 25 >= rows.total} onClick={() => { setPreview(null); void run(current => current.assignments(pool.id, rows.page + 1), setRows); }}>Weiter</button></nav>
    </section>}
    {ready && pickerReady && <section aria-label="Manuelle Lizenzquelle vorbereiten" className="space-y-3">
      {users ? <><form className="flex flex-wrap items-end gap-3" onSubmit={event => { event.preventDefault(); setUserId(''); setPreview(null); void run(current => current.users(1, search), setUsers); }}>
        <label>Lizenz-Mitarbeiter suchen<input className={inputClass} disabled={blocked} maxLength={100} value={search} onChange={event => setSearch(event.target.value)} /></label><button className="fluent-btn-secondary" disabled={blocked}>Lizenz-Mitarbeiter suchen</button>
      </form><label>Lizenz-Mitarbeiter auswählen<select className={inputClass} disabled={blocked} value={userId} onChange={event => { setUserId(event.target.value); setPreview(null); }}><option value="">Mitarbeiter wählen …</option>{users.users.map(user => <option key={user.id} value={user.id}>{userName(user)} · {user.username}</option>)}</select></label>
        <nav aria-label="Lizenz-Mitarbeiterseiten" className="flex gap-4"><button disabled={blocked || users.page <= 1} onClick={() => { setUserId(''); setPreview(null); void run(current => current.users(users.page - 1, search), setUsers); }}>Zurück</button><span>Seite {users.page} · {users.total} Mitarbeiter</span><button disabled={blocked || users.page * 25 >= users.total} onClick={() => { setUserId(''); setPreview(null); void run(current => current.users(users.page + 1, search), setUsers); }}>Weiter</button></nav>
      </> : <label>Bekannte Lizenz-Mitarbeiter-ID<input className={inputClass} disabled={blocked} maxLength={36} value={userId} onChange={event => { setUserId(event.target.value); setPreview(null); }} /><span className="text-sm">Keine Profil-Leseberechtigung. Bekannte eigene UUID eingeben; der Server prüft das Ziel.</span></label>}
      <button className="fluent-btn-secondary" disabled={blocked || !userId} onClick={() => inspect()}>Lizenzquellen-Vorschau laden</button>
    </section>}
    {preview && <section aria-label="Manuelle Lizenzquellen-Vorschau" className="rounded border border-white/20 p-3 space-y-3">
      <p className="break-all">Mitarbeiter {preview.target.id} · {preview.target.deleted ? 'Gelöscht' : preview.target.enabled ? 'Aktiv' : 'Gesperrt'} · Berechtigungsgeneration {preview.target.eligibilityRevision} · Pool-Revision {preview.poolRevision}</p>
      {preview.assignment ? <><p>1 belegter Lizenzplatz · {preview.assignment.sources.length} Quellen.</p><CompanyLicenseSources sources={preview.assignment.sources} /></> : <p>Noch kein Lizenzplatz belegt. Eine neue manuelle Quelle benötigt einen freien Platz.</p>}
      <label>Begründung der manuellen Lizenzquelle<input className={inputClass} maxLength={500} disabled={blocked} value={reason} onChange={event => setReason(event.target.value)} /></label>
      {!preview.assignment?.sources.some(source => source.sourceType === 'direct') ? <button className="fluent-btn-primary" disabled={blocked || !preview.target.enabled || preview.target.deleted || reason.trim().length < 10} onClick={() => prepare('manual_assign')}>Manuelle Quelle hinzufügen</button>
        : <button className="fluent-btn-secondary" disabled={blocked || reason.trim().length < 10} onClick={() => prepare('manual_revoke')}>Manuelle Quelle entfernen</button>}
      {preview.assignment?.sources.some(source => source.sourceType === 'blueprint') && <p>Blueprint-Quellen bleiben bei einer manuellen Rücknahme erhalten. Rücknahme der Bindung unter Firmen-Blueprints.</p>}
    </section>}
    {receipt && <section aria-label="Quellenbasierter Lizenznachweis" className="rounded border border-green-500/30 p-3 space-y-2">
      <h4>{receipt.sourceAdded ? 'Manuelle Quelle hinzugefügt' : 'Manuelle Quelle entfernt'}</h4>
      <p>{receipt.seatAllocated ? 'Ein Lizenzplatz wurde belegt.' : receipt.seatReleased ? 'Der letzte Ursprung wurde entfernt; ein Lizenzplatz wurde freigegeben.' : 'Der Lizenzplatz bleibt durch andere Quellen belegt.'}</p>
      <p>{receipt.outcome === 'already_applied' ? 'Ursprünglicher Versuch bereits gespeichert.' : 'Vorgang gespeichert.'} Historischer Nachweis, nicht der aktuelle Stand. Ereigniszustellung ausstehend.</p><p className="break-all">Vorgang {receipt.operationId} · Pool-Revision {receipt.poolRevision}</p>
    </section>}
    {intent && <aside aria-label="Unbestätigte manuelle Lizenzänderung" className="space-y-3"><p>Das Ergebnis könnte bereits gespeichert sein. Nur den exakt ursprünglichen Versuch ausdrücklich prüfen; keine automatische Wiederholung.</p><p className="break-all">Vorgang {intent.operationId}</p>
      <button className="fluent-btn-secondary" disabled={busy || !client.current?.canRetry(intent)} onClick={() => { setConfirmation(intent); setConfirmed(false); }}>Ursprüngliche Lizenzänderung wiederaufnehmen</button>
    </aside>}
    {confirmation && <DirectoryConfirmation title={confirmation.action === 'manual_assign' ? 'Manuelle Lizenzquelle hinzufügen' : 'Manuelle Lizenzquelle entfernen'} busy={busy} error={confirmed ? '' : 'Bitte genau diesen Vorgang bestätigen.'} onClose={() => { setConfirmation(null); setConfirmed(false); }} onConfirm={write}>
      <p>{pool.name} · Mitarbeiter {confirmation.userId}</p><p>{String(confirmation.body.reason)}</p><p>Nur die manuelle Quelle wird geändert. Andere Quellen bleiben erhalten. Keine Installation, Cloud-Zuweisung oder Abrechnung.</p>
      <label className="flex gap-3 mt-3"><input type="checkbox" checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)} />Ich bestätige diese manuelle Lizenzänderung.</label>
    </DirectoryConfirmation>}
  </section>;
}
