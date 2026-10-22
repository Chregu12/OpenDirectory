'use client';

import React, { useEffect, useRef, useState } from 'react';
import { ViewShell } from '@/components/ui/ViewShell';
import { DataTable } from '@/components/ui/DataTable';
import { CompanyApplicationsCapabilities, CompanyApplicationsClient, CompanyAssignment, CompanyAssignmentPage, CompanyHistoryPage, CompanyLicenseReturnAssignment, CompanyLicenseReturnPreview, CompanyLicenseReturnReceipt, CompanyPool, CompanyPoolInput, CompanyPoolPage, companyApplicationsError, normalizeCompanyLicenseReason, normalizeCompanyPoolInput } from '@/lib/companyApplications';
import { UserPage, userName } from '@/lib/directoryUsers';
import { DirectoryConfirmation } from './UserDetailPanel';
import CompanyOffboardingPanel from './CompanyOffboardingPanel';
import CompanyApplicationAssignmentsPanel from './CompanyApplicationAssignmentsPanel';
import CompanyOffboardingV2Panel from './CompanyOffboardingV2Panel';

const initialValues: CompanyPoolInput = { name: '', vendor: '', description: '', totalSeats: 1, reason: '' };
const eventLabels = { 'app.license.pool.created': 'Lizenzpool erstellt', 'app.license.pool.updated': 'App und Lizenzbestand aktualisiert', 'app.license.assigned': 'Lizenz zugewiesen', 'app.license.released': 'Lizenz freigegeben', 'app.license.source.assigned': 'Lizenzquelle zugewiesen', 'app.license.source.released': 'Lizenzquelle zurückgegeben' };
const returnLabels = { released: 'Freigabe bestätigt', unconfirmed: 'Ergebnis nicht bestätigt', not_attempted: 'Nicht versucht' };
function Pagination({ page, total, label, disabled, onPage }: { page: number; total: number; label: string; disabled: boolean; onPage: (page: number) => void }) {
  return <nav aria-label={label} className="flex flex-wrap items-center gap-4 py-3 text-sm">
    <button className="fluent-btn-secondary" aria-label={'Vorherige ' + label} disabled={disabled || page <= 1} onClick={() => onPage(page - 1)}>Zurück</button>
    <span>Seite {page} von {Math.max(1, Math.ceil(total / 25))} · {total} Einträge</span>
    <button className="fluent-btn-secondary" aria-label={'Nächste ' + label} disabled={disabled || page * 25 >= total} onClick={() => onPage(page + 1)}>Weiter</button>
  </nav>;
}

export default function CompanyApplicationsView() {
  const client = useRef<CompanyApplicationsClient | null>(null);
  const generation = useRef(0);
  const writing = useRef(false);
  const [reload, setReload] = useState(0);
  const [access, setAccess] = useState<CompanyApplicationsCapabilities | null>(null);
  const [protocol, setProtocol] = useState<'v1' | 'v2'>('v2');
  const [pools, setPools] = useState<CompanyPoolPage | null>(null);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [searchDraft, setSearchDraft] = useState('');
  const [listVersion, setListVersion] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<CompanyPool | null>(null);
  const [assignments, setAssignments] = useState<CompanyAssignmentPage | null>(null);
  const [assignmentPage, setAssignmentPage] = useState(1);
  const [history, setHistory] = useState<CompanyHistoryPage | null>(null);
  const [historyPage, setHistoryPage] = useState(1);
  const [detailVersion, setDetailVersion] = useState(0);
  const [poolVersion, setPoolVersion] = useState(0);
  const [users, setUsers] = useState<UserPage | null>(null);
  const [picker, setPicker] = useState<'loading' | 'directory' | 'uuid'>('loading');
  const [userPage, setUserPage] = useState(1);
  const [userSearch, setUserSearch] = useState('');
  const [userSearchDraft, setUserSearchDraft] = useState('');
  const [targetUserId, setTargetUserId] = useState('');
  const [reason, setReason] = useState('');
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<CompanyPool | null>(null);
  const [editPending, setEditPending] = useState<{ pool: CompanyPool; input: CompanyPoolInput } | null>(null);
  const [values, setValues] = useState<CompanyPoolInput>({ ...initialValues });
  const [formError, setFormError] = useState('');
  const [pending, setPending] = useState<{ pool: CompanyPool; userId: string; reason: string; assignment: CompanyAssignment | null } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [returnsOpen, setReturnsOpen] = useState(false);
  const [returnUserId, setReturnUserId] = useState('');
  const [returnPreview, setReturnPreview] = useState<CompanyLicenseReturnPreview | null>(null);
  const [returnReason, setReturnReason] = useState('');
  const [returnFormError, setReturnFormError] = useState('');
  const [returnPending, setReturnPending] = useState<{ preview: CompanyLicenseReturnPreview; reason: string } | null>(null);
  const [returnReceipt, setReturnReceipt] = useState<{ receipt: CompanyLicenseReturnReceipt; assignments: CompanyLicenseReturnAssignment[]; page: number; total: number } | null>(null);
  const canRead = access?.permissions.includes('company.apps.read');
  const canCreate = canRead && access?.permissions.includes('company.apps.create');
  const canAssign = canRead && access?.permissions.includes('company.apps.assign');
  const clearReturns = () => { setReturnPreview(null); setReturnPending(null); setReturnReason(''); setReturnFormError(''); };
  const clearSelection = () => {
    setSelectedId(null); setSelected(null); setAssignments(null); setAssignmentPage(1); setHistory(null); setHistoryPage(1);
    setPending(null); setEditing(null); setEditPending(null); setUsers(null); setPicker('loading'); setUserPage(1); setUserSearch(''); setUserSearchDraft(''); setTargetUserId(''); setReason(''); setFormError('');
  };
  const fail = (failure: unknown, expected: number, readback = false) => {
    if (generation.current !== expected) return;
    generation.current += 1; client.current?.invalidate(); writing.current = false;
    setAccess(null); setPools(null); clearSelection(); clearReturns(); setReturnUserId(''); setReturnReceipt(null); setCreating(false); setBusy(false); setNotice('');
    setError(companyApplicationsError(failure) + (readback ? ' Die Änderung kann bereits wirksam sein. Nicht erneut bestätigen; zuerst den aktuellen Pool neu laden und prüfen.' : ''));
  };
  useEffect(() => {
    const current = new CompanyApplicationsClient(); client.current = current;
    const expected = ++generation.current;
    setAccess(null); setPools(null); clearSelection(); clearReturns(); setReturnUserId(''); setCreating(false); setBusy(false); setError(''); setNotice(''); writing.current = false;
    const onSessionError = () => fail({ response: { status: 401 } }, expected);
    window.addEventListener('od:session-error', onSessionError);
    current.reload().then(result => { if (generation.current === expected) {
      let saved = null; try { saved = window.sessionStorage.getItem(`od:company-license-view:${result.tenantId}:${result.actorUserId}`); } catch {}
      const currentRequested = new URLSearchParams(window.location.search).get('licenseView') === 'source-aware';
      setProtocol(!currentRequested && saved === 'v1' ? 'v1' : 'v2'); setAccess(result);
    } }).catch(failure => fail(failure, expected));
    return () => { generation.current += 1; current.dispose(); window.removeEventListener('od:session-error', onSessionError); };
  }, [reload]);
  useEffect(() => {
    if (!canRead) return;
    const controller = new AbortController(); const expected = generation.current; let active = true;
    setPools(null);
    client.current.list(page, search, controller.signal).then(result => { if (active && generation.current === expected) setPools(result); }).catch(failure => { if (active) fail(failure, expected); });
    return () => { active = false; controller.abort(); };
  }, [access, page, search, listVersion]);
  useEffect(() => {
    if (!canRead || !selectedId) return;
    const controller = new AbortController(); const expected = generation.current; let active = true;
    setSelected(null);
    client.current.get(selectedId, controller.signal).then(result => { if (active && generation.current === expected) setSelected(result); }).catch(failure => { if (active) fail(failure, expected); });
    return () => { active = false; controller.abort(); };
  }, [access, selectedId, poolVersion]);
  useEffect(() => {
    if (!canRead || !selectedId || protocol !== 'v1') return;
    const controller = new AbortController(); const expected = generation.current; let active = true;
    setAssignments(null);
    client.current.listAssignments(selectedId, assignmentPage, controller.signal).then(result => { if (active && generation.current === expected) setAssignments(result); }).catch(failure => { if (active) fail(failure, expected); });
    return () => { active = false; controller.abort(); };
  }, [access, selectedId, assignmentPage, detailVersion, protocol]);
  useEffect(() => {
    if (!canRead || !selectedId || protocol !== 'v1') return;
    const controller = new AbortController(); const expected = generation.current; let active = true;
    setHistory(null);
    client.current.history(selectedId, historyPage, controller.signal).then(result => { if (active && generation.current === expected) setHistory(result); }).catch(failure => { if (active) fail(failure, expected); });
    return () => { active = false; controller.abort(); };
  }, [access, selectedId, historyPage, detailVersion, protocol]);
  useEffect(() => {
    if (!canAssign || !selected || protocol !== 'v1') return;
    const controller = new AbortController(); const expected = generation.current; let active = true;
    setUsers(null); setPicker('loading'); setTargetUserId('');
    client.current.users(userPage, userSearch, controller.signal).then(result => {
      if (active && generation.current === expected) { setUsers(result); setPicker(result ? 'directory' : 'uuid'); }
    }).catch(failure => { if (active) fail(failure, expected); });
    return () => { active = false; controller.abort(); };
  }, [access, selected?.id, userPage, userSearch, protocol]);

  const begin = (assignment: CompanyAssignment | null) => {
    if (busy || !selected || !canAssign) return;
    try {
      const normalized = normalizeCompanyLicenseReason(reason);
      const userId = assignment ? assignment.userId : targetUserId;
      if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(userId)) throw new Error();
      setFormError(''); setPending({ pool: selected, assignment, userId, reason: normalized });
    } catch { setFormError('Bitte eine kanonische Benutzer-ID und eine Begründung mit 10 bis 500 Zeichen eingeben.'); }
  };
  const confirm = async () => {
    if (!pending || !canAssign || writing.current) return;
    const change = pending; const expected = generation.current;
    writing.current = true; setBusy(true); setNotice('');
    try {
      const input = { userId: change.userId, reason: change.reason, confirm: true as const };
      const result = change.assignment ? await client.current.revoke(change.pool, change.assignment, input) : await client.current.assign(change.pool, input);
      if (generation.current !== expected) return;
      setSelected(result); setPending(null); setTargetUserId(''); setReason(''); clearReturns(); setReturnReceipt(null);
      setPools(current => current && ({ ...current, pools: current.pools.map(pool => pool.id === result.id ? result : pool) }));
      setAssignmentPage(1); setHistoryPage(1); setDetailVersion(value => value + 1);
      setNotice(change.assignment ? 'Lokale Lizenzzuweisung freigegeben.' : 'Lokale Lizenzzuweisung gespeichert.');
    } catch (failure) { fail(failure, expected); }
    finally { if (generation.current === expected) { writing.current = false; setBusy(false); } }
  };

  const beginEdit = async () => {
    if (!selected || !canCreate || busy || writing.current) return;
    const snapshot = selected; const expected = generation.current;
    writing.current = true; setBusy(true); setNotice('');
    try {
      await client.current.editCapabilities(snapshot);
      if (generation.current !== expected) return;
      setValues({ name: snapshot.name, vendor: snapshot.vendor, description: snapshot.description, totalSeats: snapshot.totalSeats, reason: '' });
      setFormError(''); setEditing(snapshot); setEditPending(null);
    } catch (failure) { fail(failure, expected); }
    finally { if (generation.current === expected) { writing.current = false; setBusy(false); } }
  };
  const confirmEdit = async () => {
    if (!editPending || editPending.pool !== editing || !canCreate || writing.current) return;
    const change = editPending; const expected = generation.current;
    writing.current = true; setBusy(true); setNotice('');
    try {
      await client.current.edit(change.pool, { ...change.input, confirm: true });
      if (generation.current !== expected) return;
      setEditing(null); setEditPending(null); setPending(null); setSelected(null); setPools(null); setAssignments(null); setHistory(null);
      clearReturns(); setReturnReceipt(null); setTargetUserId(''); setReason('');
      setPage(1); setListVersion(value => value + 1); setPoolVersion(value => value + 1);
      setAssignmentPage(1); setHistoryPage(1); setDetailVersion(value => value + 1);
      setNotice('App und lokaler Lizenzbestand aktualisiert.');
    } catch (failure) { fail(failure, expected, true); }
    finally { if (generation.current === expected) { writing.current = false; setBusy(false); } }
  };

  const previewReturns = async (nextPage = 1) => {
    if (!canAssign || writing.current) return;
    if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(returnUserId)) { setReturnFormError('Bitte eine bekannte kanonische Benutzer-ID der eigenen Firma eingeben.'); return; }
    const expected = generation.current; writing.current = true; setBusy(true); clearReturns(); setReturnReceipt(null);
    try {
      const result = await client.current.previewLicenseReturns(returnUserId, nextPage);
      if (generation.current === expected) setReturnPreview(result);
    } catch (failure) { fail(failure, expected); }
    finally { if (generation.current === expected) { writing.current = false; setBusy(false); } }
  };
  const beginReturns = () => {
    if (!returnPreview || busy || !canAssign || returnPreview.target.enabled || !returnPreview.assignments.length) return;
    try { setReturnPending({ preview: returnPreview, reason: normalizeCompanyLicenseReason(returnReason) }); setReturnFormError(''); }
    catch { setReturnFormError('Bitte eine Begründung mit 10 bis 500 Zeichen eingeben.'); }
  };
  const confirmReturns = async () => {
    if (!returnPending || returnPending.preview !== returnPreview || !canAssign || writing.current) return;
    const change = returnPending; const expected = generation.current;
    writing.current = true; setBusy(true); setReturnReceipt(null);
    try {
      const receipt = await client.current.returnLicenses(change.preview, { reason: change.reason, confirm: true });
      if (generation.current !== expected) return;
      setReturnReceipt({ receipt, assignments: change.preview.assignments, page: change.preview.page, total: change.preview.total }); setAccess(null);
      clearReturns(); clearSelection(); setReturnUserId(''); generation.current += 1; setReload(value => value + 1);
    } catch (failure) { fail(failure, expected); }
    finally { if (generation.current === expected) { writing.current = false; setBusy(false); } }
  };

  return <ViewShell title="Anwendungen & Lizenzen" subtitle="Eigene Firmen-App-Lizenzpools und lokale Benutzerzuweisungen."
    primaryAction={canCreate && pools ? { label: 'Lizenzpool erstellen', onClick: () => { setValues({ ...initialValues }); setFormError(''); setCreating(true); setNotice(''); }, disabled: busy } : undefined}
    actions={[{ label: 'Neu laden', onClick: () => { generation.current += 1; client.current?.invalidate(); clearReturns(); setReturnReceipt(null); setReload(value => value + 1); }, disabled: busy }]}>
    <div className="space-y-5" style={{ color: 'var(--text-primary)' }}>
      <p className="rounded-lg border border-white/10 p-4 text-sm">Nur lokale Lizenzverteilung an Benutzer der eigenen Firma. Keine Cloud-Zuweisung, Installation, SSO-Einrichtung oder Abrechnung. Gesperrte Benutzer und pausierte Mandanten sind keine zulässigen neuen Ziele. Kontosperren geben diese lokalen Lizenzen noch nicht automatisch zurück. Bestehende Zuweisungen können ausdrücklich freigegeben werden, auch bei gesperrten oder gelöschten Benutzern.</p>
      {error ? <p role="alert" className="rounded border border-red-500/40 p-4">{error}</p> : !access ? <p role="status">Lizenzberechtigungen werden geprüft …</p> : !canRead ? <p role="status">Keine Berechtigung zum Lesen der Firmen-Lizenzpools.</p> : <>
        {notice && <p role="status">{notice}</p>}
        <nav aria-label="Lizenzverwaltungsmodus" className="flex flex-wrap gap-3">
          <button className="fluent-btn-secondary" aria-pressed={protocol === 'v2'} disabled={busy} onClick={() => {
            if (protocol === 'v2') return;
            try { window.sessionStorage.setItem(`od:company-license-view:${access.tenantId}:${access.actorUserId}`, 'v2'); } catch {}
            generation.current++; client.current?.invalidate(); clearReturns(); clearSelection(); setReturnReceipt(null); setAccess(null); setPools(null); setProtocol('v2'); setReload(value => value + 1);
          }}>Aktuelle quellenbasierte Verwaltung</button>
          <button className="fluent-btn-secondary" aria-pressed={protocol === 'v1'} disabled={busy} onClick={() => {
            if (protocol === 'v1') return;
            try { window.sessionStorage.setItem(`od:company-license-view:${access.tenantId}:${access.actorUserId}`, 'v1'); } catch {}
            generation.current++; client.current?.invalidate(); clearReturns(); clearSelection(); setReturnReceipt(null); setAccess(null); setPools(null); setProtocol('v1'); setReload(value => value + 1);
          }}>Bisherige Direktverwaltung</button>
        </nav>
        {canAssign && (protocol === 'v2' ? <CompanyOffboardingV2Panel context={access} /> : <div><h2 className="font-semibold">Bisherige Offboarding-Vorgänge</h2><p>Diese Direktverwaltung unterstützt keine gemischten Blueprint-Quellen. Ein Upgrade-Konflikt gibt keine Lizenz frei. Für alle Quellen ausdrücklich zur aktuellen Verwaltung wechseln.</p><CompanyOffboardingPanel context={access} /></div>)}
        {returnReceipt && access.actorUserId === returnReceipt.receipt.actorUserId && access.tenantId === returnReceipt.receipt.tenantId && <section aria-label="Ergebnis der Lizenzrückgabe" className="rounded border border-white/10 p-4 space-y-3">
          <p role="status">{returnReceipt.receipt.results.filter(row => row.status === 'released').length} von {returnReceipt.receipt.results.length} Freigaben dieser Seite bestätigt · Seite {returnReceipt.page} · zuvor {returnReceipt.total} Zuweisungen insgesamt.</p>
          <ul className="space-y-4">{returnReceipt.receipt.results.map(row => {
            const assignment = returnReceipt.assignments.find(candidate => candidate.id === row.assignmentId && candidate.poolId === row.poolId);
            return <li key={row.assignmentId} className="text-sm space-y-1">
              <p className="font-medium">{assignment?.name || 'Lokale Lizenzzuweisung'} · {returnLabels[row.status]}{row.code !== null && ` (${row.code})`}</p>
              {assignment && <p>{assignment.vendor}</p>}
              <details><summary className="cursor-pointer">Nachweis</summary>
                <dl className="mt-3 space-y-2">{Object.entries({ 'Pool-ID': row.poolId, 'Zuweisungs-ID': row.assignmentId, 'Benutzer-ID': returnReceipt.receipt.userId, 'Korrelations-ID': returnReceipt.receipt.correlationId }).map(([label, value]) => <div key={label}><dt className="opacity-70">{label}</dt><dd className="break-all">{value}</dd></div>)}</dl>
              </details>
            </li>;
          })}</ul>
          <p>Unbestätigte Ergebnisse können bereits wirksam sein. Bitte ausdrücklich eine neue Vorschau laden und prüfen; keine automatische Wiederholung. Dies bestätigt nur diese Seite, kein vollständiges Offboarding.</p>
        </section>}
        {canAssign && protocol === 'v1' && <section aria-label="Mitarbeiter-Lizenzrückgabe" className="rounded border border-white/10 p-4 space-y-3">
          <button className="fluent-btn-secondary" aria-expanded={returnsOpen} aria-controls="company-license-returns" disabled={busy} onClick={() => { setReturnsOpen(value => !value); clearReturns(); }}>Lizenzen eines Mitarbeiters zurückgeben</button>
          {returnsOpen && <div id="company-license-returns" className="space-y-4">
            <p>Zuerst unter People → Konto sperren das Konto sperren. Diese Aktion gibt ausschließlich lokale Lizenzen eines gesperrten oder gelöschten Mitarbeiters zurück. Sie sperrt kein Konto und führt keinen automatischen Offboarding-, Sitzungs- oder Geräteworkflow aus.</p>
            <form className="flex flex-wrap items-end gap-3" onSubmit={event => { event.preventDefault(); void previewReturns(); }}>
              <label className="text-sm">Mitarbeiter-ID für Lizenzrückgabe<input className="mt-1 block rounded border p-2 bg-transparent" aria-describedby="company-license-return-hint" minLength={36} maxLength={36} required pattern="[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}" value={returnUserId} disabled={busy || !!returnPending} onChange={event => { setReturnUserId(event.target.value); clearReturns(); setReturnReceipt(null); }} /></label>
              <button className="fluent-btn-secondary" type="submit" disabled={busy || !!returnPending}>Lizenzrückgabe-Vorschau laden</button>
              <p id="company-license-return-hint" className="text-sm">Bekannte kanonische UUID der eigenen Firma, auch bei gesperrten oder gelöschten Mitarbeitern. Der Server prüft Ziel, Berechtigung und aktuelle MFA für jede Anfrage. Die Vorschau schreibt nichts.</p>
            </form>
            {returnFormError && <p role="alert">{returnFormError}</p>}
            {returnPreview && <section aria-label="Lizenzrückgabe-Vorschau" className="space-y-3">
              <p>Benutzer-ID: {returnPreview.userId} · {returnPreview.target.deleted ? 'Gelöscht' : returnPreview.target.enabled ? 'Aktiv' : 'Gesperrt'} · Zielversion {returnPreview.target.eligibilityRevision}</p>
              <p>{returnPreview.assignments.length} Zuweisungen auf dieser Seite von {returnPreview.total} insgesamt. Nur diese vollständige Seite mit höchstens 25 Zuweisungen wird ausgewählt.</p>
              {returnPreview.target.enabled && <p role="status">Aktiver Mitarbeiter: Rückgabe gesperrt. Zuerst People → Konto sperren, danach ausdrücklich eine neue Vorschau laden.</p>}
              <DataTable<CompanyLicenseReturnAssignment> rows={returnPreview.assignments} getRowId={row => row.id} emptyMessage="Keine lokalen Lizenzzuweisungen für diesen Mitarbeiter vorhanden." columns={[
                { key: 'name', header: 'Anwendung' }, { key: 'vendor', header: 'Hersteller' }, { key: 'poolRevision', header: 'Poolversion' },
                { key: 'assignedAt', header: 'Zugewiesen am', render: row => <time dateTime={row.assignedAt}>{new Date(row.assignedAt).toLocaleString('de-CH', { dateStyle: 'medium', timeStyle: 'short' })}</time> },
                { key: 'proof', header: 'Nachweis', render: row => <details><summary>Nachweis</summary><p>Pool-ID: {row.poolId} · Zuweisungs-ID: {row.id} · Grant-ID: {row.grantId}</p></details> },
              ]} />
              <Pagination label="Rückgabeseite" page={returnPreview.page} total={returnPreview.total} disabled={busy || !!returnPending} onPage={next => { void previewReturns(next); }} />
              <label className="block text-sm">Begründung der Lizenzrückgabe<input className="mt-1 block w-full rounded border p-2 bg-transparent" minLength={10} maxLength={500} value={returnReason} disabled={busy || !!returnPending} onChange={event => setReturnReason(event.target.value)} /></label>
              <button className="fluent-btn-secondary" disabled={busy || returnPreview.target.enabled || returnPreview.assignments.length === 0} onClick={beginReturns}>Diese Seite zurückgeben</button>
            </section>}
          </div>}
        </section>}
        <form className="flex flex-wrap items-end gap-3" onSubmit={event => { event.preventDefault(); clearSelection(); setPage(1); setSearch(searchDraft.trim()); setListVersion(value => value + 1); }}>
          <label className="text-sm">Anwendungen suchen<input className="mt-1 block rounded border p-2 bg-transparent" maxLength={200} disabled={busy} value={searchDraft} onChange={event => setSearchDraft(event.target.value)} placeholder="Name oder Hersteller" /></label>
          <button className="fluent-btn-secondary" type="submit" disabled={busy}>Suchen</button>
        </form>
        {pools ? <section aria-label="Firmen-Lizenzpools">
          <DataTable<CompanyPool> rows={pools.pools} getRowId={pool => pool.id} activeRowId={selectedId} emptyMessage="Keine Firmen-Lizenzpools gefunden." columns={[
            { key: 'name', header: 'Anwendung', render: pool => <button className="text-blue-500 underline" disabled={busy} onClick={() => { if (selectedId === pool.id) return; clearSelection(); setSelectedId(pool.id); }}>{pool.name}</button> },
            { key: 'vendor', header: 'Hersteller' }, { key: 'totalSeats', header: 'Lizenzbestand' }, { key: 'usedSeats', header: 'Zugewiesen' }, { key: 'availableSeats', header: 'Verfügbar' },
          ]} />
          <Pagination label="Poolseite" page={pools.page} total={pools.total} disabled={busy} onPage={next => { clearSelection(); setPage(next); }} />
        </section> : <p role="status">Lizenzpools werden geladen …</p>}
        {selectedId && !selected && <p role="status">Lizenzpool wird geladen …</p>}
        {selected && <article aria-label="Lizenzpooldetails" className="rounded-lg border border-white/10 p-5 space-y-5">
          <div className="flex items-start justify-between gap-4"><h2 className="text-xl font-semibold">{selected.name}</h2><button className="fluent-btn-secondary" disabled={busy} onClick={clearSelection}>Details schließen</button></div>
          <dl className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">{Object.entries({
            'Pool-ID': selected.id, 'Firmen-ID': selected.tenantId, Hersteller: selected.vendor, Beschreibung: selected.description || '—',
            Lizenzbestand: selected.totalSeats, Zugewiesen: selected.usedSeats, Verfügbar: selected.availableSeats,
            Lizenzmodell: 'Pro Benutzer · lokal', Datensatzversion: selected.revision, 'Erstellt am': selected.createdAt, 'Geändert am': selected.updatedAt,
          }).map(([label, value]) => <div key={label}><dt className="opacity-70">{label}</dt><dd className="break-words">{value}</dd></div>)}</dl>
          {canCreate && <button className="fluent-btn-secondary" disabled={busy} onClick={() => { void beginEdit(); }}>App und Lizenzbestand bearbeiten</button>}
          {protocol === 'v2' && <CompanyApplicationAssignmentsPanel key={access.actorUserId + ':' + access.tenantId + ':' + selected.id} context={access} pool={selected} onReload={() => {
            setPoolVersion(value => value + 1); setListVersion(value => value + 1);
          }} />}
          {canAssign && protocol === 'v1' && <section aria-label="Lizenz zuweisen" className="border-t border-white/10 pt-4 space-y-4">
            <h3 className="font-semibold">Lizenz zuweisen oder freigeben</h3>
            <label className="block text-sm">Begründung<input className="mt-1 block w-full rounded border p-2 bg-transparent" minLength={10} maxLength={500} value={reason} disabled={busy} onChange={event => setReason(event.target.value)} /></label>
            {formError && <p role="alert">{formError}</p>}
            {selected.availableSeats === 0 && <p role="status">Keine freien Lizenzen. Bestehende Zuweisungen können freigegeben werden.</p>}
            {picker === 'loading' ? <p role="status">Verzeichnisberechtigung wird geprüft …</p> : <>
              {picker === 'directory' && <>
                <form className="flex flex-wrap items-end gap-3" onSubmit={event => { event.preventDefault(); setUserPage(1); setUserSearch(userSearchDraft.trim()); }}>
                  <label className="text-sm">Benutzer suchen<input className="block rounded border p-2 bg-transparent" maxLength={200} disabled={busy} value={userSearchDraft} onChange={event => setUserSearchDraft(event.target.value)} /></label>
                  <button className="fluent-btn-secondary" type="submit" disabled={busy}>Benutzer suchen</button>
                </form>
                <label className="block text-sm">Benutzer auswählen<select aria-label="Benutzer auswählen" className="block w-full rounded border p-2 bg-transparent" value={targetUserId} disabled={busy} onChange={event => setTargetUserId(event.target.value)}>
                  <option value="">Benutzer wählen …</option>{users?.users.map(user => <option key={user.id} value={user.id}>{userName(user)} · {user.username}</option>)}
                </select></label>
                {users && <Pagination label="Benutzerseite" page={users.page} total={users.total} disabled={busy} onPage={setUserPage} />}
              </>}
              <form className="flex flex-wrap items-end gap-3" onSubmit={event => { event.preventDefault(); begin(null); }}>
                {picker === 'uuid' && <div className="text-sm"><label>Kanonische Benutzer-ID<input className="mt-1 block rounded border p-2 bg-transparent" aria-describedby="company-license-user-hint" required minLength={36} maxLength={36} pattern="[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}" value={targetUserId} disabled={busy} onChange={event => setTargetUserId(event.target.value)} /></label><p id="company-license-user-hint" className="mt-1 opacity-70">Keine Leseberechtigung für Benutzerprofile. Bekannte UUID der eigenen Firma eingeben; der Server prüft das Ziel.</p></div>}
                <button className="fluent-btn-primary" type="submit" disabled={busy || !targetUserId || selected.availableSeats === 0 || reason.trim().length < 10}>Lizenz zuweisen</button>
              </form>
            </>}
          </section>}
          {protocol === 'v1' && <section aria-label="Lizenzzuweisungen" className="border-t border-white/10 pt-4 space-y-3">
            <h3 className="font-semibold">Lokale Lizenzzuweisungen</h3>
            {assignments ? <><DataTable<CompanyAssignment> rows={assignments.assignments} getRowId={assignment => assignment.id} emptyMessage="Keine Lizenzzuweisungen vorhanden." columns={[
              { key: 'userId', header: 'Benutzer', render: assignment => { const profile = users?.users.find(user => user.id === assignment.userId); return profile ? userName(profile) : assignment.userId; } },
              { key: 'assignedAt', header: 'Zugewiesen am', render: assignment => <time dateTime={assignment.assignedAt}>{new Date(assignment.assignedAt).toLocaleString('de-CH', { dateStyle: 'medium', timeStyle: 'short' })}</time> },
              { key: 'proof', header: 'Nachweis', render: assignment => <details>
                <summary className="cursor-pointer">Nachweis</summary>
                <dl className="mt-3 space-y-2 text-sm">{Object.entries({ 'Benutzer-ID': assignment.userId, 'Ausgeführt von': assignment.assignedBy, 'Grant-ID': assignment.grantId, 'Zuweisungs-ID': assignment.id }).map(([label, value]) => <div key={label}><dt className="opacity-70">{label}</dt><dd className="break-all">{value}</dd></div>)}</dl>
              </details> },
              ...(canAssign ? [{ key: 'action', header: 'Aktion', render: (assignment: CompanyAssignment) => <button className="fluent-btn-secondary" disabled={busy || reason.trim().length < 10} onClick={() => begin(assignment)}>Lizenz freigeben</button> }] : []),
            ]} /><Pagination label="Zuweisungsseite" page={assignments.page} total={assignments.total} disabled={busy} onPage={setAssignmentPage} /></> : <p role="status">Lizenzzuweisungen werden geladen …</p>}
          </section>}
          {protocol === 'v1' && <section aria-label="Lizenzhistorie" className="border-t border-white/10 pt-4 space-y-3">
            <h3 className="font-semibold">Lizenzhistorie</h3>
            {history ? <><ol className="space-y-4">{history.events.map(event => <li key={event.id} className="text-sm space-y-1">
              <p className="font-medium">{eventLabels[event.type]}</p><p><time dateTime={event.createdAt}>{event.createdAt}</time> · Version {event.beforeRevision || '—'} → {event.afterRevision}</p>
              <p className="break-words">Benutzer: {event.userId || '—'} · Ausgeführt von: {'actor' in event ? 'App ' + event.actor.clientId : event.actorUserId}</p>
              <p className="break-words">Korrelations-ID: {event.correlationId}</p><p className="opacity-70">Ereigniszustellung ausstehend</p>
            </li>)}</ol>{history.events.length === 0 && <p>Keine Ereignisse vorhanden.</p>}<Pagination label="Historienseite" page={history.page} total={history.total} disabled={busy} onPage={setHistoryPage} /></> : <p role="status">Lizenzhistorie wird geladen …</p>}
          </section>}
        </article>}
      </>}
    </div>
    {(creating || editing && !editPending) && canCreate && <DirectoryConfirmation title={editing ? 'App und Lizenzbestand bearbeiten' : 'Lizenzpool erstellen'} busy={busy} error="" onClose={() => { setCreating(false); setEditing(null); }} onConfirm={async () => {
      if (writing.current) return;
      let input: CompanyPoolInput;
      try { input = normalizeCompanyPoolInput(values); } catch { setFormError('Bitte Name, Hersteller, 1 bis 10’000 Lizenzen und Begründung mit 10 bis 500 Zeichen prüfen.'); return; }
      if (editing) {
        if (input.totalSeats < editing.usedSeats) { setFormError(`Der Lizenzbestand muss mindestens ${editing.usedSeats} bereits zugewiesene Lizenzen umfassen. Zuweisungen werden nicht automatisch freigegeben.`); return; }
        if (input.name === editing.name && input.vendor === editing.vendor && input.description === editing.description && input.totalSeats === editing.totalSeats) { setFormError('Keine Änderung an App oder Lizenzbestand. Bitte Werte ändern oder abbrechen.'); return; }
        setFormError(''); setEditPending({ pool: editing, input }); return;
      }
      const expected = generation.current; writing.current = true; setBusy(true); setFormError(''); setNotice('');
      try {
        const result = await client.current.create(input);
        if (generation.current !== expected) return;
        setCreating(false); clearReturns(); setReturnReceipt(null); setSearch(''); setSearchDraft(''); setPage(1); setListVersion(value => value + 1); setNotice(`Lokaler Lizenzpool ${result.name} erstellt.`);
      } catch (failure) { fail(failure, expected); }
      finally { if (generation.current === expected) { writing.current = false; setBusy(false); } }
    }}>
      <p className="text-sm">{editing ? `Bearbeitet ausschließlich diese App und ihren lokalen Lizenzbestand. Bereits zugewiesen: ${editing.usedSeats}; dieser Bestand darf nicht unterschritten werden. Kein Kauf, keine Abrechnung und keine Cloud-Bereitstellung.` : 'Erfasst einen lokalen Lizenzbestand. Kein Kauf und keine Cloud-Bereitstellung.'}</p>
      <fieldset disabled={busy} className="space-y-3 mt-4">
        {([{ field: 'name', label: 'Anwendungsname', maximum: 160 }, { field: 'vendor', label: 'Hersteller', maximum: 160 }, { field: 'description', label: 'Beschreibung', maximum: 2000 }, { field: 'reason', label: 'Begründung', maximum: 500 }] as const).map(({ field, label, maximum }) => <label className="block text-sm" key={field}>{label}<input className="mt-1 block w-full rounded border p-2 bg-transparent" maxLength={maximum} required={field !== 'description'} value={values[field]} onChange={event => setValues(previous => ({ ...previous, [field]: event.target.value }))} /></label>)}
        <label className="block text-sm">Lizenzanzahl<input className="mt-1 block w-full rounded border p-2 bg-transparent" type="number" required min={Math.max(1, editing?.usedSeats || 0)} max={10000} step={1} value={Number.isNaN(values.totalSeats) ? '' : values.totalSeats} onChange={event => setValues(previous => ({ ...previous, totalSeats: event.target.valueAsNumber }))} /></label>
      </fieldset>{formError && <p role="alert">{formError}</p>}
    </DirectoryConfirmation>}
    {editPending && editing && canCreate && <DirectoryConfirmation title="Änderungen an App und Lizenzbestand bestätigen" busy={busy} error="" onClose={() => { setEditPending(null); setEditing(null); }} onConfirm={confirmEdit}>
      <div className="max-h-[65vh] overflow-y-auto space-y-4">
        <p>Bitte alle Änderungen prüfen. Nur lokaler Lizenzbestand: kein Kauf, keine Abrechnung und keine Cloud-Änderung.</p>
        <table className="w-full text-sm text-left"><caption className="sr-only">App und Lizenzbestand vorher und nachher</caption>
          <thead><tr><th scope="col">Feld</th><th scope="col">Vorher</th><th scope="col">Nachher</th></tr></thead>
          <tbody>{([{ field: 'name', label: 'Anwendungsname' }, { field: 'vendor', label: 'Hersteller' }, { field: 'description', label: 'Beschreibung' }, { field: 'totalSeats', label: 'Lizenzbestand' }] as const).map(({ field, label }) => <tr key={field}><th scope="row" className="p-2">{label}</th><td className="p-2 break-words">{editPending.pool[field] || '—'}</td><td className="p-2 break-words">{editPending.input[field] || '—'}</td></tr>)}</tbody>
        </table>
        <p>Bereits zugewiesen: {editPending.pool.usedSeats}. Mindestbestand: {Math.max(1, editPending.pool.usedSeats)}. Bestehende Zuweisungen bleiben unverändert; keine automatische Freigabe.</p>
        <p>Begründung: {editPending.input.reason}</p>
      </div>
    </DirectoryConfirmation>}
    {pending && canAssign && <DirectoryConfirmation title={pending.assignment ? 'Lizenzfreigabe bestätigen' : 'Lizenzzuweisung bestätigen'} busy={busy} error="" onClose={() => setPending(null)} onConfirm={confirm}>
      <p>{pending.pool.name} · Benutzer-ID: {pending.userId}</p><p className="mt-3">Begründung: {pending.reason}</p><p className="mt-3 text-sm">Nur lokale {pending.assignment ? 'Freigabe' : 'Zuweisung'} · keine Cloud-Änderung oder Installation. Serverberechtigungen, Kapazitäts-, Review- und PIM-Prüfungen bleiben verbindlich.</p>
    </DirectoryConfirmation>}
    {returnPending && canAssign && <DirectoryConfirmation title="Mitarbeiter-Lizenzrückgabe bestätigen" busy={busy} error="" onClose={() => setReturnPending(null)} onConfirm={confirmReturns}>
      <p>Benutzer-ID: {returnPending.preview.userId}</p>
      <p>Seite {returnPending.preview.page}: genau {returnPending.preview.assignments.length} von insgesamt {returnPending.preview.total} Zuweisungen. Weitere Seiten werden nicht automatisch bearbeitet.</p>
      <ul className="max-h-60 overflow-auto">{returnPending.preview.assignments.map(row => <li key={row.id}>{row.name} · {row.vendor} · Poolversion {row.poolRevision} · {row.poolId} · {row.id}</li>)}</ul>
      <p>Begründung: {returnPending.reason}</p><p>Nur lokale Lizenzrückgabe. Der Server prüft die aktuelle Berechtigung, MFA, den Mitarbeiterstatus und jede Poolversion erneut. Unbestätigte Ergebnisse können bereits wirksam sein; keine automatische Wiederholung.</p>
    </DirectoryConfirmation>}
  </ViewShell>;
}
