'use client';

import React, { useEffect, useRef, useState } from 'react';
import { CompanyPool } from '@/lib/companyApplications';
import { CompanyWorkflowContext, companyWorkflowError, companyWorkflowUnsafe } from '@/lib/companyAssignmentProtocol';
import { CompanyMicrosoftClient, MicrosoftState, MicrosoftMappings, MicrosoftProducts, MicrosoftHistory, MicrosoftIntent, MicrosoftReceipt, MicrosoftPreview, MicrosoftSyncIntent, MicrosoftSyncReceipt } from '@/lib/companyMicrosoft';
import { UserPage, userName } from '@/lib/directoryUsers';
import { DirectoryConfirmation } from './UserDetailPanel';

const inputClass = 'mt-1 block w-full rounded border border-[var(--border-strong)] bg-transparent p-2';
const actionLabels = { connect: 'Microsoft-Verbindung bestätigen', renew: 'Microsoft-Verbindung neu prüfen', bind_pool: 'Microsoft-Produkt verknüpfen', bind_user: 'Microsoft-Benutzer verknüpfen', disconnect: 'Microsoft-Verbindung trennen', retire_pool: 'Produktverknüpfung entfernen', retire_user: 'Benutzerverknüpfung entfernen' };
const previewLabels = { assign: 'Microsoft-Lizenz zuweisen', remove: 'Verwaltete Microsoft-Lizenz zurückgeben', confirmed: 'Aktueller Stand stimmt überein', conflict: 'Abweichung prüfen', review: 'Unklaren Schreibversuch prüfen', recover: 'Unterbrochenen Vorgang prüfen', verify: 'Ausstehende Anbieterwirkung prüfen', external_retained: 'Externe Zuweisung erhalten' };
const stockStatusLabels = { Enabled: 'Aktiv', Warning: 'Warnung', Suspended: 'Ausgesetzt', Deleted: 'Gelöscht', LockedOut: 'Gesperrt' };
const eventLabels = { ...actionLabels, sync_prepared: 'Lizenzabgleich vorbereitet', sync_dispatched: 'Microsoft-Anfrage versendet', sync_finished: 'Ergebnis des Lizenzabgleichs gespeichert' };
const resultLabels = { verifying: 'Anbieterbestätigung ausstehend', confirmed: 'Abgleich durch unabhängige Rückprüfung bestätigt', conflict: 'Konflikt im Lizenzabgleich', failed: 'Lizenzabgleich fehlgeschlagen oder vor Versand abgebrochen', unknown: 'Ausgang der Microsoft-Anfrage unklar' };

export default function CompanyMicrosoftPanel({ context, pool, onAccessError }: { context: CompanyWorkflowContext; pool: CompanyPool; onAccessError: (error: unknown) => void }) {
  const client = useRef<CompanyMicrosoftClient | null>(null); const generation = useRef(0); const running = useRef(false);
  const [state, setState] = useState<MicrosoftState | null>(null); const [mappings, setMappings] = useState<MicrosoftMappings | null>(null);
  const [products, setProducts] = useState<MicrosoftProducts | null>(null); const [history, setHistory] = useState<MicrosoftHistory | null>(null);
  const [preview, setPreview] = useState<MicrosoftPreview | null>(null);
  const [syncReason, setSyncReason] = useState(''); const [syncConfirmation, setSyncConfirmation] = useState<MicrosoftSyncIntent | null>(null); const [syncConfirmed, setSyncConfirmed] = useState(false);
  const [syncIntent, setSyncIntent] = useState<MicrosoftSyncIntent | null>(null); const [syncReceipt, setSyncReceipt] = useState<MicrosoftSyncReceipt | null>(null);
  const [users, setUsers] = useState<UserPage | null>(null); const [usersLoaded, setUsersLoaded] = useState(false);
  const [userId, setUserId] = useState(''); const [objectId, setObjectId] = useState(''); const [skuId, setSkuId] = useState(''); const [search, setSearch] = useState(''); const [reason, setReason] = useState('');
  const [confirmation, setConfirmation] = useState<MicrosoftIntent | null>(null); const [confirmed, setConfirmed] = useState(false); const [intent, setIntent] = useState<MicrosoftIntent | null>(null); const [receipt, setReceipt] = useState<MicrosoftReceipt | null>(null);
  const [busy, setBusy] = useState(false); const [needsReload, setNeedsReload] = useState(false); const [error, setError] = useState(''); const [formError, setFormError] = useState('');
  const clear = () => { setState(null); setMappings(null); setProducts(null); setHistory(null); setUsers(null); setUsersLoaded(false); setUserId(''); setObjectId(''); setSkuId(''); setSearch(''); setReason(''); setConfirmation(null); setConfirmed(false); setIntent(null); setReceipt(null); setPreview(null); setSyncReason(''); setSyncConfirmation(null); setSyncConfirmed(false); setSyncIntent(null); setSyncReceipt(null); };
  const run = async <Value,>(operation: (current: CompanyMicrosoftClient) => Promise<Value>, apply: (value: Value) => void) => {
    if (!client.current || running.current) return;
    const current = client.current; const expected = generation.current; running.current = true; setBusy(true); setError(''); setFormError('');
    try { const value = await operation(current); if (expected === generation.current) apply(value); }
    catch (failure) {
      if (expected === generation.current) {
        setError(companyWorkflowError(failure)); setConfirmation(null); setConfirmed(false); setSyncConfirmation(null); setSyncConfirmed(false); setNeedsReload(true);
        if (companyWorkflowUnsafe(failure)) { current.invalidate(); clear(); onAccessError(failure); }
      }
    } finally { if (expected === generation.current) { running.current = false; setBusy(false); } }
  };
  useEffect(() => {
    generation.current++; client.current = new CompanyMicrosoftClient(context); running.current = false; clear(); setBusy(false); setNeedsReload(false); setError('');
    const sessionError = () => { generation.current++; client.current?.invalidate(); running.current = false; clear(); setBusy(false); setNeedsReload(true); setError(companyWorkflowError({ response: { status: 401 } })); };
    window.addEventListener('od:session-error', sessionError);
    return () => { generation.current++; client.current?.dispose(); window.removeEventListener('od:session-error', sessionError); };
  }, [context.actorUserId, context.tenantId, pool.id]);
  const reload = () => {
    generation.current++; client.current?.dispose(); client.current = new CompanyMicrosoftClient(context); running.current = false; clear(); setNeedsReload(false);
    void run(async current => ({ state: await current.state(), mappings: await current.mappings(pool.id), history: await current.history() }), value => { setState(value.state); setMappings(value.mappings); setHistory(value.history); });
  };
  const prepare = (capture: (current: CompanyMicrosoftClient) => MicrosoftIntent) => {
    if (blocked || !client.current) return;
    try { setPreview(null); setConfirmation(capture(client.current)); setConfirmed(false); setFormError(''); }
    catch { setFormError('Bitte den aktuellen Stand, die ausgewählten IDs und eine Begründung mit 10 bis 500 Zeichen prüfen.'); }
  };
  const write = () => {
    if (!confirmation || !confirmed || busy) return;
    const captured = confirmation; setIntent(captured);
    void run(current => current.write(captured), value => { setReceipt(value); setConfirmation(null); setConfirmed(false); setIntent(null); setNeedsReload(true); });
  };
  const beginSync = () => {
    if (blocked || !preview || !client.current) return;
    try { setReceipt(null); setSyncConfirmation(client.current.captureSync(preview, syncReason)); setSyncConfirmed(false); setFormError(''); }
    catch { setFormError('Bitte aktuelle Abgleichvorschau, Wartezeit und Begründung mit 10 bis 500 Zeichen prüfen.'); }
  };
  const executeSync = () => {
    if (!syncConfirmation || !syncConfirmed || busy) return;
    const captured = syncConfirmation; setSyncIntent(captured);
    void run(current => current.sync(captured), value => { setSyncReceipt(value); setSyncIntent(null); setSyncConfirmation(null); setSyncConfirmed(false); setPreview(null); setNeedsReload(true); });
  };
  const blocked = busy || needsReload || !!confirmation || !!intent || !!syncConfirmation || !!syncIntent;
  const selectedUser = users?.users.find(row => row.id === userId);
  return <details className="od-panel text-sm">
    <summary>Microsoft 365 · Verknüpfungen dieses Lizenzpools</summary>
    <section aria-label="Microsoft-Verknüpfungen" className="mt-3 space-y-4">
      <p>Den Firmenpool einem Microsoft-Produkt und die eigenen Mitarbeitenden ihren Microsoft-Konten zuordnen. Eine Verknüpfung allein weist noch keine Cloud-Lizenz zu.</p>
      <button className="fluent-btn-secondary" disabled={busy || !!confirmation || !!syncConfirmation} onClick={reload}>Microsoft-Verknüpfungen laden</button>
      {busy && <p role="status">Microsoft-Vorgang wird geprüft …</p>}{error && <p role="alert">{error}</p>}{formError && <p role="alert">{formError}</p>}
      {state?.state === 'not_configured' && <p role="status">Für diese Firma ist noch keine freigegebene Microsoft-Verbindung mit getrenntem Lese- und Schreibzugang eingerichtet.</p>}
      {state?.state === 'configuration_unavailable' && <p role="status">Die Microsoft-Zugangskonfiguration ist nicht verfügbar. Gespeicherte Verknüpfungen und das Protokoll können weiterhin geprüft werden.</p>}
      {state && !['not_configured', 'configuration_unavailable'].includes(state.state) && <>
        <p className="break-all">Microsoft-Verzeichnis: {state.connection?.microsoftTenantId || state.microsoftTenantId}</p>
        {state.connection && state.connection.microsoftTenantId !== state.microsoftTenantId && <p className="break-all">Neu konfiguriertes Verzeichnis: {state.microsoftTenantId}. Zuerst die alten Verknüpfungen entfernen und die bisherige Verbindung trennen.</p>}
        <details><summary>Geprüfte Microsoft-Anwendungen</summary><p className="break-all">Bestand lesen: {state.readClientId}</p><p className="break-all">Lizenzen verwalten: {state.writeClientId}</p></details>
        {state.state === 'review_required' && <p role="status">Die Verbindungskonfiguration hat sich geändert. Vor weiterer Nutzung neu prüfen und bestätigen.</p>}
      </>}
      {state && (!['not_configured', 'configuration_unavailable'].includes(state.state) || state.connection) && <label>Begründung der Microsoft-Verknüpfung<input className={inputClass} value={reason} minLength={10} maxLength={500} disabled={blocked} onChange={event => setReason(event.target.value)} /></label>}
      {state?.state === 'configured' && <button className="fluent-btn-primary" disabled={blocked || reason.trim().length < 10} onClick={() => prepare(current => current.connect(state, reason))}>Microsoft-Verbindung bestätigen</button>}
      {state && ['connected', 'review_required'].includes(state.state) && state.connection?.microsoftTenantId === state.microsoftTenantId && <button className="fluent-btn-secondary" disabled={blocked || reason.trim().length < 10} onClick={() => prepare(current => current.connect(state, reason, true))}>Microsoft-Verbindung neu prüfen</button>}
      {state && mappings?.pool && <section aria-label="Microsoft-Produktverknüpfung" className="space-y-3"><h4 className="font-semibold">Produkt für {pool.name}</h4><p className="break-all">Microsoft-SKU: {mappings.pool.skuId}</p><button className="fluent-btn-secondary" disabled={blocked || reason.trim().length < 10} onClick={() => prepare(current => current.retire(state, 'pool', mappings.pool, reason))}>Produktverknüpfung entfernen</button></section>}
      {state?.state === 'connected' && <>
        {!mappings?.pool && <section aria-label="Microsoft-Produktverknüpfung" className="space-y-3">
          <h4 className="font-semibold">Produkt für {pool.name}</h4>
          <button className="fluent-btn-secondary" disabled={blocked} onClick={() => { setProducts(null); setSkuId(''); void run(current => current.products(), setProducts); }}>Microsoft-Produkte laden</button>
              {products && <><label>Microsoft-Produkt auswählen<select className={inputClass} disabled={blocked} value={skuId} onChange={event => setSkuId(event.target.value)}><option value="">Produkt wählen …</option>{products.products.filter(row => row.appliesTo === 'User' && row.capabilityStatus === 'Enabled' && row.prepaidUnits.enabled > 0).map(row => <option key={row.skuId} value={row.skuId}>{row.skuPartNumber} · {row.prepaidUnits.enabled} aktive Einheiten · {row.consumedUnits} verbraucht</option>)}</select></label>
                {!products.products.some(row => row.appliesTo === 'User' && row.capabilityStatus === 'Enabled' && row.prepaidUnits.enabled > 0) && <p>Keine aktiven Benutzerprodukte verfügbar.</p>}
                <button className="fluent-btn-primary" disabled={blocked || !skuId || reason.trim().length < 10} onClick={() => prepare(current => current.bindPool(state, products, pool.id, skuId, reason))}>Microsoft-Produkt verknüpfen</button></>}
        </section>}
        <section aria-label="Microsoft-Benutzerverknüpfung" className="space-y-3">
          <h4 className="font-semibold">Microsoft-Konto zuordnen</h4>
          <form className="flex flex-wrap items-end gap-3" onSubmit={event => { event.preventDefault(); setUserId(''); setObjectId(''); void run(current => current.users(1, search), value => { setUsers(value); setUsersLoaded(true); }); }}>
            <label>Firmenbenutzer suchen<input className={inputClass} maxLength={100} disabled={blocked} value={search} onChange={event => setSearch(event.target.value)} /></label><button className="fluent-btn-secondary" disabled={blocked}>Firmenbenutzer suchen</button>
          </form>
          {usersLoaded && (users ? <><label>Firmenbenutzer auswählen<select className={inputClass} disabled={blocked} value={userId} onChange={event => { setUserId(event.target.value); setObjectId(''); }}><option value="">Mitarbeiter wählen …</option>{users.users.map(row => <option key={row.id} value={row.id}>{userName(row)} · {row.username}</option>)}</select></label>
            <nav aria-label="Microsoft-Firmenbenutzerseiten" className="flex gap-4"><button disabled={blocked || users.page <= 1} onClick={() => { setUserId(''); setObjectId(''); void run(current => current.users(users.page - 1, search), setUsers); }}>Zurück</button><span>Seite {users.page} · {users.total} Mitarbeiter</span><button disabled={blocked || users.page * 25 >= users.total} onClick={() => { setUserId(''); setObjectId(''); void run(current => current.users(users.page + 1, search), setUsers); }}>Weiter</button></nav></>
            : <label>Bekannte Firmenbenutzer-ID<input className={inputClass} maxLength={36} disabled={blocked} value={userId} onChange={event => { setUserId(event.target.value); setObjectId(''); }} /><span>Keine Profil-Leseberechtigung. Der Server prüft die eigene Firmenzugehörigkeit.</span></label>)}
          {userId && <><p>{selectedUser ? userName(selectedUser) : userId}</p><label>Microsoft-Benutzer-ID<input className={inputClass} maxLength={36} disabled={blocked} value={objectId} onChange={event => setObjectId(event.target.value)} /><span>Die Objekt-ID des zugehörigen Kontos aus dem oben angezeigten Microsoft-Verzeichnis.</span></label>
            <button className="fluent-btn-primary" disabled={blocked || !objectId || reason.trim().length < 10} onClick={() => prepare(current => current.bindUser(state, userId, objectId.trim(), reason))}>Microsoft-Benutzer verknüpfen</button></>}
        </section>
      </>}
      {state?.connection && mappings && <section aria-label="Gespeicherte Microsoft-Benutzerverknüpfungen" className="space-y-3">
        <h4 className="font-semibold">Gespeicherte Kontozuordnungen</h4>{!mappings.users.length && <p>Keine Benutzerverknüpfungen auf dieser Seite.</p>}
        <ul className="space-y-3">{mappings.users.map(row => <li key={row.id} className="rounded border border-[var(--border)] p-3 space-y-2"><p className="break-all">Firmenbenutzer {row.userId}</p><p className="break-all">Microsoft-Konto {row.objectId}</p><div className="flex flex-wrap gap-3">
          {state.state === 'connected' && mappings.pool && <button className="fluent-btn-secondary" disabled={blocked} onClick={() => { setPreview(null); setSyncReason(''); setSyncReceipt(null); void run(current => current.preview(pool.id, row.userId), setPreview); }}>Microsoft-Lizenzabgleich prüfen</button>}
          <button className="fluent-btn-secondary" disabled={blocked || reason.trim().length < 10} onClick={() => prepare(current => current.retire(state, 'user', row, reason))}>Benutzerverknüpfung entfernen</button></div></li>)}</ul>
        <nav aria-label="Microsoft-Verknüpfungsseiten" className="flex gap-4"><button disabled={blocked || mappings.page <= 1} onClick={() => void run(current => current.mappings(pool.id, mappings.page - 1), setMappings)}>Zurück</button><span>Seite {mappings.page}</span><button disabled={blocked || !mappings.hasMore} onClick={() => void run(current => current.mappings(pool.id, mappings.page + 1), setMappings)}>Weiter</button></nav>
      </section>}
      {preview && <section aria-label="Microsoft-Lizenzabgleich-Vorschau" className="rounded border border-[var(--border)] p-3 space-y-3">
        <h4 className="font-semibold">{previewLabels[preview.action]}</h4><p className="break-all">Firmenbenutzer {preview.userId} · Microsoft-Konto {preview.user.objectId}</p>
        <p>Lokaler Anspruch: {preview.local.desired ? 'vorhanden' : 'nicht vorhanden'} · {preview.local.raw.origins.length} gespeicherte Quellen.</p>
        <p>Microsoft: {preview.remote.direct ? preview.remote.active ? 'aktive direkte Lizenz beobachtet' : 'direkte Lizenz nicht als aktiv bestätigt' : preview.remote.inherited ? 'Gruppenlizenz beobachtet' : preview.remote.present ? 'Zuweisung noch nicht eindeutig' : 'keine Lizenz beobachtet'}{preview.remote.inherited && preview.remote.direct ? ' und zusätzliche Gruppenlizenz' : ''} · Konto {preview.remote.accountEnabled ? 'aktiv' : 'gesperrt'}.</p>
        {preview.stock && <p>Microsoft-Bestand: {preview.stock.prepaidUnits.enabled} aktive Einheiten · {preview.stock.consumedUnits} verbraucht · {stockStatusLabels[preview.stock.capabilityStatus]}.</p>}
        {preview.local.desired && !preview.remote.present && preview.action === 'conflict' && <p>Microsoft bestätigt derzeit keinen passenden verfügbaren Benutzer-Lizenzbestand für eine neue Zuweisung.</p>}
        <p>{preview.target?.owned ? 'Der Verwaltungsnachweis gehört zu OpenDirectory.' : 'Keine bestehende Microsoft-Zuweisung als eigene übernommen.'} Noch keine Cloud-Änderung ausgelöst.</p>
        {preview.local.groups.length > 0 && <ul>{preview.local.groups.map(row => <li key={row.ruleId}>Gruppe {row.groupId} · {row.active ? 'aktuelle berechtigte Mitgliedschaft' : 'keine aktuelle berechtigte Mitgliedschaft'}</li>)}</ul>}
        <p>Geprüft am {new Date(preview.checkedAt).toLocaleString('de-CH')}.</p>
        {preview.target?.retryAt && Date.parse(preview.target.retryAt) > Date.now() && <p>Microsoft-Wartezeit bis {new Date(preview.target.retryAt).toLocaleString('de-CH')}. Danach die Vorschau neu prüfen.</p>}
        {preview.action !== 'recover' && <><label>Begründung des Microsoft-Lizenzabgleichs<input className={inputClass} value={syncReason} maxLength={500} disabled={blocked} onChange={event => setSyncReason(event.target.value)} /></label>
          <button className="fluent-btn-primary" disabled={blocked || syncReason.trim().length < 10 || !!preview.target?.retryAt && Date.parse(preview.target.retryAt) > Date.now()} onClick={beginSync}>Microsoft-Lizenzabgleich vorbereiten</button></>}
      </section>}
      {syncReceipt && <section aria-label="Microsoft-Lizenzabgleich-Ergebnis" className="rounded border border-[var(--border)] p-3 space-y-3"><h4 className="font-semibold">{resultLabels[syncReceipt.result.status]}</h4>
        <p>{syncReceipt.result.kind === 'acknowledged' ? 'Microsoft hat die Anfrage angenommen. Die tatsächliche Wirkung muss in einem neuen Abgleich separat bestätigt werden.' : syncReceipt.result.kind === 'unknown' ? 'Keine automatische Wiederholung oder Übernahme einer Lizenz. Den ursprünglichen Vorgang prüfen.' : 'Der erfasste Stand ist protokolliert. Für weitere Aktionen den aktuellen Stand neu laden.'}</p>
        <p className="break-all">Vorgang {syncReceipt.result.operationId} · Benutzer {syncReceipt.result.userId}{syncReceipt.historical ? ' · historischer Originalnachweis' : ''}</p>
        {syncReceipt.result.retryAt && <p>Im ursprünglichen Versuch gemeldete Wartezeit bis {new Date(syncReceipt.result.retryAt).toLocaleString('de-CH')}.</p>}
        {syncReceipt.result.errorCode && <details><summary>Hinweis zum Anbieterstatus</summary><p>{syncReceipt.result.errorCode}</p></details>}
      </section>}
      {syncIntent && !busy && <aside aria-label="Unbestätigter Microsoft-Lizenzabgleich" className="space-y-3"><p>Das Ergebnis könnte bereits gespeichert sein. Nur den ursprünglichen Vorgang ausdrücklich wiederaufnehmen; er wird nicht automatisch erneut versendet.</p><p className="break-all">Vorgang {syncIntent.operationId}</p>
        <button className="fluent-btn-secondary" disabled={busy || !client.current?.canRetry(syncIntent)} onClick={() => { setSyncConfirmation(syncIntent); setSyncConfirmed(false); }}>Ursprünglichen Lizenzabgleich wiederaufnehmen</button></aside>}
      {state?.connection && <button className="fluent-btn-secondary" disabled={blocked || reason.trim().length < 10} onClick={() => prepare(current => current.retire(state, 'connection', state.connection, reason))}>Microsoft-Verbindung trennen</button>}
      {receipt && <p role="status">{actionLabels[receipt.action]} · {receipt.historical ? 'Ursprünglicher Vorgang bereits gespeichert' : 'Vorgang gespeichert'} · {receipt.operationId}. Aktuellen Stand neu laden.</p>}
      {intent && <aside aria-label="Unbestätigte Microsoft-Verknüpfung" className="space-y-3"><p>Die Verknüpfung könnte bereits gespeichert sein. Den ursprünglichen Versuch ausdrücklich prüfen oder den aktuellen Stand neu laden.</p><p className="break-all">Vorgang {intent.operationId}</p><button className="fluent-btn-secondary" disabled={busy || !client.current?.canRetry(intent)} onClick={() => { setConfirmation(intent); setConfirmed(false); }}>Ursprüngliche Microsoft-Verknüpfung prüfen</button></aside>}
      {history && (history.events.length > 0 || state?.connection) && <details><summary>Protokoll der Microsoft-Verknüpfungen</summary><ul className="space-y-3 mt-3">{history.events.map(row => <li key={row.id}><p>{new Date(row.createdAt).toLocaleString('de-CH')} · {eventLabels[row.type]}</p><p>{row.reason}</p><p className="break-all">{row.actorKind === 'human' ? 'Benutzer ' + row.actorUserId : 'Dienst für den ursprünglichen Vorgang'} · Vorgang {row.operationId}</p></li>)}</ul>
        <nav aria-label="Microsoft-Protokollseiten" className="flex gap-4"><button disabled={blocked || history.page <= 1} onClick={() => void run(current => current.history(history.page - 1), setHistory)}>Zurück</button><span>Seite {history.page}</span><button disabled={blocked || !history.hasMore} onClick={() => void run(current => current.history(history.page + 1), setHistory)}>Weiter</button></nav></details>}
    </section>
    {confirmation && <DirectoryConfirmation title={actionLabels[confirmation.action]} busy={busy} error={confirmed ? '' : 'Bitte genau diesen Vorgang bestätigen.'} onClose={() => { setConfirmation(null); setConfirmed(false); }} onConfirm={write}>
      <p>{pool.name} · Microsoft-Verzeichnis {confirmation.action === 'disconnect' ? state?.connection?.microsoftTenantId : state?.microsoftTenantId || state?.connection?.microsoftTenantId}</p><p>{String(confirmation.body.reason)}</p>
      {confirmation.action.startsWith('retire_') && <p className="break-all">{confirmation.kind === 'user' ? 'Firmenbenutzer' : 'Firmenpool'} {confirmation.targetId} · Verknüpfung {confirmation.expectedId}</p>}
      {confirmation.action === 'bind_pool' && <p className="break-all">Microsoft-SKU {String(confirmation.body.skuId)} · alle Servicepläne aktiviert.</p>}
      {confirmation.action === 'bind_user' && <p className="break-all">Firmenbenutzer {confirmation.targetId} · Microsoft-Konto {String(confirmation.body.objectId)}</p>}
      {['bind_pool', 'bind_user'].includes(confirmation.action) && <p>Die verknüpfte direkte Microsoft-Lizenz soll ausschließlich über OpenDirectory verwaltet werden. Bestehende fremde oder gruppenbasierte Zuweisungen werden nicht übernommen.</p>}
      <p>Nur die Verknüpfung wird gespeichert. Noch keine Microsoft-Lizenzänderung.</p>
      <label className="flex gap-3 mt-3"><input type="checkbox" checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)} />Ich bestätige diese Microsoft-Verknüpfung.</label>
    </DirectoryConfirmation>}
    {syncConfirmation && <DirectoryConfirmation title="Microsoft-Lizenzabgleich bestätigen" busy={busy} error={syncConfirmed ? '' : 'Bitte genau diesen Lizenzabgleich bestätigen.'} onClose={() => { setSyncConfirmation(null); setSyncConfirmed(false); }} onConfirm={executeSync}>
      <p>{previewLabels[syncConfirmation.action]} · {pool.name}</p><p className="break-all">Firmenbenutzer {syncConfirmation.userId} · Vorgang {syncConfirmation.operationId}</p><p>{syncConfirmation.body.reason}</p>
      <p>{['assign', 'remove'].includes(syncConfirmation.action) ? 'Dieser bestätigte Vorgang kann die verknüpfte Microsoft-Lizenz ändern. Eine angenommene Anfrage ist noch keine bestätigte Wirkung.' : 'Dieser Vorgang prüft und protokolliert den beobachteten Stand. Er übernimmt oder wiederholt keinen ungeklärten Schreibversuch.'}</p>
      <label className="flex gap-3 mt-3"><input type="checkbox" checked={syncConfirmed} disabled={busy} onChange={event => setSyncConfirmed(event.target.checked)} />Ich bestätige diesen Microsoft-Lizenzabgleich.</label>
    </DirectoryConfirmation>}
  </details>;
}
