'use client';

import React, { useEffect, useRef, useState } from 'react';
import { ViewShell } from '@/components/ui/ViewShell';
import { DataTable } from '@/components/ui/DataTable';
import { CompanyApplicationsClient, CompanyPoolPage } from '@/lib/companyApplications';
import {
  CompanyBlueprintsClient, CompanyBlueprintAccess, CompanyBlueprintDraft, CompanyBlueprintDetail, CompanyBlueprintSummary,
  CompanyBlueprintPage, CompanyBlueprintVersion, CompanyBlueprintVersionDetail, CompanyBlueprintEvent, CompanyBlueprintIntent,
  CompanyBlueprintReceipt, CompanyBlueprintConfigType, companyBlueprintId, companyBlueprintsError, companyBlueprintsUnsafe,
} from '@/lib/companyBlueprints';
import { DirectoryConfirmation } from './UserDetailPanel';
import CompanyBlueprintUserAssignmentsPanel from './CompanyBlueprintUserAssignmentsPanel';

const labels = { screen_lock: 'Bildschirmsperre', filevault: 'FileVault', software_update: 'Software-Updates' };
const actions = { created: 'Blueprint erstellen', updated: 'Entwurf speichern', published: 'Version lokal freigeben', restored: 'Als Entwurf wiederherstellen' };
const eventLabels = { 'blueprint.created': 'Blueprint erstellt', 'blueprint.draft.updated': 'Entwurf aktualisiert', 'blueprint.published': 'Version lokal freigegeben', 'blueprint.draft.restored': 'Version als Entwurf wiederhergestellt' };
const defaults = { screen_lock: { minutes: 5, requirePassword: true }, filevault: { enabled: true }, software_update: { automatic: true, deferralDays: 0 } };
const emptyDraft = (): CompanyBlueprintDraft => ({ name: '', description: '', platform: 'all', configurations: [], appPoolIds: [] });
const inputClass = 'mt-1 w-full rounded border border-white/20 bg-transparent p-2';
function Pages({ page, total, label, disabled, onPage }: { page: number; total: number; label: string; disabled: boolean; onPage: (page: number) => void }) {
  return <nav aria-label={label} className="flex flex-wrap items-center gap-4 py-3 text-sm">
    <button className="fluent-btn-secondary" aria-label={'Vorherige ' + label} disabled={disabled || page <= 1} onClick={() => onPage(page - 1)}>Zurück</button>
    <span>Seite {page} · {total} Einträge</span>
    <button className="fluent-btn-secondary" aria-label={'Nächste ' + label} disabled={disabled || page >= 1000000 || page * 25 >= total} onClick={() => onPage(page + 1)}>Weiter</button>
  </nav>;
}
function DraftContent({ draft }: { draft: CompanyBlueprintDraft }) {
  return <div className="space-y-3"><p>{draft.name} · {draft.platform}</p><p>{draft.description || 'Keine Beschreibung'}</p>
    <ul className="space-y-2">{draft.configurations.map(config => <li key={config.id}>
      <p>{config.name} · {labels[config.type]}</p><details><summary>Gespeichertes Profil anzeigen</summary><pre className="whitespace-pre-wrap break-all p-2 text-sm">{config.payloadJson}</pre><p className="break-all text-xs">{config.id}</p></details>
    </li>)}</ul><p>{draft.configurations.length} Konfigurationen · {draft.appPoolIds.length} gewünschte App-Pools</p>
  </div>;
}

export default function CompanyBlueprintsView() {
  const client = useRef<CompanyBlueprintsClient | null>(null); const appClient = useRef<CompanyApplicationsClient | null>(null);
  const generation = useRef(0); const running = useRef(false);
  const [access, setAccess] = useState<CompanyBlueprintAccess | null>(null);
  const [list, setList] = useState<CompanyBlueprintPage<CompanyBlueprintSummary> | null>(null);
  const [search, setSearch] = useState(''); const [searchDraft, setSearchDraft] = useState('');
  const [detail, setDetail] = useState<CompanyBlueprintDetail | null>(null);
  const [versions, setVersions] = useState<CompanyBlueprintPage<CompanyBlueprintVersion> | null>(null);
  const [version, setVersion] = useState<CompanyBlueprintVersionDetail | null>(null);
  const [history, setHistory] = useState<CompanyBlueprintPage<CompanyBlueprintEvent> | null>(null);
  const [draft, setDraft] = useState<CompanyBlueprintDraft | null>(null); const [reason, setReason] = useState('');
  const [configChoice, setConfigChoice] = useState<CompanyBlueprintConfigType>('screen_lock');
  const [apps, setApps] = useState<CompanyPoolPage | null>(null); const [appError, setAppError] = useState('');
  const [appSearch, setAppSearch] = useState(''); const [appQuery, setAppQuery] = useState('');
  const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [formError, setFormError] = useState('');
  const [needsReload, setNeedsReload] = useState(false); const [confirmation, setConfirmation] = useState<CompanyBlueprintIntent | null>(null);
  const [confirmed, setConfirmed] = useState(false); const [attempt, setAttempt] = useState<CompanyBlueprintIntent | null>(null);
  const [receipt, setReceipt] = useState<CompanyBlueprintReceipt | null>(null);

  const clearDetail = () => {
    setDetail(null); setVersions(null); setVersion(null); setHistory(null); setDraft(null); setReason(''); setApps(null);
    setAppError(''); setAppSearch(''); setAppQuery(''); setFormError(''); setConfirmation(null); setConfirmed(false); setAttempt(null); setReceipt(null);
  };
  const fail = (failure: unknown) => {
    setError(companyBlueprintsError(failure)); setConfirmation(null); setConfirmed(false); setNeedsReload(true);
    if (companyBlueprintsUnsafe(failure)) {
      generation.current++; client.current?.invalidate(); appClient.current?.dispose(); appClient.current = null;
      running.current = false; setBusy(false); setAccess(null); setList(null); clearDetail();
    } else if ([400, 404, 409, 412].includes((failure as { response?: { status?: number } })?.response?.status)) setAttempt(null);
  };
  const run = async <Value,>(operation: () => Promise<Value>, apply: (value: Value) => void) => {
    if (running.current) return;
    const expected = generation.current; running.current = true; setBusy(true); setError(''); setFormError('');
    try { const result = await operation(); if (expected === generation.current) apply(result); }
    catch (failure) { if (expected === generation.current) fail(failure); }
    finally { if (expected === generation.current) { running.current = false; setBusy(false); } }
  };
  const reload = () => {
    generation.current++; client.current?.dispose(); appClient.current?.dispose(); appClient.current = null;
    const current = new CompanyBlueprintsClient(); client.current = current; running.current = false;
    setAccess(null); setList(null); clearDetail(); setSearch(''); setSearchDraft(''); setNeedsReload(false); setError('');
    void run(async () => ({ access: await current.access(), list: await current.list() }), result => { setAccess(result.access); setList(result.list); });
  };
  useEffect(() => {
    reload();
    const sessionError = () => {
      generation.current++; client.current?.invalidate(); appClient.current?.dispose(); appClient.current = null;
      running.current = false; setBusy(false); setAccess(null); setList(null); clearDetail(); setSearch(''); setSearchDraft('');
      setNeedsReload(true); setError(companyBlueprintsError({ response: { status: 401 } }));
    };
    window.addEventListener('od:session-error', sessionError);
    return () => { generation.current++; client.current?.dispose(); appClient.current?.dispose(); running.current = false; window.removeEventListener('od:session-error', sessionError); };
  }, []);

  const loadList = (page: number, query = search) => {
    if (busy || attempt) return;
    clearDetail(); setList(null); setSearch(query);
    void run(() => client.current.list(page, query), result => { setList(result); setNeedsReload(false); });
  };
  const select = (id: string) => {
    if (busy || attempt || needsReload) return;
    clearDetail();
    void run(async () => ({ detail: await client.current.get(id), versions: await client.current.versions(id), history: await client.current.history(id) }), result => {
      setDetail(result.detail); setVersions(result.versions); setHistory(result.history);
    });
  };
  const begin = (action: CompanyBlueprintReceipt['action']) => {
    if (busy || needsReload || attempt || !access) return;
    try {
      const intent = client.current.capture(action, action === 'created' ? null : detail, reason,
        action === 'restored' ? version?.version : draft || undefined);
      setConfirmation(intent); setConfirmed(false); setFormError('');
    } catch { setFormError('Bitte gültige Felder, eindeutige App-Pools und eine Begründung mit 10 bis 500 Zeichen ohne Steuerzeichen angeben. Konflikte müssen vor einer Freigabe bearbeitet werden.'); }
  };
  const confirm = () => {
    if (busy || !confirmation || !confirmed) return;
    const intent = confirmation; setAttempt(intent); setReceipt(null);
    void run(() => client.current.write(intent), result => {
      setReceipt(result); setAttempt(null); setConfirmation(null); setConfirmed(false); setDraft(null); setDetail(null);
      setVersions(null); setVersion(null); setHistory(null); setApps(null); setReason(''); setList(null); setNeedsReload(true);
    });
  };
  const loadApps = (page = 1, query = appQuery) => {
    if (busy || !access || !draft || attempt || needsReload) return;
    const context = access; const expected = generation.current; setAppError(''); setApps(null); setAppQuery(query);
    if (!appClient.current) appClient.current = new CompanyApplicationsClient();
    const current = appClient.current;
    void run(async () => {
      try {
        const authority = await current.reload();
        if (authority.actorUserId !== context.actorUserId || authority.tenantId !== context.tenantId) throw { blueprintSessionChanged: true };
        if (!authority.permissions.includes('company.apps.read')) throw new Error();
        return await current.list(page, query);
      } catch (failure) {
        if (failure?.blueprintSessionChanged) throw { response: { status: 401 } };
        if (expected === generation.current) { current.invalidate(); setAppError('App-Auswahl nicht verfügbar: unabhängige Firmen-App-Berechtigung und aktuelle Anmeldung erforderlich. Bestehende Referenzen bleiben unverändert.'); }
        return null;
      }
    }, result => setApps(result));
  };
  const changeConfig = (id: string, update: Partial<CompanyBlueprintDraft['configurations'][number]>) => {
    setDraft(current => ({ ...current, configurations: current.configurations.map(config => config.id === id ? { ...config, ...update } : config) }));
  };
  const editPayload = (id: string, field: string, value: number | boolean) => {
    const config = draft.configurations.find(candidate => candidate.id === id);
    changeConfig(id, { payloadJson: JSON.stringify({ ...JSON.parse(config.payloadJson), [field]: value }) });
  };
  const blocked = busy || !!confirmation || !!attempt || needsReload;
  const acknowledged = receipt && access && receipt.actorUserId === access.actorUserId && receipt.tenantId === access.tenantId;

  return <ViewShell title="Firmen-Blueprints" subtitle="Eigene Konfigurationsentwürfe und unveränderliche lokale Versionen."
    primaryAction={access && list && !needsReload ? { label: 'Blueprint erstellen', disabled: blocked, onClick: () => { clearDetail(); setDraft(emptyDraft()); } } : undefined}
    actions={[{ label: 'Aktuellen Stand laden', onClick: reload, disabled: busy || !!confirmation || !!attempt }]}>
    <div className="space-y-5 min-w-0" style={{ color: 'var(--text-primary)' }}>
      <p className="rounded-lg border border-white/10 p-4 text-sm">Lokale Planung für die eigene Firma. Keine Gerätezuweisung, Installation, Lizenzreservierung oder MDM-Freigabe durch Entwurf oder Freigabe. Eine lokal freigegebene Version ist ein unveränderlicher Plan, keine Bestätigung einer wirksamen Gerätekonfiguration. Erst eine separat bestätigte Mitarbeiterzuweisung belegt echte lokale App-Lizenzen.</p>
      {error && <p role="alert" className="rounded border border-red-500/40 p-4">{error}</p>}
      {!access && !error && <p role="status">Aktuelle Firmenberechtigung und zusätzliche Anmeldung werden geprüft …</p>}
      {acknowledged && <section aria-label="Bestätigter Änderungsnachweis" className="rounded-lg border border-green-500/30 p-4 space-y-2">
        <h2 className="font-semibold">{actions[receipt.action]} bestätigt</h2>
        <p>{receipt.outcome === 'already_applied' ? 'Ursprünglicher Versuch bereits gespeichert.' : 'Änderung gespeichert.'} Historischer Nachweis für Revision {receipt.revision}; kein Nachweis des aktuellen Stands.</p>
        <p>{receipt.publishedVersion === null ? 'Keine lokal freigegebene Version in diesem Nachweis.' : `Lokal freigegebene Version in diesem Nachweis: ${receipt.publishedVersion}.`} Ereigniszustellung: ausstehend.</p>
        <details><summary>Nachweis anzeigen</summary><p className="break-all">Blueprint: {receipt.blueprintId}</p><p className="break-all">Vorgang: {receipt.operationId}</p></details>
        <button className="fluent-btn-primary" disabled={busy} onClick={reload}>Aktuellen Blueprint-Stand neu laden</button>
      </section>}
      {attempt && <section aria-label="Unbestätigter Änderungsversuch" className="rounded-lg border border-amber-500/40 p-4 space-y-3">
        <h2 className="font-semibold">Ursprünglichen Versuch prüfen</h2><p>Die Änderung könnte bereits gespeichert sein. Keine neue Version und kein neuer Vorgang werden automatisch erzeugt.</p>
        <p className="break-all">Vorgang: {attempt.operationId}</p><p>{actions[attempt.action]} · ursprünglicher Versionsnachweis: {attempt.etag || 'Neuer Blueprint'}</p>
        <button className="fluent-btn-secondary" disabled={busy || !client.current?.canRetry(attempt)} onClick={() => { setConfirmation(attempt); setConfirmed(false); }}>Ursprünglichen Versuch wiederaufnehmen</button>
        <button className="fluent-btn-secondary ml-3" disabled={busy} onClick={reload}>Versuch verwerfen und aktuellen Stand laden</button>
      </section>}
      {access && list && <section aria-label="Blueprint-Katalog" className="space-y-3">
        <form className="flex flex-wrap gap-3 items-end" onSubmit={event => { event.preventDefault(); loadList(1, searchDraft.trim()); }}>
          <div><label htmlFor="company-blueprints-search">Blueprint suchen</label><input id="company-blueprints-search" className={inputClass} value={searchDraft} maxLength={100} disabled={blocked} onChange={event => setSearchDraft(event.target.value)} /></div>
          <button className="fluent-btn-secondary" disabled={blocked}>Suchen</button>
        </form>
        <DataTable rows={list.rows} getRowId={row => row.id} emptyMessage="Noch keine Firmen-Blueprints vorhanden."
          columns={[{ key: 'name', header: 'Blueprint', render: row => <button className="text-blue-400 underline text-left" disabled={blocked} onClick={() => select(row.id)}>{row.name}</button> },
            { key: 'platform', header: 'Plattform' }, { key: 'revision', header: 'Revision' },
            { key: 'publishedVersion', header: 'Lokale Version', render: row => row.publishedVersion === null ? 'Noch nicht freigegeben' : `Version ${row.publishedVersion}` },
            { key: 'draftChanged', header: 'Entwurf', render: row => row.draftChanged ? 'Nicht freigegebene Änderungen' : 'Entspricht lokaler Version' },
            { key: 'configurationCount', header: 'Konfigurationen' }, { key: 'appCount', header: 'Gewünschte Apps' }]} />
        <Pages page={list.page} total={list.total} label="Blueprint-Seiten" disabled={blocked} onPage={loadList} />
      </section>}
      {detail && access && <section aria-label="Blueprint-Details" className="rounded-lg border border-white/10 p-5 space-y-4">
        <div className="flex flex-wrap justify-between gap-4"><div><h2 className="text-lg font-semibold">{detail.draft.name}</h2><p>Revision {detail.revision} · {detail.publishedVersion === null ? 'Noch keine lokale Freigabe' : `Lokale Version ${detail.publishedVersion}`} · {detail.draftChanged ? 'Entwurf geändert' : 'Entwurf entspricht lokaler Version'}</p></div>
          <button className="fluent-btn-secondary" onClick={reload}>Details schliessen</button></div>
        <DraftContent draft={detail.draft} />
        <section aria-label="Konfliktprüfung des Entwurfs" className="rounded border border-white/10 p-3 space-y-2">
          <h3 className="font-semibold">Konfliktprüfung</h3>
          <p>{detail.preview.hasConflicts ? 'Konflikte vorhanden – keine lokale Freigabe möglich.' : 'Keine Konflikte innerhalb dieses Entwurfs.'} Keine Prüfung weiterer Blueprints oder tatsächlicher Geräte.</p>
          {!detail.draft.configurations.length && !detail.draft.appPoolIds.length && <p>Leere Entwürfe können gespeichert werden. Eine lokale Freigabe benötigt mindestens eine Konfiguration oder eine gewünschte Firmen-App.</p>}
          {detail.preview.effectiveConfigurations.map(config => <details key={config.configType}><summary>{labels[config.configType]}: {config.sources.length} übereinstimmende Quellen</summary><pre className="whitespace-pre-wrap break-all text-sm">{config.payloadJson}</pre><ul>{config.sources.map(source => <li className="break-all text-xs" key={source.configurationId}>{source.blueprintId} · {source.configurationId}</li>)}</ul></details>)}
          {detail.preview.conflicts.map(conflict => <div key={conflict.configType}><h4>{labels[conflict.configType]}: {conflict.variants.length} widersprüchliche Profile</h4>
            {conflict.variants.map((variant, index) => <details key={index}><summary>Konfliktprofil {index + 1}</summary><pre className="whitespace-pre-wrap break-all">{variant.payloadJson}</pre><ul>{variant.sources.map(source => <li className="break-all text-xs" key={source.configurationId}>{source.blueprintId} · {source.configurationId}</li>)}</ul></details>)}
          </div>)}
        </section>
        <div className="flex flex-wrap gap-3"><button className="fluent-btn-secondary" disabled={blocked || !!draft} onClick={() => { setDraft(JSON.parse(JSON.stringify(detail.draft))); setReason(''); setFormError(''); setApps(null); }}>Entwurf bearbeiten</button>
          <button className="fluent-btn-primary" disabled={blocked || !!draft || detail.preview.hasConflicts || !detail.draftChanged || !detail.draft.configurations.length && !detail.draft.appPoolIds.length} onClick={() => begin('published')}>Version lokal freigeben</button></div>
      </section>}
      {draft && access && <section aria-label="Blueprint-Editor" className="rounded-lg border border-white/10 p-5 space-y-5">
        <h2 className="text-lg font-semibold">{detail ? 'Entwurf bearbeiten' : 'Neuer Firmen-Blueprint'}</h2>
        <fieldset disabled={blocked} className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2"><div><label htmlFor="company-blueprint-name">Blueprint-Name</label><input id="company-blueprint-name" className={inputClass} maxLength={160} value={draft.name} onChange={event => setDraft({ ...draft, name: event.target.value })} /></div>
            <div><label htmlFor="company-blueprint-platform">Blueprint-Plattform</label><select id="company-blueprint-platform" className={inputClass} value={draft.platform} onChange={event => setDraft({ ...draft, platform: event.target.value as CompanyBlueprintDraft['platform'] })}>
              <option value="all">Alle Plattformen</option><option value="windows">Windows</option><option value="macos">macOS</option><option value="linux">Linux</option>
            </select></div></div>
          <div><label htmlFor="company-blueprint-description">Beschreibung</label><input id="company-blueprint-description" className={inputClass} maxLength={2000} value={draft.description} onChange={event => setDraft({ ...draft, description: event.target.value })} /></div>
          <h3 className="font-semibold">Konfigurationen · {draft.configurations.length} / 25</h3>
          {draft.configurations.map((config, index) => {
            const payload = JSON.parse(config.payloadJson) as Record<string, number | boolean>;
            return <fieldset className="rounded border border-white/20 p-4 space-y-3" key={config.id}>
              <legend className="px-2">Konfiguration {index + 1} · {labels[config.type]}</legend>
              <div><label htmlFor={'config-name-' + config.id}>Konfigurationsname {index + 1}</label><input id={'config-name-' + config.id} className={inputClass} maxLength={160} value={config.name} onChange={event => changeConfig(config.id, { name: event.target.value })} /></div>
              {config.type === 'screen_lock' && <><div><label htmlFor={'config-minutes-' + config.id}>Sperre nach Minuten {index + 1}</label><input id={'config-minutes-' + config.id} className={inputClass} type="number" min={1} max={1440} step={1} value={Number(payload.minutes)} onChange={event => editPayload(config.id, 'minutes', Number(event.target.value))} /></div>
                <label className="flex gap-3"><input type="checkbox" checked={Boolean(payload.requirePassword)} onChange={event => editPayload(config.id, 'requirePassword', event.target.checked)} />Passwort bei Entsperrung verlangen {index + 1}</label></>}
              {config.type === 'filevault' && <label className="flex gap-3"><input type="checkbox" checked={Boolean(payload.enabled)} onChange={event => editPayload(config.id, 'enabled', event.target.checked)} />FileVault gewünscht {index + 1}</label>}
              {config.type === 'software_update' && <><label className="flex gap-3"><input type="checkbox" checked={Boolean(payload.automatic)} onChange={event => editPayload(config.id, 'automatic', event.target.checked)} />Automatische Updates gewünscht {index + 1}</label>
                <div><label htmlFor={'config-deferral-' + config.id}>Update-Aufschub in Tagen {index + 1}</label><input id={'config-deferral-' + config.id} className={inputClass} type="number" min={0} max={365} step={1} value={Number(payload.deferralDays)} onChange={event => editPayload(config.id, 'deferralDays', Number(event.target.value))} /></div></>}
              <button className="fluent-btn-secondary" onClick={() => setDraft({ ...draft, configurations: draft.configurations.filter(candidate => candidate.id !== config.id) })}>Konfiguration {index + 1} entfernen</button>
            </fieldset>;
          })}
          <div className="flex flex-wrap gap-3 items-end"><div><label htmlFor="company-blueprint-config-type">Neue Konfigurationsart</label><select id="company-blueprint-config-type" className={inputClass} value={configChoice} onChange={event => setConfigChoice(event.target.value as CompanyBlueprintConfigType)}>
            {Object.entries(labels).map(([type, label]) => <option value={type} key={type}>{label}</option>)}</select></div>
            <button className="fluent-btn-secondary" disabled={draft.configurations.length >= 25} onClick={() => {
              try { setDraft({ ...draft, configurations: [...draft.configurations, { id: companyBlueprintId(), type: configChoice, name: labels[configChoice], payloadJson: JSON.stringify(defaults[configChoice]) }] }); }
              catch { setFormError('Sichere Konfigurations-ID konnte nicht erzeugt werden. Bitte Seite neu laden.'); }
            }}>Konfiguration hinzufügen</button></div>
          <p className="text-sm opacity-80">WLAN, VPN, Zertifikate und freie Konfigurationen sind nicht verfügbar. Keine Eingabe von Passwörtern, Schlüsseln oder Provider-Secrets.</p>
          <section aria-label="Gewünschte Firmen-Apps" className="space-y-3">
            <h3 className="font-semibold">Gewünschte Apps · {draft.appPoolIds.length} / 25</h3><p className="text-sm">Nur Referenzen auf eigene lokale App-Pools. Kein Bestand wird reserviert, keine Lizenz zugewiesen und keine App installiert.</p>
            <ul className="space-y-2">{draft.appPoolIds.map(poolId => <li className="flex flex-wrap gap-3 items-center" key={poolId}><span className="break-all">{apps?.pools.find(pool => pool.id === poolId)?.name || poolId}</span><button className="fluent-btn-secondary" aria-label={'App-Pool entfernen ' + poolId} onClick={() => setDraft({ ...draft, appPoolIds: draft.appPoolIds.filter(value => value !== poolId) })}>Referenz entfernen</button></li>)}</ul>
            <div className="flex flex-wrap gap-3 items-end"><div><label htmlFor="company-blueprint-app-search">Firmen-App suchen</label><input id="company-blueprint-app-search" className={inputClass} maxLength={100} value={appSearch} onChange={event => setAppSearch(event.target.value)} /></div>
              <button className="fluent-btn-secondary" onClick={() => loadApps(1, appSearch.trim())}>App-Auswahl laden</button></div>
            {appError && <p role="alert">{appError}</p>}
            {apps && <><ul className="space-y-2">{apps.pools.map(pool => <li key={pool.id}><label className="flex gap-3"><input type="checkbox" checked={draft.appPoolIds.includes(pool.id)} disabled={!draft.appPoolIds.includes(pool.id) && draft.appPoolIds.length >= 25} onChange={event => setDraft({ ...draft, appPoolIds: event.target.checked ? [...draft.appPoolIds, pool.id] : draft.appPoolIds.filter(value => value !== pool.id) })} />{pool.name} · {pool.vendor}</label><p className="break-all text-xs ml-7">{pool.id}</p></li>)}</ul>
              {!apps.pools.length && <p>Keine verfügbaren Firmen-App-Pools für diese Suche.</p>}
              <Pages page={apps.page} total={apps.total} label="Firmen-App-Seiten" disabled={blocked} onPage={page => loadApps(page)} /></>}
          </section>
        </fieldset>
        <div className="flex flex-wrap gap-3"><button className="fluent-btn-primary" disabled={blocked} onClick={() => begin(detail ? 'updated' : 'created')}>{detail ? 'Entwurf speichern' : 'Blueprint anlegen'}</button><button className="fluent-btn-secondary" onClick={reload}>Editor schliessen</button></div>
      </section>}
      {access && (draft || detail) && <div><label htmlFor="company-blueprint-reason">Begründung für die Änderung</label><input id="company-blueprint-reason" className={inputClass} minLength={10} maxLength={500} value={reason} disabled={blocked} onChange={event => setReason(event.target.value)} /><p className="mt-1 text-sm opacity-80">10–500 Zeichen, keine Zugangsdaten. Die Begründung bleibt in der Historie erhalten.</p></div>}
      {formError && <p role="alert">{formError}</p>}
      {detail && versions && history && access && <div className="grid gap-5 xl:grid-cols-2">
        <section aria-label="Lokale Blueprint-Versionen" className="rounded-lg border border-white/10 p-5 space-y-3"><h2 className="text-lg font-semibold">Unveränderliche Versionen</h2>
          {!versions.rows.length && <p>Noch keine Version lokal freigegeben.</p>}
          <ul className="space-y-3">{versions.rows.map(row => <li key={row.version}><button className="text-blue-400 underline" disabled={blocked} onClick={() => { setVersion(null); void run(() => client.current.version(detail.id, row.version), setVersion); }}>Version {row.version} ansehen</button><p className="text-sm">Quellrevision {row.sourceRevision} → Freigaberevision {row.publishedRevision} · {new Date(row.createdAt).toLocaleString('de-CH')}</p></li>)}</ul>
          <Pages page={versions.page} total={versions.total} label="Versionsseiten" disabled={blocked} onPage={page => { setVersion(null); void run(() => client.current.versions(detail.id, page), setVersions); }} />
          {version && <section aria-label={'Gespeicherte Version ' + version.version} className="border-t border-white/10 pt-3 space-y-3"><h3 className="font-semibold">Version {version.version} · historischer Stand</h3><DraftContent draft={version.draft} />
            <ul>{version.apps.map(app => <li className="break-all text-sm" key={app.id}>{app.name} · {app.vendor} · Pool-Revision {app.revision} · {app.id}</li>)}</ul>
            <p className="text-sm">App-Namen und Pool-Revisionen stammen aus dieser Freigabe, nicht aus aktuellem Lizenzbestand. Wiederherstellen ändert nur den Entwurf. Eine weitere lokale Freigabe erzeugt eine neue Version.</p>
            <button className="fluent-btn-secondary" disabled={blocked || !!draft} onClick={() => begin('restored')}>Als Entwurf wiederherstellen</button>
            <CompanyBlueprintUserAssignmentsPanel key={detail.id + ':' + version.version} context={access} blueprintId={detail.id} version={version} disabled={blocked || !!draft} />
          </section>}
        </section>
        <section aria-label="Blueprint-Historie" className="rounded-lg border border-white/10 p-5 space-y-3"><h2 className="text-lg font-semibold">Änderungshistorie</h2>
          {!history.rows.length && <p>Keine Historieneinträge verfügbar.</p>}
          <ol className="space-y-4">{history.rows.map(event => <li key={event.id}><h3 className="font-medium">{eventLabels[event.type]}</h3><p className="text-sm">{new Date(event.createdAt).toLocaleString('de-CH')} · Revision {event.beforeRevision || '—'} → {event.afterRevision}</p><p>{event.reason}</p>
            {event.releasedVersion !== null && <p>Lokale Version {event.releasedVersion}</p>}{event.restoredFrom !== null && <p>Entwurf aus Version {event.restoredFrom}</p>}
            <details><summary>Ereignisnachweis</summary><p className="break-all">Akteur: {event.actorUserId}</p><p className="break-all">Ereignis: {event.id} · Version {event.version}</p><p className="break-all">Korrelation: {event.correlationId}</p><p>Zustellung: ausstehend</p></details></li>)}</ol>
          <Pages page={history.page} total={history.total} label="Historieseiten" disabled={blocked} onPage={page => { void run(() => client.current.history(detail.id, page), setHistory); }} />
        </section>
      </div>}
      {busy && <p role="status">Firmen-Blueprint-Anfrage wird geprüft …</p>}
      {confirmation && <DirectoryConfirmation title={actions[confirmation.action]} busy={busy} error={confirmed ? '' : 'Bitte genau diesen lokalen Vorgang bestätigen.'} onClose={() => { setConfirmation(null); setConfirmed(false); }} onConfirm={confirm}>
        <div className="max-h-[50vh] overflow-y-auto space-y-3"><p>Nur ein lokaler Blueprint-Vorgang. Keine Geräteaktion, Lizenzreservierung oder externe Veröffentlichung.</p>
          <p className="break-all">Blueprint: {confirmation.blueprintId}</p><p className="break-all">Vorgang: {confirmation.operationId}</p><p className="break-all">{confirmation.etag || 'Neuer Blueprint'}</p>
          {confirmation.body.version && <p>Version {confirmation.body.version} wird nur in den Entwurf übernommen.</p>}
          {confirmation.body.draft && <p>{confirmation.body.draft.name} · {confirmation.body.draft.configurations.length} Konfigurationen · {confirmation.body.draft.appPoolIds.length} gewünschte App-Pools</p>}
          <p>{confirmation.body.reason}</p><label className="flex gap-3"><input type="checkbox" checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)} />Ich bestätige diesen lokalen Blueprint-Vorgang.</label>
        </div>
      </DirectoryConfirmation>}
    </div>
  </ViewShell>;
}
