'use client';

import React, { useEffect, useRef, useState } from 'react';
import { ShieldCheckIcon, ArrowPathIcon, XMarkIcon, MagnifyingGlassIcon } from '@heroicons/react/24/outline';
import { Dialog } from '@headlessui/react';
import { privilegedGroups, PIMGroup, PIMGroupState, PIMGroupMember, PIMGroupEvent } from '@/lib/privilegedGroups';
import { privilegedActivation, ActivationRequest, pimError } from '@/lib/privilegedActivation';
import { directoryUsers, DirectoryUser, userName } from '@/lib/directoryUsers';
import { startLogin } from '@/lib/auth';
import { DirectoryConfirmation } from './UserDetailPanel';
import CompanyPimPanel from './CompanyPimPanel';

const labels: Record<string, string> = { group_created: 'PIM-Gruppe eingerichtet', group_disabled: 'PIM-Gruppe deaktiviert', pending: 'Wartet auf Freigabe', approved: 'Freigegeben · jetzt aktivieren', active: 'Aktiv', revoked: 'Beendet', denied: 'Abgelehnt', cancelled: 'Abgebrochen', expired: 'Abgelaufen', stale: 'Berechtigung geändert', eligibility_created: 'Benutzer berechtigt', eligibility_revoked: 'Berechtigung entzogen' };
const durations = [900, 3600, 7200, 14400, 28800, 36000];
const time = (value: string | null) => value ? new Date(value).toLocaleString('de-CH') : '—';
const durationText = (value: number) => value < 3600 ? `${value / 60} ${value === 60 ? 'Minute' : 'Minuten'}` : `${value / 3600} ${value === 3600 ? 'Stunde' : 'Stunden'}`;
type Form = { kind: 'request' | 'assign' | 'disable'; group: PIMGroup; eligibilityId?: string } | { kind: 'create' };
type Tab = 'eligible' | 'active' | 'requests' | 'groups' | 'approvals';
type Change = { kind: 'request'; group: PIMGroup; body: { id: string; eligibilityId: string; durationSeconds: number; reason: string } }
  | { kind: 'assign'; group: PIMGroup; body: { userId: string; maxDurationSeconds: number; validForSeconds: number; reason: string; confirm: true } }
  | { kind: 'create'; body: { name: string; description: string; role: string; maxDurationSeconds: number; reason: string; confirm: true } }
  | { kind: 'disable'; group: PIMGroup; reason: string } | { kind: 'initialize' }
  | { kind: 'revoke-eligibility'; group: PIMGroup; eligibilityId: string; userId: string }
  | { kind: 'change'; group: Pick<PIMGroup, 'name' | 'role'>; request: ActivationRequest; action: 'approve' | 'deny' | 'activate' | 'cancel' | 'revoke' };

export default function PIMGroupsPanel({ management = false }: { management?: boolean }) {
  const generation = useRef(0); const writing = useRef(false);
  const tabId = React.useId();
  const [tab, setTab] = useState<Tab>('eligible'); const [search, setSearch] = useState('');
  const [state, setState] = useState<PIMGroupState | null>(null); const [version, setVersion] = useState(0); const [error, setError] = useState(''); const [notice, setNotice] = useState('');
  const [form, setForm] = useState<Form | null>(null); const [pending, setPending] = useState<Change | null>(null); const [busy, setBusy] = useState(false); const [now, setNow] = useState(Date.now());
  const [seconds, setSeconds] = useState(3600); const [reason, setReason] = useState(''); const [userId, setUserId] = useState(''); const [days, setDays] = useState(7);
  const [name, setName] = useState(''); const [description, setDescription] = useState(''); const [role, setRole] = useState(''); const [users, setUsers] = useState<DirectoryUser[]>([]);
  const [detail, setDetail] = useState<{ kind: 'members' | 'history'; group: PIMGroup; page: number } | null>(null);
  const [members, setMembers] = useState<PIMGroupMember[]>([]); const [events, setEvents] = useState<PIMGroupEvent[]>([]); const [total, setTotal] = useState(0); const [detailReady, setDetailReady] = useState(false);
  function clear() { setState(null); setForm(null); setPending(null); setDetail(null); setMembers([]); setEvents([]); setNotice(''); }
  function reload() { generation.current += 1; clear(); setError(''); setVersion(value => value + 1); }
  useEffect(() => { if (management && new URLSearchParams(window.location.search).has('userId')) setTab('groups'); }, [management]);
  useEffect(() => {
    const expected = ++generation.current; const controller = new AbortController();
    const invalid = () => { generation.current += 1; clear(); setError('Sitzung oder Berechtigung hat sich geändert. Bitte erneut anmelden.'); };
    window.addEventListener('od:session-error', invalid);
    privilegedGroups.load(controller.signal).then(value => { if (generation.current === expected) setState(value); }).catch(failure => { if (generation.current === expected) { clear(); setError(pimError(failure)); } });
    return () => { generation.current += 1; controller.abort(); window.removeEventListener('od:session-error', invalid); };
  }, [version]);
  useEffect(() => {
    const timer = setInterval(() => { setNow(Date.now()); if (!writing.current && !form && !pending && !detail) setVersion(value => value + 1); }, 30000); return () => clearInterval(timer);
  }, [form, pending, detail]);
  const nextExpiry = state?.self.requests.filter(item => item.status === 'active' && item.expiresAt).reduce((earliest, item) => Math.min(earliest, Date.parse(item.expiresAt!)), Infinity);
  useEffect(() => {
    if (!Number.isFinite(nextExpiry)) return;
    const timer = setTimeout(() => { generation.current += 1; clear(); setNotice('Eine Aktivierung ist abgelaufen. Bitte mit den aktuell gültigen Rechten neu anmelden.'); }, Math.max(0, nextExpiry! - Date.now()));
    return () => clearTimeout(timer);
  }, [nextExpiry]);
  useEffect(() => {
    setUsers([]); if (form?.kind !== 'assign') return; const controller = new AbortController(); let active = true;
    directoryUsers.list(1, '', '', controller.signal).then(value => { if (active) setUsers(value.users); }).catch(() => {});
    return () => { active = false; controller.abort(); };
  }, [form]);
  useEffect(() => {
    setMembers([]); setEvents([]); setTotal(0); setDetailReady(false); if (!detail) return;
    const expected = generation.current; const controller = new AbortController(); let active = true;
    (detail.kind === 'members' ? privilegedGroups.members(detail.group.id, detail.page, controller.signal) : privilegedGroups.history(detail.group.id, detail.page, controller.signal)).then(value => {
      if (!active || generation.current !== expected) return; setTotal(value.total); if ('members' in value) setMembers(value.members); else setEvents(value.events); setDetailReady(true);
    }).catch(failure => { if (active && generation.current === expected) { setDetail(null); setError(pimError(failure)); } });
    return () => { active = false; controller.abort(); };
  }, [detail]);
  function begin(next: Form) {
    setPending(null); setError(''); setNotice(''); setReason(''); setName(''); setDescription(''); setForm(next);
    setSeconds(Math.min(3600, 'group' in next ? next.group.maxDurationSeconds : 36000));
    setRole(state?.roles.find(item => item.assignable)?.role || '');
    const selected = new URLSearchParams(window.location.search).get('userId'); setUserId(selected && /^[a-f0-9-]{36}$/.test(selected) ? selected : '');
  }
  function capture(event: React.FormEvent) {
    event.preventDefault(); if (!form || !state || busy || reason.trim().length < 10) return;
    if (form.kind === 'create') setPending({ kind: 'create', body: { name: name.trim(), description: description.trim(), role, maxDurationSeconds: seconds, reason: reason.trim(), confirm: true } });
    else if (form.kind === 'request') {
      if (!Number.isInteger(seconds) || seconds < 60 || seconds > form.group.maxDurationSeconds) return;
      void execute({ kind: 'request', group: form.group, body: { id: crypto.randomUUID(), eligibilityId: form.eligibilityId!, durationSeconds: seconds, reason: reason.trim() } });
    }
    else if (form.kind === 'assign') setPending({ kind: 'assign', group: form.group, body: { userId, maxDurationSeconds: seconds, validForSeconds: days * 86400, reason: reason.trim(), confirm: true } });
    else setPending({ kind: 'disable', group: form.group, reason: reason.trim() });
  }
  async function execute(change: Change) {
    if (!state || writing.current) return; const expected = generation.current; writing.current = true; setBusy(true);
    try {
      let ownRoleChanged = false;
      if (change.kind === 'request') { const result = await privilegedActivation.request(change.body); if (result.userId !== state.userId) throw new Error('Unconfirmed PIM owner'); }
      else if (change.kind === 'assign') await privilegedGroups.assign(change.group.id, change.body);
      else if (change.kind === 'create') await privilegedGroups.create(change.body);
      else if (change.kind === 'disable') { await privilegedGroups.disable(change.group.id, change.reason); ownRoleChanged = state.self.requests.some(item => item.status === 'active' && state.bindings.some(binding => binding.groupId === change.group.id && binding.eligibilityId === item.eligibilityId)); }
      else if (change.kind === 'initialize') await privilegedGroups.initialize();
      else if (change.kind === 'revoke-eligibility') { await privilegedActivation.revokeEligibility(change.eligibilityId); ownRoleChanged = change.userId === state.userId; }
      else {
        const result = await privilegedActivation.change(change.request.id, change.action);
        if (result.userId !== change.request.userId || result.role !== change.request.role) throw new Error('Unconfirmed PIM target');
        ownRoleChanged = result.userId === state.userId && (change.action === 'activate' || change.request.status === 'active');
      }
      if (generation.current !== expected) return;
      if (ownRoleChanged) { clear(); startLogin(); return; }
      reload();
      if (change.kind === 'request') { setTab('requests'); setNotice('Antrag gesendet. Deine Aktivierung wartet auf eine unabhängige Freigabe.'); }
      else setNotice('Änderung gespeichert und protokolliert.');
    } catch (failure) {
      if (generation.current === expected) { generation.current += 1; clear(); setError(pimError(failure) + ' Vor einem weiteren Schreibvorgang zuerst den aktuellen Stand neu laden.'); }
    } finally { writing.current = false; setBusy(false); }
  }
  const legacyGroups: PIMGroup[] = (state?.self.eligibilities || []).filter(item => !state?.bindings.some(binding => binding.eligibilityId === item.id)).map(item => ({
    id: item.id, name: item.role, description: 'Persönliche Rollenberechtigung', role: item.role,
    maxDurationSeconds: Math.min(item.maxDurationSeconds, state?.roles.find(role => role.role === item.role)?.maxDurationSeconds || 0),
    configuredMaxDurationSeconds: item.maxDurationSeconds, enabled: item.status === 'eligible', protected: false, createdAt: item.createdAt, canManage: false,
  }));
  const rows = [...(state?.groups || []), ...legacyGroups].map(group => {
    const isGroup = state?.groups.some(item => item.id === group.id) === true;
    const ownBindings = state?.bindings.filter(binding => binding.groupId === group.id && binding.userId === state.userId) || [];
    const linked = (id: string) => isGroup ? ownBindings.some(binding => binding.eligibilityId === id) : id === group.id;
    const eligibility = state?.self.eligibilities.find(item => linked(item.id) && item.status === 'eligible' && Date.parse(item.expiresAt) > now);
    const requests = state?.self.requests.filter(item => linked(item.eligibilityId)) || [];
    const current = requests.find(item => ['active', 'approved', 'pending'].includes(item.status) && (!item.expiresAt || Date.parse(item.expiresAt) > now));
    const standing = state?.standingRoles.includes(group.role) === true;
    const maximum = Math.min(group.maxDurationSeconds, eligibility?.maxDurationSeconds || group.maxDurationSeconds,
      eligibility ? Math.floor((Date.parse(eligibility.expiresAt) - now) / 60000) * 60 : group.maxDurationSeconds);
    return { group, isGroup, eligibility, current, standing, maximum };
  });
  const tabs: { id: Tab; label: string }[] = [
    { id: 'eligible', label: 'Berechtigt' }, { id: 'active', label: 'Aktiv' }, { id: 'requests', label: 'Meine Anträge' },
    { id: 'groups', label: 'Gruppen' }, ...(state?.canReview ? [{ id: 'approvals' as const, label: 'Genehmigungen' }] : []),
  ];
  const selectedTab = tabs.some(item => item.id === tab) ? tab : 'eligible';
  const filtered = rows.filter(row => (selectedTab === 'groups' ? row.isGroup && (row.group.enabled || management)
    : selectedTab === 'active' ? row.standing || row.current?.status === 'active'
      : row.group.enabled && row.eligibility && row.maximum >= 60 && !row.standing && row.current?.status !== 'active'))
    .filter(row => (row.group.name + ' ' + row.group.description).toLocaleLowerCase().includes(search.toLocaleLowerCase()));
  const groupFor = (request: ActivationRequest) => rows.find(row => row.group.id === request.eligibilityId
    || state?.bindings.some(binding => binding.groupId === row.group.id && binding.eligibilityId === request.eligibilityId))?.group
    || { id: request.eligibilityId, name: request.role, role: request.role };
  const requests = (selectedTab === 'approvals' ? state?.queue || [] : state?.self.requests || [])
    .filter(item => (groupFor(item).name + ' ' + item.reason).toLocaleLowerCase().includes(search.toLocaleLowerCase()));
  const ownApproved = (group: Pick<PIMGroup, 'name' | 'role'>, request: ActivationRequest) => void execute({ kind: 'change', group, request, action: 'activate' });
  const formTitle = form?.kind === 'request' ? 'Aktivieren' : form?.kind === 'assign' ? 'Zuweisung hinzufügen' : form?.kind === 'create' ? 'Gruppe erstellen' : 'Gruppe deaktivieren';
  const returnTo = management ? '%2Fpim' : '%2Fdashboard';
  if(state&&!error&&!notice&&!state.canCreate&&!state.canReview&&!state.standingRoles.length&&!state.self.eligibilities.length&&!state.self.requests.length&&!state.groups.some(group=>group.canManage))return <CompanyPimPanel management={management}/>;
  return <><section className="od-pim" aria-label="PIM-Aufgabengruppen">
    <div className="od-pim-heading"><div><h2><ShieldCheckIcon aria-hidden="true" />Meine Rollen</h2><p>Aktiviere den Zugriff, den du gerade benötigst.</p></div>
      {!management && <a className="od-text-action" href="/pim">Privileged Identity Management öffnen</a>}
    </div>
    {notice && <p role="status" className="od-pim-message">{notice}{!state && <a className="od-text-action" href={'/api/auth/oidc/login?returnTo=' + returnTo}>Neu anmelden</a>}</p>}
    {error && <div role="alert" className="od-pim-message od-pim-error"><p>{error}</p><div className="flex flex-wrap gap-4">
      <a className="od-text-action" href={'/api/auth/oidc/login?returnTo=' + returnTo}>Neu anmelden / MFA bestätigen</a>
      <a className="od-text-action" href={'/mfa?returnTo=' + returnTo}>MFA einrichten</a></div></div>}
    <div className="od-pim-tabs" role="tablist" aria-label="PIM-Zuweisungen">{tabs.map((item, index) => <button key={item.id} id={tabId + item.id} role="tab" aria-selected={selectedTab === item.id}
      aria-controls={tabId + '-panel'} tabIndex={selectedTab === item.id ? 0 : -1} onClick={() => { setTab(item.id); setSearch(''); }} onKeyDown={event => {
        const next = event.key === 'ArrowRight' ? (index + 1) % tabs.length : event.key === 'ArrowLeft' ? (index + tabs.length - 1) % tabs.length : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : -1;
        if (next < 0) return; event.preventDefault(); setTab(tabs[next].id); setSearch(''); document.getElementById(tabId + tabs[next].id)?.focus();
      }}>{item.label}</button>)}</div>
    <div className="od-pim-toolbar"><label className="od-pim-search"><MagnifyingGlassIcon aria-hidden="true" /><input aria-label="Rollen und Gruppen suchen" placeholder="Nach Rolle oder Gruppe suchen" maxLength={120} value={search} onChange={event => setSearch(event.target.value)} /></label>
      <button className="fluent-btn-ghost" disabled={busy || !!pending} onClick={reload}><ArrowPathIcon aria-hidden="true" className="h-4 w-4" />Aktualisieren</button>
      {management && selectedTab === 'groups' && state?.canCreate && <><button className="fluent-btn-primary" disabled={busy || !!pending} onClick={() => begin({ kind: 'create' })}>Gruppe erstellen</button>
        {!state.groups.length && state.roles.some(item => item.role === 'admin' && item.assignable) && <button className="fluent-btn-secondary" disabled={busy || !!pending} onClick={() => setPending({ kind: 'initialize' })}>Standardgruppen einrichten</button>}</>}
    </div>
    <div id={tabId + '-panel'} role="tabpanel" aria-labelledby={tabId + selectedTab} tabIndex={0}>
      {!state && !error && !notice && <p className="od-pim-empty" role="status">Zuweisungen werden geladen …</p>}
      {(state?.truncated || state?.self.truncated) && <p role="status" className="od-pim-message">Die Anzeige ist begrenzt. Weitere Datensätze bitte in der Verwaltung prüfen.</p>}
      {state && <>
        {selectedTab === 'active' && state.standingRoles.includes('admin') && <details className="od-pim-note"><summary>Direkte Adminrechte sind bereits aktiv.</summary><p>Diese bestehende direkte Adminrolle wird durch PIM nicht begrenzt. Ein Betrieb ausschließlich über PIM erfordert einen unabhängigen Freigabe- und Wiederherstellungsweg. <a className="od-text-action" href="/pim">Rollenrichtlinien öffnen</a></p></details>}
        <div className="od-pim-table-scroll"><table className="od-pim-table"><thead><tr><th>Rolle / Gruppe</th><th>{selectedTab === 'approvals' ? 'Antragsteller' : 'Status'}</th><th>Dauer / Ablauf</th><th>Aktion</th></tr></thead><tbody>
          {['requests', 'approvals'].includes(selectedTab) ? requests.map(item => {
            const group = groupFor(item); const own = item.userId === state.userId; const reviewable = !own && state.roles.some(role => role.role === item.role && role.reviewable);
            return <tr key={item.id} aria-label={'Antrag ' + item.id}><td><strong>{group.name}</strong><span>{item.reason}</span><span className="od-pim-mobile-meta">{labels[item.status]} · {durationText(item.durationSeconds)}</span></td>
              <td>{selectedTab === 'approvals' ? <><span className="break-all">{item.userId}</span><span>{labels[item.status]}</span></> : labels[item.status]}</td>
              <td>{durationText(item.durationSeconds)}{item.expiresAt && <span>Bis {time(item.expiresAt)}</span>}</td><td><div className="od-pim-actions">
                {own && item.status === 'approved' && <button className="od-text-action" disabled={busy} onClick={() => ownApproved(group, item)}>Aktivieren</button>}
                {own && ['pending', 'approved', 'active'].includes(item.status) && <button className="od-text-action" disabled={busy || !!pending} onClick={() => setPending({ kind: 'change', group, request: item, action: 'cancel' })}>{item.status === 'active' ? 'Deaktivieren' : 'Zurückziehen'}</button>}
                {reviewable && item.status === 'pending' && (['approve', 'deny'] as const).map(action => <button className="od-text-action" disabled={busy || !!pending} key={action} onClick={() => setPending({ kind: 'change', group, request: item, action })}>{action === 'approve' ? 'Genehmigen' : 'Ablehnen'}</button>)}
                {reviewable && item.status === 'active' && <button className="od-text-action" disabled={busy || !!pending} onClick={() => setPending({ kind: 'change', group, request: item, action: 'revoke' })}>Widerrufen</button>}
              </div></td></tr>;
          }) : filtered.map(({ group, isGroup, eligibility, current, standing, maximum }) => {
            const status = !group.enabled ? 'Deaktiviert' : current ? labels[current.status] : standing ? 'Direkt aktiv' : eligibility ? 'Berechtigt' : 'Nicht zugewiesen';
            return <tr key={group.id} aria-label={'PIM-Gruppe ' + group.name}><td><strong>{group.name}</strong><span>{group.description}</span><span className="od-pim-mobile-meta">{status} · {current?.expiresAt ? 'Bis ' + time(current.expiresAt) : standing ? 'Direkte Zuweisung' : 'Max. ' + durationText(Math.max(60, maximum))}</span></td><td><span className={current?.status === 'active' || standing ? 'od-pim-active-status' : ''}>{status}</span></td>
              <td>{current?.expiresAt ? <><span>Bis {time(current.expiresAt)}</span><span>Noch {Math.max(0, Math.ceil((Date.parse(current.expiresAt) - now) / 60000))} Minuten</span></> : standing ? 'Direkte Zuweisung' : <>Max. {durationText(Math.max(60, maximum))}</>}</td>
              <td><div className="od-pim-actions">
                {group.enabled && eligibility && maximum >= 60 && !current && !standing && <button className="od-text-action" disabled={busy || !!pending} onClick={() => begin({ kind: 'request', group: { ...group, maxDurationSeconds: maximum }, eligibilityId: eligibility.id })}>Aktivieren</button>}
                {group.enabled && current?.status === 'approved' && <button className="od-text-action" disabled={busy} onClick={() => ownApproved(group, current)}>Aktivieren</button>}
                {current?.status === 'pending' && <button className="od-text-action" onClick={() => { setTab('requests'); setSearch(''); }}>Antrag anzeigen</button>}
                {current?.status === 'active' && <button className="od-text-action" disabled={busy || !!pending} onClick={() => setPending({ kind: 'change', group, request: current, action: 'cancel' })}>Deaktivieren</button>}
                {management && selectedTab === 'groups' && group.canManage && group.enabled && <button className="od-text-action" disabled={busy || !!pending} onClick={() => begin({ kind: 'assign', group })}>Zuweisen</button>}
                {isGroup && <details className="od-pim-row-menu"><summary aria-label={'Weitere Aktionen für ' + group.name}>•••</summary><div>
                  <button disabled={busy || !!pending} onClick={() => setDetail({ kind: 'history', group, page: 1 })}>Protokoll</button>
                  {management && group.canManage && <><button disabled={busy || !!pending} onClick={() => setDetail({ kind: 'members', group, page: 1 })}>Zuweisungen anzeigen</button>
                    {group.enabled && <button disabled={busy || !!pending} onClick={() => begin({ kind: 'disable', group })}>Gruppe deaktivieren</button>}</>}
                </div></details>}
              </div></td></tr>;
          })}
        </tbody></table></div>
        {(['requests', 'approvals'].includes(selectedTab) ? !requests.length : !filtered.length) && <div className="od-pim-empty"><ShieldCheckIcon aria-hidden="true" /><h3>{search ? 'Keine passenden Zuweisungen' : selectedTab === 'active' ? 'Keine aktiven Rollen' : selectedTab === 'requests' ? 'Keine Anträge' : selectedTab === 'approvals' ? 'Keine Genehmigungen vorhanden' : selectedTab === 'groups' ? 'Keine Gruppen vorhanden' : 'Keine berechtigten Zuweisungen'}</h3>
          <p>{selectedTab === 'eligible' && !search ? 'Zugewiesene Rollen erscheinen hier. Unter „Aktiv“ siehst du deinen bereits freigegebenen Zugriff.' : 'Aktualisiere die Ansicht oder wähle einen anderen Bereich.'}</p>
          {selectedTab === 'eligible' && <button className="od-text-action" onClick={() => setTab('groups')}>Gruppen anzeigen</button>}</div>}
        <p className="od-pim-count">{['requests', 'approvals'].includes(selectedTab) ? requests.length : filtered.length} Einträge</p>
      </>}
    </div>
    {form && state && <Dialog open onClose={() => { if (!busy) setForm(null); }} className="od-pim-dialog">
      <div className="od-pim-backdrop" aria-hidden="true" /><Dialog.Panel className="od-pim-blade">
        <header><div><Dialog.Title>{formTitle}{'group' in form ? ' – ' + form.group.name : ''}</Dialog.Title><p>Privileged Identity Management</p></div><button type="button" disabled={busy} aria-label="Formular schließen" onClick={() => setForm(null)}><XMarkIcon aria-hidden="true" /></button></header>
        <form onSubmit={capture} className="od-pim-form"><div className="od-pim-form-body">
          {form.kind === 'request' && <><div className="od-pim-section-label">Aktivieren</div><dl className="od-pim-summary"><div><dt>Rolle / Gruppe</dt><dd>{form.group.name}</dd></div><div><dt>Zuweisung</dt><dd>Berechtigt</dd></div></dl>
            <p className="od-pim-message">Eine unabhängige Freigabe und frische MFA sind erforderlich. Dein Antrag wird protokolliert.</p>
            {form.group.role === 'admin' && <p className="od-pim-error od-pim-message">Global Security gewährt für die gewählte Dauer volle Adminrechte.</p>}
            <label htmlFor={tabId + '-duration'}>Dauer (Stunden)</label><div className="od-pim-duration"><input type="range" aria-label="Aktivierungsdauer in Minuten" min={60} max={form.group.maxDurationSeconds} step={60} value={seconds} onChange={event => setSeconds(Number(event.target.value))} />
              <input id={tabId + '-duration'} type="number" min={1 / 60} max={form.group.maxDurationSeconds / 3600} step="any" required value={seconds / 3600} onChange={event => setSeconds(Math.round(Number(event.target.value) * 3600))} /></div><p className="od-pim-hint">Maximal {durationText(form.group.maxDurationSeconds)}</p>
          </>}
          {form.kind === 'create' && <><label>Gruppenname<input className="fluent-input" required minLength={2} maxLength={80} value={name} onChange={event => setName(event.target.value)} /></label>
            <label>Beschreibung<input className="fluent-input" maxLength={500} value={description} onChange={event => setDescription(event.target.value)} /></label>
            <label>Zugeordnete Rolle<select className="fluent-input" required value={role} onChange={event => setRole(event.target.value)}>{state.roles.filter(item => item.assignable).map(item => <option key={item.role} value={item.role}>{item.role}</option>)}</select></label></>}
          {form.kind === 'assign' && <>
            {users.length > 0 && <label>Benutzer auswählen<select className="fluent-input" value={users.some(user => user.id === userId) ? userId : ''} onChange={event => setUserId(event.target.value)}><option value="">Benutzer auswählen …</option>{users.map(user => <option key={user.id} value={user.id} disabled={user.id === state.userId}>{userName(user)} · {user.username}{user.id === state.userId ? ' · anderer Administrator erforderlich' : ''}</option>)}</select></label>}
            <details className="od-pim-manual-id" open={!users.length || Boolean(userId && !users.some(user => user.id === userId))}><summary>Verzeichnis-ID eingeben</summary><label>Verzeichnis-ID des Benutzers<input className="fluent-input" required pattern="[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}" value={userId} onChange={event => setUserId(event.target.value)} /></label></details>
            <p className="od-pim-hint">Diese Zuweisung berechtigt zur Aktivierung und erteilt noch keine aktiven Rechte.</p>
            <label>Berechtigung gültig für Tage<input className="fluent-input" type="number" min={1} max={30} required value={days} onChange={event => setDays(Number(event.target.value))} /></label>
          </>}
          {!['request', 'disable'].includes(form.kind) && <label>{form.kind === 'assign' ? 'Maximale Aktivierungsdauer' : 'Gruppenlimit'}<select className="fluent-input" value={seconds} onChange={event => setSeconds(Number(event.target.value))}>
            {Array.from(new Set([Math.min(3600, 'group' in form ? form.group.maxDurationSeconds : 36000), ...durations.filter(value => value <= ('group' in form ? form.group.maxDurationSeconds : 36000))])).sort((a, b) => a - b).map(value => <option key={value} value={value}>{durationText(value)}</option>)}
          </select></label>}
          {form.kind === 'disable' && <p>Alle laufenden Berechtigungen dieser Gruppe werden entzogen. Die Nachweise bleiben im Protokoll erhalten.</p>}
          <label>Begründung <span aria-hidden="true">*</span><textarea className="fluent-input" rows={5} required minLength={10} maxLength={500} placeholder="Warum benötigst du diesen Zugriff?" value={reason} onChange={event => setReason(event.target.value)} /></label>
          <p className="od-pim-hint">10–500 Zeichen. Die Begründung wird im Protokoll gespeichert.</p>
        </div><footer><button className="fluent-btn-primary" disabled={busy || !!pending || reason.trim().length < 10 || form.kind === 'assign' && (!/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(userId) || userId === state.userId)}>{busy ? 'Wird gesendet …' : form.kind === 'request' ? 'Aktivieren' : 'Weiter'}</button>
          <button type="button" className="fluent-btn-secondary" disabled={busy} onClick={() => setForm(null)}>Abbrechen</button></footer></form>
      </Dialog.Panel>
    </Dialog>}
    {detail && <Dialog open onClose={() => { if (!busy) setDetail(null); }} className="od-pim-dialog"><div className="od-pim-backdrop" aria-hidden="true" /><Dialog.Panel className="od-pim-blade">
      <header><div><Dialog.Title>{detail.kind === 'history' ? 'Protokoll' : 'Zuweisungen'} – {detail.group.name}</Dialog.Title><p>Privileged Identity Management</p></div><button type="button" aria-label="Details schließen" disabled={busy} onClick={() => setDetail(null)}><XMarkIcon aria-hidden="true" /></button></header>
      <section className="od-pim-form-body" aria-label={detail.kind === 'history' ? 'PIM-Protokoll' : 'PIM-Gruppenzuweisungen'}>
        {!detailReady ? <p role="status">Daten werden geladen …</p> : <>
          {detail.kind === 'history' ? <>{!events.length && <p>Keine PIM-Vorgänge vorhanden.</p>}{events.map(event => <article key={event.id} className="od-pim-event"><h3>{labels[event.action]}</h3><p>{time(event.createdAt)}</p><p>{event.reason}</p><dl><div><dt>Benutzer</dt><dd>{event.userId || 'Gruppenkonfiguration'}</dd></div><div><dt>Ausgeführt von</dt><dd>{event.actorUserId || 'System'}</dd></div></dl>{event.expiresAt && <p>Geplantes Ende: {time(event.expiresAt)}</p>}</article>)}</> : <>
            {!members.length && <p>Keine Benutzer zugewiesen.</p>}{members.map(member => <article key={member.eligibilityId} className="od-pim-event"><h3>{member.name}</h3><p>{member.userId}</p><p>{member.revoked ? 'Entzogen' : Date.parse(member.expiresAt) <= now ? 'Abgelaufen' : 'Berechtigt'} · bis {time(member.expiresAt)}</p>
              {!member.revoked && Date.parse(member.expiresAt) > now && <button className="od-text-action" disabled={busy || !!pending} onClick={() => setPending({ kind: 'revoke-eligibility', group: detail.group, eligibilityId: member.eligibilityId, userId: member.userId })}>Berechtigung entziehen</button>}</article>)}</>}
          <div className="od-pim-pagination"><button className="fluent-btn-secondary" disabled={detail.page <= 1 || busy} onClick={() => setDetail({ ...detail, page: detail.page - 1 })}>Zurück</button><span>Seite {detail.page} · {total} Einträge</span><button className="fluent-btn-secondary" disabled={detail.page * 25 >= total || busy} onClick={() => setDetail({ ...detail, page: detail.page + 1 })}>Weiter</button></div>
        </>}
      </section>
    </Dialog.Panel></Dialog>}
    {pending && <DirectoryConfirmation title="PIM-Vorgang bestätigen" busy={busy} error="" onClose={() => setPending(null)} onConfirm={() => void execute(pending)}>
      <p>{pending.kind === 'change' ? `${pending.group.name}: ${pending.action === 'approve' ? 'Antrag unabhängig genehmigen.' : pending.action === 'deny' ? 'Antrag ablehnen.' : 'Aktivierung beziehungsweise Antrag beenden.'}`
        : pending.kind === 'assign' ? `${pending.body.userId} für ${pending.group.name} berechtigen. Aktive Rechte entstehen erst nach Freigabe und Aktivierung.`
          : pending.kind === 'create' ? `Gruppe ${pending.body.name} mit Rolle ${pending.body.role} erstellen.`
            : pending.kind === 'disable' ? `${pending.group.name} deaktivieren und alle laufenden Gruppenberechtigungen entziehen.`
              : pending.kind === 'revoke-eligibility' ? `Gruppenberechtigung für ${pending.userId} entziehen. Aktive Rollen aus dieser Berechtigung enden ebenfalls.` : 'Standardgruppen anlegen. Es werden keine Benutzer berechtigt und keine Rechte aktiviert.'}</p>
      {'body' in pending && <p className="mt-3">Begründung: {pending.body.reason}</p>}
      {pending.kind === 'change' && <p className="mt-3">Benutzer: {pending.request.userId} · {pending.request.reason}</p>}
    </DirectoryConfirmation>}
  </section><CompanyPimPanel management={management}/></>;
}
