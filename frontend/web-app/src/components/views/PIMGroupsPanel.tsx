'use client';

import React, { useEffect, useRef, useState } from 'react';
import { ShieldCheckIcon, CommandLineIcon, KeyIcon, UsersIcon, Squares2X2Icon, RocketLaunchIcon, ClockIcon, DocumentTextIcon } from '@heroicons/react/24/outline';
import { privilegedGroups, PIMGroup, PIMGroupState, PIMGroupMember, PIMGroupEvent } from '@/lib/privilegedGroups';
import { privilegedActivation, ActivationRequest, pimError } from '@/lib/privilegedActivation';
import { directoryUsers, DirectoryUser, userName } from '@/lib/directoryUsers';
import { startLogin } from '@/lib/auth';
import { DirectoryConfirmation } from './UserDetailPanel';

const labels: Record<string, string> = { group_created: 'PIM-Gruppe eingerichtet', group_disabled: 'PIM-Gruppe deaktiviert', pending: 'Wartet auf Freigabe', approved: 'Freigegeben · jetzt aktivieren', active: 'Aktiv', revoked: 'Beendet', denied: 'Abgelehnt', cancelled: 'Abgebrochen', expired: 'Abgelaufen', stale: 'Berechtigung geändert', eligibility_created: 'Benutzer berechtigt', eligibility_revoked: 'Berechtigung entzogen' };
const looks: Record<string, { icon: typeof ShieldCheckIcon; color: string }> = {
  'device-enrollment-operator': { icon: CommandLineIcon, color: '#3b82f6' }, 'license-administrator': { icon: KeyIcon, color: '#8b5cf6' },
  'user-administrator': { icon: UsersIcon, color: '#06b6d4' }, 'application-administrator': { icon: Squares2X2Icon, color: '#10b981' },
  'policy-deployment-operator': { icon: RocketLaunchIcon, color: '#f59e0b' }, admin: { icon: ShieldCheckIcon, color: '#ef4444' },
};
const durations = [900, 3600, 7200, 14400, 28800, 36000];
const time = (value: string | null) => value ? new Date(value).toLocaleString('de-CH') : '—';
const durationText = (value: number) => value < 3600 ? `${value / 60} ${value === 60 ? 'Minute' : 'Minuten'}` : `${value / 3600} ${value === 3600 ? 'Stunde' : 'Stunden'}`;
type Form = { kind: 'request' | 'assign' | 'disable'; group: PIMGroup; eligibilityId?: string } | { kind: 'create' };
type Change = { kind: 'request'; group: PIMGroup; body: { id: string; eligibilityId: string; durationSeconds: number; reason: string } }
  | { kind: 'assign'; group: PIMGroup; body: { userId: string; maxDurationSeconds: number; validForSeconds: number; reason: string; confirm: true } }
  | { kind: 'create'; body: { name: string; description: string; role: string; maxDurationSeconds: number; reason: string; confirm: true } }
  | { kind: 'disable'; group: PIMGroup; reason: string } | { kind: 'initialize' }
  | { kind: 'revoke-eligibility'; group: PIMGroup; eligibilityId: string; userId: string }
  | { kind: 'change'; group: PIMGroup; request: ActivationRequest; action: 'approve' | 'deny' | 'activate' | 'cancel' | 'revoke' };

export default function PIMGroupsPanel({ management = false }: { management?: boolean }) {
  const generation = useRef(0); const writing = useRef(false);
  const [state, setState] = useState<PIMGroupState | null>(null); const [version, setVersion] = useState(0); const [error, setError] = useState(''); const [notice, setNotice] = useState('');
  const [form, setForm] = useState<Form | null>(null); const [pending, setPending] = useState<Change | null>(null); const [busy, setBusy] = useState(false); const [now, setNow] = useState(Date.now());
  const [seconds, setSeconds] = useState(3600); const [reason, setReason] = useState(''); const [userId, setUserId] = useState(''); const [days, setDays] = useState(7);
  const [name, setName] = useState(''); const [description, setDescription] = useState(''); const [role, setRole] = useState(''); const [users, setUsers] = useState<DirectoryUser[]>([]);
  const [detail, setDetail] = useState<{ kind: 'members' | 'history'; group: PIMGroup; page: number } | null>(null);
  const [members, setMembers] = useState<PIMGroupMember[]>([]); const [events, setEvents] = useState<PIMGroupEvent[]>([]); const [total, setTotal] = useState(0); const [detailReady, setDetailReady] = useState(false);
  function clear() { setState(null); setForm(null); setPending(null); setDetail(null); setMembers([]); setEvents([]); }
  function reload() { generation.current += 1; clear(); setError(''); setVersion(value => value + 1); }
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
    else if (form.kind === 'request') setPending({ kind: 'request', group: form.group, body: { id: crypto.randomUUID(), eligibilityId: form.eligibilityId!, durationSeconds: seconds, reason: reason.trim() } });
    else if (form.kind === 'assign') setPending({ kind: 'assign', group: form.group, body: { userId, maxDurationSeconds: seconds, validForSeconds: days * 86400, reason: reason.trim(), confirm: true } });
    else setPending({ kind: 'disable', group: form.group, reason: reason.trim() });
  }
  async function perform() {
    if (!pending || !state || writing.current) return; const change = pending; const expected = generation.current; writing.current = true; setBusy(true);
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
      reload(); setNotice('PIM-Vorgang bestätigt und protokolliert.');
    } catch (failure) {
      if (generation.current === expected) { generation.current += 1; clear(); setError(pimError(failure) + ' Vor einem weiteren Schreibvorgang zuerst den aktuellen Stand neu laden.'); }
    } finally { writing.current = false; setBusy(false); }
  }
  const activeCount = state?.self.requests.filter(item => item.status === 'active' && item.expiresAt && Date.parse(item.expiresAt) > now).length || 0;
  return <section className="rounded-xl p-5 space-y-4" aria-label="PIM-Aufgabengruppen" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
    <div className="flex flex-wrap justify-between items-start gap-3"><div><h2 className="text-lg font-semibold flex items-center gap-2"><ShieldCheckIcon className="h-5 w-5" />Privilegierter Zugriff · PIM</h2>
      <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>Aktiviere nur die Aufgaben, die du gerade brauchst. Zuweisung, Freigabe, Aktivierung und Widerruf werden protokolliert.</p></div>
      <div className="flex flex-wrap gap-2 items-center"><span className="od-badge">{activeCount} aktiv</span><button className="fluent-btn-secondary" disabled={busy || !!pending} onClick={reload}>PIM neu laden</button>{!management && <a className="fluent-btn-secondary" href="/pim">Gruppen & Zuweisungen</a>}</div></div>
    {notice && <p role="status">{notice} <a className="underline" href="/api/auth/oidc/login?returnTo=%2Fdashboard">Anmeldung bestätigen</a></p>}
    {error && <div role="alert" className="space-y-2"><p>{error}</p><a className="fluent-btn-secondary" href={management ? "/api/auth/oidc/login?returnTo=%2Fpim" : "/api/auth/oidc/login?returnTo=%2Fdashboard"}>Neu anmelden / MFA bestätigen</a><a className="fluent-btn-secondary" href={management ? "/mfa?returnTo=%2Fpim" : "/mfa?returnTo=%2Fdashboard"}>MFA einrichten oder prüfen</a></div>}
    {!state && !error && !notice && <p role="status">PIM-Gruppen werden geprüft …</p>}
    {state?.standingRoles.includes('admin') && <p className="rounded border border-amber-500/40 p-3 text-sm">Dauerhafte Adminrechte sind bereits aktiv. Das Aktivieren einzelner Gruppen begrenzt diese bestehende Adminrolle nicht. Für einen Betrieb nur über PIM muss die Admin-Rollenrichtlinie mit einem unabhängigen Freigabe- und Wiederherstellungsweg eingerichtet werden. <a href="/pim" className="underline">Rollenrichtlinien öffnen</a></p>}
    {state?.truncated && <p role="status">Die Anzeige ist begrenzt. Weitere Datensätze bitte über die Gruppenverwaltung prüfen.</p>}
    {state && <>
      {!state.groups.length && <p>Für diese Firma sind noch keine PIM-Gruppen eingerichtet.</p>}
      {management && state.canCreate && <div className="flex flex-wrap gap-2"><button className="fluent-btn-primary" disabled={busy || !!pending} onClick={() => begin({ kind: 'create' })}>PIM-Gruppe erstellen</button>
        {!state.groups.length && state.roles.some(item => item.role === 'admin' && item.assignable) && <button className="fluent-btn-secondary" disabled={busy || !!pending} onClick={() => setPending({ kind: 'initialize' })}>Standardgruppen einrichten</button>}</div>}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">{state.groups.filter(group => group.enabled || management).map(group => {
        const look = looks[group.role] || { icon: ShieldCheckIcon, color: '#64748b' }; const Icon = look.icon;
        const ownBindings = state.bindings.filter(binding => binding.groupId === group.id && binding.userId === state.userId);
        const eligibility = state.self.eligibilities.find(item => ownBindings.some(binding => binding.eligibilityId === item.id) && item.status === 'eligible');
        const requests = state.self.requests.filter(item => ownBindings.some(binding => binding.eligibilityId === item.eligibilityId));
        const current = requests.find(item => ['active', 'approved', 'pending'].includes(item.status) && (!item.expiresAt || Date.parse(item.expiresAt) > now));
        const maximum = Math.min(group.maxDurationSeconds, eligibility?.maxDurationSeconds || group.maxDurationSeconds);
        return <article key={group.id} className="rounded-xl p-4 space-y-3" aria-label={'PIM-Gruppe ' + group.name} style={{ border: `1px solid ${look.color}55`, background: 'var(--bg-base)' }}>
          <div className="flex justify-between gap-3"><div className="flex items-center gap-3"><span className="rounded-lg p-2" style={{ color: look.color, background: look.color + '18' }}><Icon className="h-6 w-6" /></span><h3 className="font-semibold">{group.name}</h3></div><span className="od-badge">{!group.enabled ? 'Deaktiviert' : current ? labels[current.status] : state.standingRoles.includes(group.role) ? 'Dauerhaft aktiv' : eligibility ? 'Berechtigt · inaktiv' : 'Nicht zugewiesen'}</span></div>
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>{group.description}</p>
          <p className="text-xs break-all">Rolle: {group.role}</p><p className="text-sm flex items-center gap-1"><ClockIcon className="h-4 w-4" />Maximal {durationText(maximum)}</p>
          {group.role === 'admin' && <p className="text-xs">Volle Adminrechte. Aktivierung nur nach unabhängiger Freigabe.</p>}
          {current?.expiresAt && <p className="text-sm">Aktiv bis {time(current.expiresAt)} · noch {Math.max(0, Math.ceil((Date.parse(current.expiresAt) - now) / 60000))} Minuten</p>}
          <div className="flex flex-wrap gap-2">
            {group.enabled && eligibility && !current && <button className="fluent-btn-primary" disabled={busy || !!pending} onClick={() => begin({ kind: 'request', group: { ...group, maxDurationSeconds: maximum }, eligibilityId: eligibility.id })}>Aktivierung anfordern</button>}
            {group.enabled && current?.status === 'approved' && <button className="fluent-btn-primary" disabled={busy || !!pending} onClick={() => setPending({ kind: 'change', group, request: current, action: 'activate' })}>Jetzt aktivieren</button>}
            {current && <button className="fluent-btn-secondary" disabled={busy || !!pending} onClick={() => setPending({ kind: 'change', group, request: current, action: 'cancel' })}>{current.status === 'active' ? 'Aktivierung beenden' : 'Antrag zurückziehen'}</button>}
            <button className="fluent-btn-secondary" disabled={busy || !!pending} onClick={() => setDetail({ kind: 'history', group, page: 1 })}><DocumentTextIcon className="h-4 w-4" />Protokoll</button>
            {management && group.canManage && <>
              {group.enabled && <button className="fluent-btn-secondary" disabled={busy || !!pending} onClick={() => begin({ kind: 'assign', group })}>Benutzer zuweisen</button>}
              <button className="fluent-btn-secondary" disabled={busy || !!pending} onClick={() => setDetail({ kind: 'members', group, page: 1 })}>Berechtigte Benutzer</button>
              {group.enabled && <button className="fluent-btn-secondary" disabled={busy || !!pending} onClick={() => begin({ kind: 'disable', group })}>Gruppe deaktivieren</button>}
            </>}
          </div>
        </article>;
      })}</div>
      {state.queue.filter(item => state.bindings.some(binding => binding.eligibilityId === item.eligibilityId)).length > 0 && <section className="space-y-3"><h3 className="font-semibold">Freigaben und aktive Gruppen</h3>
        {state.queue.filter(item => state.bindings.some(binding => binding.eligibilityId === item.eligibilityId)).map(item => {
          const binding = state.bindings.find(value => value.eligibilityId === item.eligibilityId); const group = state.groups.find(value => value.id === binding?.groupId); if (!group) return null;
          const reviewable = state.roles.find(value => value.role === item.role)?.reviewable && item.userId !== state.userId;
          return <div key={item.id} className="rounded border border-[var(--border)] p-3 text-sm"><p>{group.name} · {labels[item.status]} · Benutzer {item.userId}</p><p>{item.reason} · {durationText(item.durationSeconds)}</p>
            {reviewable && item.status === 'pending' && <div className="flex gap-2 mt-2">{(['approve', 'deny'] as const).map(action => <button className="fluent-btn-secondary" disabled={busy || !!pending} key={action} onClick={() => setPending({ kind: 'change', group, request: item, action })}>{action === 'approve' ? 'Genehmigen' : 'Ablehnen'}</button>)}</div>}
            {reviewable && item.status === 'active' && <button className="fluent-btn-secondary mt-2" disabled={busy || !!pending} onClick={() => setPending({ kind: 'change', group, request: item, action: 'revoke' })}>Aktivierung widerrufen</button>}
          </div>;
        })}</section>}
    </>}
    {form && state && <form onSubmit={capture} className="od-panel space-y-3"><h3 className="font-semibold">{form.kind === 'request' ? 'Aktivierungsantrag' : form.kind === 'assign' ? 'Benutzer für PIM berechtigen' : form.kind === 'create' ? 'Neue PIM-Gruppe' : 'Gruppe und ihre aktiven Rechte deaktivieren'}{'group' in form ? ': ' + form.group.name : ''}</h3>
      {form.kind === 'create' && <><label className="block">Gruppenname<input className="fluent-input" required minLength={2} maxLength={80} value={name} onChange={event => setName(event.target.value)} /></label>
        <label className="block">Beschreibung<input className="fluent-input" maxLength={500} value={description} onChange={event => setDescription(event.target.value)} /></label>
        <label className="block">Zugeordnete Rolle<select className="fluent-input" required value={role} onChange={event => setRole(event.target.value)}>{state.roles.filter(item => item.assignable).map(item => <option key={item.role} value={item.role}>{item.role}</option>)}</select></label></>}
      {form.kind === 'assign' && <>
        {users.length > 0 && <label className="block">Benutzer auswählen<select className="fluent-input" value={users.some(user => user.id === userId) ? userId : ''} onChange={event => setUserId(event.target.value)}><option value="">Verzeichnisbenutzer auswählen …</option>{users.map(user => <option key={user.id} value={user.id} disabled={user.id === state.userId}>{userName(user)} · {user.username}{user.id === state.userId ? ' · eigene Zuweisung benötigt anderen Administrator' : ''}</option>)}</select></label>}
        <label className="block">Verzeichnis-ID des Benutzers<input className="fluent-input" required pattern="[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}" value={userId} onChange={event => setUserId(event.target.value)} /></label>
        <p className="text-sm">Die Zuweisung berechtigt zur Beantragung und erteilt noch keine aktiven Rechte. <a className="underline" href="/users">Benutzerverwaltung öffnen</a></p>
        <label className="block">Berechtigung gültig für Tage<input className="fluent-input" type="number" min={1} max={30} required value={days} onChange={event => setDays(Number(event.target.value))} /></label>
      </>}
      {form.kind !== 'disable' && <label className="block">{form.kind === 'assign' ? 'Maximale Aktivierungsdauer' : form.kind === 'create' ? 'Gruppenlimit' : 'Gewünschte Dauer'}<select className="fluent-input" value={seconds} onChange={event => setSeconds(Number(event.target.value))}>
        {Array.from(new Set([Math.min(3600, 'group' in form ? form.group.maxDurationSeconds : 36000), ...durations.filter(value => value <= ('group' in form ? form.group.maxDurationSeconds : 36000))])).sort((a, b) => a - b).map(value => <option key={value} value={value}>{durationText(value)}</option>)}
      </select></label>}
      <label className="block">Begründung<textarea className="fluent-input" required minLength={10} maxLength={500} value={reason} onChange={event => setReason(event.target.value)} /></label>
      <div className="flex gap-3"><button className="fluent-btn-primary" disabled={busy || !!pending || reason.trim().length < 10 || form.kind === 'assign' && userId === state.userId}>Vorgang prüfen</button><button type="button" className="fluent-btn-secondary" disabled={busy} onClick={() => setForm(null)}>Abbrechen</button></div>
    </form>}
    {detail && <section className="od-panel space-y-3" aria-label={detail.kind === 'history' ? 'PIM-Protokoll' : 'PIM-Gruppenzuweisungen'}><div className="flex justify-between gap-2"><h3 className="font-semibold">{detail.group.name} · {detail.kind === 'history' ? 'Protokoll' : 'Berechtigte Benutzer'}</h3><button className="fluent-btn-secondary" onClick={() => setDetail(null)}>Schließen</button></div>
      {!detailReady ? <p role="status">Daten werden geprüft …</p> : <>
        {detail.kind === 'history' ? <><p className="text-sm">Unveränderbare PIM-Vorgänge mit Person, Begründung, Zeit und geplantem Ende. Ohne Leseberechtigung für fremde Anträge werden nur eigene Vorgänge angezeigt.</p>
          {!events.length && <p>Keine PIM-Vorgänge vorhanden.</p>}{events.map(event => <div key={event.id} className="border-b border-[var(--border)] py-2 text-sm"><p>{labels[event.action]} · {time(event.createdAt)}</p><p>{event.userId ? 'Benutzer ' + event.userId : 'Gruppenkonfiguration'} · Ausgeführt von {event.actorUserId || 'System'}</p><p>{event.reason}</p>{event.expiresAt && <p>Geplantes Ende: {time(event.expiresAt)}</p>}</div>)}</> : <>
          {!members.length && <p>Keine Benutzer zugewiesen.</p>}{members.map(member => <div key={member.eligibilityId} className="border-b border-[var(--border)] py-2 text-sm"><p>{member.name} · {member.userId}</p><p>{member.revoked ? 'Entzogen' : Date.parse(member.expiresAt) <= now ? 'Abgelaufen' : 'Berechtigt'} · bis {time(member.expiresAt)}</p>
            {!member.revoked && Date.parse(member.expiresAt) > now && <button className="fluent-btn-secondary" disabled={busy || !!pending} onClick={() => setPending({ kind: 'revoke-eligibility', group: detail.group, eligibilityId: member.eligibilityId, userId: member.userId })}>Berechtigung entziehen</button>}</div>)}</>}
        <div className="flex items-center gap-3"><button className="fluent-btn-secondary" disabled={detail.page <= 1 || busy} onClick={() => setDetail({ ...detail, page: detail.page - 1 })}>Vorherige Seite</button><span>Seite {detail.page} · {total} Einträge</span><button className="fluent-btn-secondary" disabled={detail.page * 25 >= total || busy} onClick={() => setDetail({ ...detail, page: detail.page + 1 })}>Nächste Seite</button></div>
      </>}
    </section>}
    {pending && <DirectoryConfirmation title="PIM-Vorgang bestätigen" busy={busy} error="" onClose={() => setPending(null)} onConfirm={perform}>
      <p>{pending.kind === 'change' ? `${pending.group.name}: ${pending.action === 'activate' ? 'Rolle zeitlich aktivieren. Danach ist eine neue Anmeldung erforderlich.' : pending.action === 'approve' ? 'Antrag unabhängig genehmigen.' : pending.action === 'deny' ? 'Antrag ablehnen.' : 'Aktivierung beziehungsweise Antrag beenden.'}`
        : pending.kind === 'request' ? `${pending.group.name} für ${durationText(pending.body.durationSeconds)} beantragen. Eine unabhängige Genehmigung ist erforderlich.`
          : pending.kind === 'assign' ? `${pending.body.userId} für ${pending.group.name} berechtigen. Aktive Rechte entstehen erst nach Freigabe und Aktivierung.`
            : pending.kind === 'create' ? `Gruppe ${pending.body.name} mit Rolle ${pending.body.role} erstellen.`
              : pending.kind === 'disable' ? `${pending.group.name} deaktivieren und alle laufenden Gruppenberechtigungen entziehen.`
                : pending.kind === 'revoke-eligibility' ? `Gruppenberechtigung für ${pending.userId} entziehen. Aktive Rollen aus dieser Berechtigung enden ebenfalls.` : 'Die Standardgruppen anlegen. Es werden keine Benutzer berechtigt und keine Rechte aktiviert.'}</p>
      {'body' in pending && <p className="mt-3">Begründung: {pending.body.reason}</p>}
      {pending.kind === 'change' && <p className="mt-3">Benutzer: {pending.request.userId} · {pending.request.reason}</p>}
    </DirectoryConfirmation>}
  </section>;
}
