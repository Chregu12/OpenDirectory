'use client';
import React, { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { useIdentityAccess } from '@/hooks/useIdentityAccess';
import { canonicalRoleUser } from '@/lib/directoryRoles';
import { ActivationRequest, Eligibility, PIMAction, PIMSelf, PIMCatalogRole, privilegedActivation, pimError } from '@/lib/privilegedActivation';
import { ensureSession, startLogin } from '@/lib/auth';
import { DirectoryConfirmation } from './UserDetailPanel';
import PrivilegedAccessPolicyView from './PrivilegedAccessPolicyView';

const labels = { eligible: 'Berechtigt, nicht aktiv', pending: 'Ausstehend', approved: 'Genehmigt, noch nicht aktiv', active: 'Aktiv', denied: 'Abgelehnt', cancelled: 'Abgebrochen', revoked: 'Widerrufen', expired: 'Abgelaufen', stale: 'Berechtigung geändert' };
type Action = { kind: 'request'; body: { id: string; eligibilityId: string; durationSeconds: number; reason: string } }
  | { kind: 'eligibility'; body: { userId: string; role: string; maxDurationSeconds: number; validForSeconds: number; reason: string } }
  | { kind: 'eligibility-revoke'; eligibility: Eligibility } | { kind: 'change'; request: ActivationRequest; action: PIMAction };

export default function PIMView() {
  const { access, can, unavailable, reload: reloadAccess } = useIdentityAccess();
  const [self, setSelf] = useState<PIMSelf | null>(null); const [catalog, setCatalog] = useState<PIMCatalogRole[]>([]); const [queue, setQueue] = useState<ActivationRequest[]>([]);
  const [attempt, setAttempt] = useState(0); const [error, setError] = useState(''); const [action, setAction] = useState<Action | null>(null); const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState(''); const [freshLogin, setFreshLogin] = useState(false);
  const [eligibilityId, setEligibilityId] = useState(''); const [duration, setDuration] = useState(3600); const [explanation, setExplanation] = useState('');
  const [targetInput, setTargetInput] = useState(''); const [target, setTarget] = useState(''); const [managed, setManaged] = useState<Eligibility[]>([]);
  const [role, setRole] = useState(''); const [maxDuration, setMaxDuration] = useState(3600); const [validDays, setValidDays] = useState(7); const [managementReason, setManagementReason] = useState('');
  const refresh = () => { setSelf(null); setError(''); setAttempt(value => value + 1); };
  const begin = (next: Action) => { setMutationError(''); setFreshLogin(false); setAction(next); };
  useEffect(() => {
    setSelf(null); setQueue([]); setCatalog([]); setError(''); if (!access?.userId) return;
    let active = true; const controller = new AbortController();
    Promise.all([privilegedActivation.self(controller.signal), privilegedActivation.catalog(controller.signal),
      access.permissions.includes('pim.requests.read') ? privilegedActivation.queue(controller.signal) : Promise.resolve([])])
      .then(([own, roles, requests]) => { if (active) { if (own.userId !== access.userId) throw new Error('Mismatched canonical identity'); setSelf(own); setCatalog(roles); setQueue(requests); } })
      .catch(failure => { if (active) setError(pimError(failure)); });
    return () => { active = false; controller.abort(); };
  }, [access, attempt]);
  useEffect(() => {
    setManaged([]); if (!target || !access?.permissions.includes('pim.eligibilities.read')) return;
    let active = true; const controller = new AbortController();
    privilegedActivation.eligibilities(target, controller.signal).then(rows => { if (active) setManaged(rows); }).catch(failure => { if (active) setError(pimError(failure)); });
    return () => { active = false; controller.abort(); };
  }, [access, target, attempt]);

  async function perform() {
    if (!action || !self || busy) return; setBusy(true);
    try {
      let selfChanged = false;
      if (action.kind === 'request') { const created = await privilegedActivation.request(action.body); if (created.userId !== self.userId) throw new Error('Unconfirmed owner'); }
      else if (action.kind === 'eligibility') await privilegedActivation.grantEligibility(action.body);
      else if (action.kind === 'eligibility-revoke') await privilegedActivation.revokeEligibility(action.eligibility.id);
      else { const changed = await privilegedActivation.change(action.request.id, action.action); if (changed.userId !== action.request.userId || changed.role !== action.request.role) throw new Error('Unconfirmed target'); selfChanged = action.request.userId === self.userId && ['activate', 'cancel'].includes(action.action) && ['approved', 'active'].includes(action.request.status); }
      toast.success('PIM-Aktion bestätigt. Aktivierte Rechte erfordern eine neue Anmeldung.'); setAction(null); setExplanation(''); refresh();
      if (selfChanged) void ensureSession(true).catch(() => {});
    } catch (failure: any) { setMutationError(pimError(failure)); setFreshLogin(failure?.response?.status === 428); }
    finally { setBusy(false); }
  }
  function requests(rows: ActivationRequest[], review: boolean) {
    return <ul className="space-y-3">{rows.map(item => <li key={item.id} className="border border-white/15 p-3 rounded space-y-2" aria-label={'Antrag ' + item.id}>
      <h3 className="font-semibold">{item.role} · {labels[item.status]}</h3><p className="break-all">Antrag: {item.id} · Verzeichnis-ID: {item.userId}</p><p>{item.reason}</p>
      <p>Dauer: {item.durationSeconds / 60} Minuten · Antragsfrist: {item.deadlineAt}</p>
      {item.decidedBy && <p className="break-all">Entscheidung durch: {item.decidedBy}{item.approvalExpiresAt ? ` · Freigabe zur Aktivierung bis: ${item.approvalExpiresAt}` : ''}</p>}
      {item.expiresAt && <p>Aktive Zuweisung endet: {item.expiresAt}</p>}
      <div className="flex gap-4 flex-wrap">{!review && item.status === 'approved' && <button onClick={() => begin({ kind: 'change', request: item, action: 'activate' })}>Jetzt aktivieren</button>}
        {!review && ['pending', 'approved', 'active', 'stale', 'expired'].includes(item.status) && <button onClick={() => begin({ kind: 'change', request: item, action: 'cancel' })}>{item.status === 'active' ? 'Deaktivieren' : 'Antrag abbrechen'}</button>}
        {review && item.userId === self?.userId && <p>Keine eigene Genehmigung oder Ablehnung.</p>}
        {review && item.userId !== self?.userId && item.status === 'pending' && can('pim.requests.review') && catalog.some(entry => entry.role === item.role && entry.reviewable) && <>
          <button onClick={() => begin({ kind: 'change', request: item, action: 'approve' })}>Genehmigen</button><button onClick={() => begin({ kind: 'change', request: item, action: 'deny' })}>Ablehnen</button></>}
        {review && item.userId !== self?.userId && ['approved', 'active'].includes(item.status) && can('pim.activations.revoke') && catalog.some(entry => entry.role === item.role && entry.reviewable) && <button onClick={() => begin({ kind: 'change', request: item, action: 'revoke' })}>Aktivierung widerrufen</button>}
      </div>
    </li>)}</ul>;
  }
  if (unavailable) return <section className="p-8" role="alert">PIM-Berechtigungen nicht verfügbar. <button onClick={reloadAccess}>Erneut prüfen</button></section>;
  if (!access) return <p className="p-8" role="status">Berechtigungen werden geprüft …</p>;
  if (!access.userId) return <p className="p-8" role="alert">Eine bestätigte kanonische Anmelde-Verknüpfung ist erforderlich.</p>;
  return <section className="p-6 space-y-6 overflow-auto h-full" style={{ background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)' }}>
    <h1 className="text-xl font-semibold">Privilegierter Zugriff</h1><p>Quelle: kanonischer Verzeichnisdienst. Berechtigung, unabhängige Genehmigung und tatsächliche Aktivierung sind getrennte Schritte.</p>
    <p>Maximal acht Stunden, zusätzlich begrenzt durch Rollenrichtlinie und Berechtigungsfrist. Genehmigungen gelten fünf Minuten; Aktivierung verlangt eine höchstens fünf Minuten alte Anmeldung mit geprüftem OpenDirectory-TOTP.</p>
    <p>Direkte Vergaben sind nur ohne verbindliche PIM-Richtlinie erlaubt. Alte PIM-Gruppen, Aufzeichnungen und Break-Glass-Prototypen sind keine kanonischen Aktivierungen.</p>
    <PrivilegedAccessPolicyView access={access} />
    <button disabled={busy || !!action} onClick={refresh}>Neu laden</button>{error && <p role="alert">{error}</p>}
    {!self && !error && <p role="status">PIM-Zustand wird geladen …</p>}
    {self && !error && <fieldset disabled={busy || !!action} className="space-y-6"><section className="space-y-3"><h2 className="text-lg font-semibold">Meine Berechtigungen</h2>{self.truncated && <p>Anzeige auf die neuesten 100 Datensätze je Liste begrenzt.</p>}
      {!self.eligibilities.length && <p>Keine PIM-Berechtigung vorhanden.</p>}
      <ul>{self.eligibilities.map(item => <li key={item.id}>{item.role} · {labels[item.status]} · maximal {Math.min(item.maxDurationSeconds,catalog.find(entry => entry.role === item.role)?.maxDurationSeconds || 0) / 60} Minuten · bis {item.expiresAt}</li>)}</ul>
      {self.eligibilities.some(item => item.status === 'eligible') && <form className="space-y-3 max-w-xl" onSubmit={event => {
        event.preventDefault(); const eligible = self.eligibilities.find(item => item.id === eligibilityId && item.status === 'eligible');
        if (!eligible || duration > Math.min(eligible.maxDurationSeconds,catalog.find(entry => entry.role === eligible.role)?.maxDurationSeconds || 0)) return;
        begin({ kind: 'request', body: { id: crypto.randomUUID(), eligibilityId, durationSeconds: duration, reason: explanation } });
      }}><label htmlFor="pim-own-role">Eigene Berechtigung</label><select id="pim-own-role" className="block p-2 bg-gray-900 border" value={eligibilityId} required onChange={event => { setEligibilityId(event.target.value); const selected = self.eligibilities.find(item => item.id === event.target.value); setDuration(Math.min(3600, selected?.maxDurationSeconds || 3600,catalog.find(entry => entry.role === selected?.role)?.maxDurationSeconds || 0)); }}>
        <option value="">Berechtigung wählen</option>{self.eligibilities.filter(item => item.status === 'eligible').map(item => <option key={item.id} value={item.id}>{item.role} · {item.id}</option>)}</select>
        <label className="block">Dauer in Minuten<input className="block p-2 border bg-transparent" type="number" min={1} max={Math.min(self.eligibilities.find(item => item.id === eligibilityId)?.maxDurationSeconds || 28800,catalog.find(entry => entry.role === self.eligibilities.find(item => item.id === eligibilityId)?.role)?.maxDurationSeconds || 28800) / 60} required value={duration / 60} onChange={event => setDuration(Number(event.target.value) * 60)} /></label>
        <label className="block">Aktivierungsbegründung<textarea className="block p-2 border bg-transparent w-full" minLength={10} maxLength={500} required value={explanation} onChange={event => setExplanation(event.target.value)} /></label><button>Aktivierung beantragen</button>
      </form>}
    </section><section className="space-y-3"><h2 className="text-lg font-semibold">Meine Anträge und Aktivierungen</h2>{!self.requests.length && <p>Keine eigenen Anträge.</p>}{requests(self.requests, false)}</section>
    {can('pim.requests.read') && <section className="space-y-3"><h2 className="text-lg font-semibold">Genehmigungsübersicht</h2><p>Maximal 100 Datensätze; offene Anträge zuerst. Genehmigung ist noch kein aktives Recht. Die Autorität des Genehmigenden wird vor Aktivierung erneut geprüft.</p>{requests(queue, true)}</section>}
    {can('pim.eligibilities.read') && <section className="space-y-4"><h2 className="text-lg font-semibold">Berechtigungen verwalten</h2>
      <form className="flex gap-3 flex-wrap" onSubmit={event => { event.preventDefault(); setError(''); try { const next = canonicalRoleUser(targetInput.trim()); if (next === target) refresh(); else setTarget(next); } catch (failure: any) { setError(failure.message); } }}>
        <label>Verzeichnis-ID<input className="block border p-2 bg-transparent font-mono w-96 max-w-full" value={targetInput} onChange={event => setTargetInput(event.target.value)} required /></label><button>Berechtigungen laden</button></form>
      {target && <><p className="break-all">Ziel: {target}</p><ul>{managed.map(item => <li key={item.id} className="border border-white/15 p-3 space-y-2"><p>{item.role} · {labels[item.status]} · bis {item.expiresAt}</p><p>{item.reason}</p>
        {can('pim.eligibilities.manage') && target !== self.userId && item.status === 'eligible' && catalog.some(entry => entry.role === item.role && entry.assignable) && <button onClick={() => begin({ kind: 'eligibility-revoke', eligibility: item })}>Berechtigung widerrufen</button>}</li>)}</ul>
        {target === self.userId ? <p>Keine Selbstverwaltung eigener PIM-Berechtigungen.</p> : can('pim.eligibilities.manage') && <form className="space-y-3 max-w-xl" onSubmit={event => { event.preventDefault(); if (catalog.some(item => item.role === role && item.assignable)) begin({ kind: 'eligibility', body: { userId: target, role, maxDurationSeconds: maxDuration, validForSeconds: validDays * 86400, reason: managementReason } }); }}>
          <label htmlFor="pim-managed-role">Berechtigte Rolle</label><select id="pim-managed-role" className="block bg-gray-900 border p-2" value={role} onChange={event => setRole(event.target.value)} required><option value="">Rolle wählen</option>{catalog.map(item => <option key={item.role} value={item.role} disabled={!item.assignable}>{item.role}{item.protected ? ' · geschützt' : ''}</option>)}</select>
          <label className="block">Maximale Aktivierungsdauer in Minuten<input className="block p-2 border bg-transparent" type="number" min={1} max={480} value={maxDuration / 60} required onChange={event => setMaxDuration(Number(event.target.value) * 60)} /></label>
          <label className="block">Berechtigung gültig in Tagen<input className="block p-2 border bg-transparent" type="number" min={1} max={30} required value={validDays} onChange={event => setValidDays(Number(event.target.value))} /></label>
          <label className="block">Verwaltungsbegründung<textarea className="block p-2 border bg-transparent w-full" minLength={10} maxLength={500} required value={managementReason} onChange={event => setManagementReason(event.target.value)} /></label><button>Berechtigung prüfen</button>
        </form>}</>}
    </section>}</fieldset>}
    {action && <DirectoryConfirmation title="PIM-Aktion bestätigen" busy={busy} error={mutationError} onClose={() => { setAction(null); refresh(); }} onConfirm={() => void perform()}>
      <p className="break-all">{action.kind === 'change' ? `${action.action} · ${action.request.role} · Antrag ${action.request.id} · Verzeichnis-ID ${action.request.userId}` : action.kind === 'eligibility-revoke' ? `Berechtigung ${action.eligibility.id} für ${action.eligibility.userId} widerrufen` : action.kind === 'eligibility' ? `Berechtigung für ${action.body.userId} · ${action.body.role} · maximal ${action.body.maxDurationSeconds / 60} Minuten` : `Eigener Antrag für Berechtigung ${action.body.eligibilityId} · ${action.body.durationSeconds / 60} Minuten`}</p>
      <p>Erst die bestätigte Aktivierung schreibt eine kanonische Rolle. Aktivierung und Deaktivierung entziehen bestehenden Tokens an den angebundenen APIs den Zugriff; danach neu anmelden.</p>
      {freshLogin && <><p>Aktivierung erfordert eine höchstens fünf Minuten alte Anmeldung mit geprüftem OpenDirectory-TOTP. Falls noch nicht eingerichtet: <a href="/mfa">Eigene MFA einrichten</a>.</p><button onClick={startLogin}>Für Aktivierung neu anmelden</button></>}
    </DirectoryConfirmation>}
  </section>;
}
