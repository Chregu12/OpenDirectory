'use client';

import React, { useEffect, useRef, useState } from 'react';
import { DirectoryAccess } from '@/lib/directoryUsers';
import { authenticationRole } from '@/lib/roleAuthentication';
import { privilegedAccessPolicy, privilegedPolicyError, PrivilegedAccessPolicy, PrivilegedAccessChange } from '@/lib/privilegedAccessPolicy';
import { startLogin } from '@/lib/auth';

const field = 'w-full rounded border border-[var(--border)] bg-[var(--bg-surface-raised)] p-2';
const button = 'rounded border border-[var(--border)] px-3 py-2 disabled:opacity-40';
export default function PrivilegedAccessPolicyView({ access }: { access: DirectoryAccess }) {
  const readable = access.permissions.includes('pim.policies.read'); const manageable = access.permissions.includes('pim.policies.manage');
  const [input,setInput] = useState(''); const [target,setTarget] = useState(''); const [attempt,setAttempt] = useState(0);
  const [page,setPage] = useState<PrivilegedAccessPolicy | null>(null); const [error,setError] = useState(''); const [busy,setBusy] = useState(false);
  const [required,setRequired] = useState(false); const [duration,setDuration] = useState(3600); const [reason,setReason] = useState('');
  const [reviewers,setReviewers] = useState('');
  const [pending,setPending] = useState<PrivilegedAccessChange | null>(null); const [acknowledged,setAcknowledged] = useState(false);
  const [mutationError,setMutationError] = useState(''); const [notice,setNotice] = useState('');
  const context = `${target}:${access.subject}:${access.userId}:${readable}:${manageable}`;
  const current = useRef(context); current.current = context;
  useEffect(() => {
    setPage(null); setPending(null); setNotice(''); setError(''); setMutationError(''); setAcknowledged(false);
    if (!readable || !target) return;
    let active = true; const controller = new AbortController();
    privilegedAccessPolicy.get(target,controller.signal).then(value => { if (active) { setPage(value); setRequired(value.required); setDuration(value.maxDurationSeconds); setReviewers(value.reviewerUserIds.join('\n')); setReason(''); } })
      .catch(failure => { if (active) setError(privilegedPolicyError(failure)); });
    return () => { active = false; controller.abort(); };
  },[readable,manageable,access.subject,access.userId,target,attempt]);
  if (!readable) return null;
  async function save() {
    if (!manageable || !page?.canManage || !pending || !acknowledged || busy || mutationError) return;
    const before = page; const change = pending; const operationContext = context; setBusy(true);
    try {
      const result = await privilegedAccessPolicy.change(before,change);
      if (current.current === operationContext) {
        setPage(result); setRequired(result.required); setDuration(result.maxDurationSeconds); setReviewers(result.reviewerUserIds.join('\n')); setPending(null); setReason(''); setAcknowledged(false);
        setNotice(`PIM-Richtlinie für ${before.role} bestätigt. Vorherige Rollenvergaben und Anträge sind nicht mehr wirksam.`);
      }
    } catch (failure) { if (current.current === operationContext) setMutationError(privilegedPolicyError(failure)); }
    finally { setBusy(false); }
  }
  return <section className="space-y-4 border border-[var(--border)] rounded p-4" aria-label="Verbindliche PIM-Richtlinien">
    <h2 className="text-lg font-semibold">PIM-Pflicht statt dauerhafter Rechte</h2>
    <p>Bei verbindlicher PIM-Aktivierung sind direkte Rollenvergaben verboten – auch für globale Administratoren. Es gelten unabhängige Genehmigung, frische MFA und eine begrenzte Aktivierungsdauer.</p>
    <form className="flex gap-3" onSubmit={event => { event.preventDefault(); try { setTarget(authenticationRole(input.trim())); setAttempt(value => value+1); } catch (failure) { setError(privilegedPolicyError(failure)); } }}>
      <label className="grow">Kanonische Rolle für PIM-Richtlinie<input className={field} required disabled={busy} value={input} onChange={event => setInput(event.target.value)} /></label>
      <button className={button} disabled={busy}>PIM-Richtlinie laden</button>
    </form>
    {notice && <p role="status">{notice}</p>}{error && <p role="alert">{error}</p>}
    {page && <div className="space-y-3"><h3>{page.role} · Version {page.version}</h3>
      <p role="status">{page.required ? 'Nur unabhängig genehmigte PIM-Aktivierung erlaubt.' : 'Direkte administrative Rollenvergaben weiterhin erlaubt.'} PIM maximal {page.maxDurationSeconds} Sekunden.</p>
      {page.protected && <p>Geschützte Rolle: Änderungen nur durch globale Administration.</p>}
      {page.reviewerUserIds.length>0 && <p>Ausdrücklich benannte Genehmiger: {page.reviewerUserIds.join(', ')}. Aktuelle PIM-Prüfrechte, frische MFA und unabhängige Identität bleiben erforderlich.</p>}
      {page.locked && <p>Die Basisrolle user bleibt von der PIM-Pflicht ausgenommen.</p>}
      {manageable && page.requiresFreshMfa && <p>Für Änderungen frisch mit Passwort und OpenDirectory-TOTP anmelden. <button className={button} onClick={startLogin}>Für PIM-Richtlinie neu anmelden</button></p>}
      {manageable && page.canManage && !pending && <form className="grid gap-3 max-w-2xl" onSubmit={event => { event.preventDefault(); setMutationError(''); setAcknowledged(false); const selected=required && page.protected ? reviewers.split(/\s+/).filter(Boolean).sort() : []; setPending({ required,maxDurationSeconds:duration,reviewerUserIds:selected,reason:reason.trim(),acknowledgeInvalidation:true }); }}>
        <label><input type="checkbox" disabled={busy} checked={required} onChange={event => setRequired(event.target.checked)} /> PIM-Aktivierung verbindlich verlangen</label>
        <label>Maximale PIM-Aktivierungsdauer in Sekunden<input className={field} type="number" min={60} max={28800} required disabled={busy} value={duration} onChange={event => setDuration(Number(event.target.value))} /></label>
        {page.protected && required && <label>Unabhängige Genehmiger (kanonische UUIDs, eine je Zeile)<textarea className={field} required={page.role==='admin'} disabled={busy} maxLength={740} value={reviewers} onChange={event => setReviewers(event.target.value)} /><span>Für admin ist mindestens ein aktiver, vom Ändernden verschiedener PIM-Genehmiger nötig. Berechtigungen und eigene MFA vor dem Umstellen vorbereiten.</span></label>}
        <label>Begründung der PIM-Richtlinie<textarea className={field} required minLength={10} maxLength={500} disabled={busy} value={reason} onChange={event => setReason(event.target.value)} /></label>
        <button className={button} disabled={busy}>PIM-Richtlinie prüfen</button>
      </form>}
      {(!manageable || !page.canManage && !page.requiresFreshMfa) && <p>PIM-Richtlinie nur lesbar.</p>}
    </div>}
    {pending && page && <div role="alertdialog" aria-label="PIM-Richtlinie bestätigen" className="space-y-3 border rounded p-4">
      <p>{page.role}: PIM {pending.required ? 'verbindlich' : 'nicht verbindlich'}, maximal {pending.maxDurationSeconds} Sekunden.</p><p>{pending.reason}</p>
      {!!pending.reviewerUserIds?.length && <p>Benannte Genehmiger: {pending.reviewerUserIds.join(', ')}</p>}
      <p>Jede Änderung entzieht alle bisherigen direkten und aktivierten Vergaben dieser Rolle und macht frühere Anträge ungültig. Auch bei späterer Lockerung leben sie nicht wieder auf. Die eigene Sitzung kann ausfallen. Vorher unabhängige Berechtigungen, Genehmiger und einen kontrollierten Wiederherstellungsweg sicherstellen.</p>
      <label><input type="checkbox" checked={acknowledged} disabled={busy} onChange={event => setAcknowledged(event.target.checked)} /> Rechteentzug und Wiederherstellung geprüft</label>
      {mutationError && <p role="alert">{mutationError}</p>}<button className={button} disabled={busy || !acknowledged || !!mutationError} onClick={() => void save()}>PIM-Richtlinie verbindlich speichern</button>
      <button className={button} disabled={busy} onClick={() => { setPending(null); setAttempt(value => value+1); }}>Schließen und PIM-Stand prüfen</button>
    </div>}
  </section>;
}
