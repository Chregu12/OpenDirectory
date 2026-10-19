'use client';

import React, { useEffect, useRef, useState } from 'react';
import { DirectoryAccess } from '@/lib/directoryUsers';
import { canonicalRoleUser } from '@/lib/directoryRoles';
import { authenticationRole } from '@/lib/roleAuthentication';
import { roleReviews, RoleReview, RoleReviewPolicy, RoleReviewPolicyPage, ReviewPolicyInput, roleReviewError } from '@/lib/roleReviews';
import { startLogin } from '@/lib/auth';

const field='w-full rounded border border-[var(--border)] bg-[var(--bg-surface-raised)] p-2';
const button='rounded border border-[var(--border)] px-3 py-2 disabled:opacity-40';
const labels={ pending:'Offen',scheduled:'Nächste Prüfung geplant',expired:'Prüffrist abgelaufen',denied:'Vergabe entzogen',exempt:'Wiederholung unabhängig beendet',obsolete:'Vergabe nicht mehr wirksam' };
type Action={ kind:'create'; input:ReviewPolicyInput } | { kind:'retire'; policy:RoleReviewPolicy } | { kind:'decide'; review:RoleReview; decision:'retain' | 'revoke' };
export default function RoleReviewsView({ access }:{ access:DirectoryAccess }) {
  const manage=access.permissions.includes('reviews.policies.manage'); const readPolicy=access.permissions.includes('reviews.policies.read');
  const assigned=access.permissions.includes('reviews.assigned.read'); const readReview=assigned || access.permissions.includes('reviews.all.read');
  const decide=access.permissions.includes('reviews.decide');
  const [input,setInput]=useState(''); const [target,setTarget]=useState(''); const [page,setPage]=useState<RoleReviewPolicyPage | null>(null);
  const [reviewInput,setReviewInput]=useState(''); const [reviewId,setReviewId]=useState(''); const [known,setKnown]=useState<RoleReview | null>(null);
  const [queue,setQueue]=useState<RoleReview[]>([]); const [truncated,setTruncated]=useState(false); const [attempt,setAttempt]=useState(0);
  const [interval,setInterval]=useState(86400); const [window,setWindow]=useState(3600); const [reviewers,setReviewers]=useState(''); const [reason,setReason]=useState('');
  const [action,setAction]=useState<Action | null>(null); const [confirmationReason,setConfirmationReason]=useState(''); const [acknowledged,setAcknowledged]=useState(false);
  const [busy,setBusy]=useState(false); const [error,setError]=useState(''); const [mutationError,setMutationError]=useState(''); const [notice,setNotice]=useState('');
  const context=`${access.subject}:${access.userId}:${[...access.permissions].sort().join(',')}:${target}:${reviewId}`;
  const current=useRef(context); current.current=context;
  useEffect(()=>{ setAction(null); setNotice(''); setMutationError(''); },[context]);
  useEffect(()=>{
    setPage(null); setError(''); if(!readPolicy || !target)return;
    let active=true; const controller=new AbortController();
    roleReviews.policy(target,controller.signal).then(value=>{ if(active)setPage(value); }).catch(failure=>{ if(active)setError(roleReviewError(failure)); });
    return ()=>{ active=false; controller.abort(); };
  },[context,attempt,readPolicy,target]);
  useEffect(()=>{
    setQueue([]); setTruncated(false); if(!assigned || !access.userId)return;
    let active=true; const controller=new AbortController();
    roleReviews.self(access.userId,controller.signal).then(value=>{ if(active){ setQueue(value.reviews); setTruncated(value.truncated); } }).catch(failure=>{ if(active)setError(roleReviewError(failure)); });
    return ()=>{ active=false; controller.abort(); };
  },[assigned,access.userId,access.subject,context,attempt]);
  useEffect(()=>{
    setKnown(null); if(!readReview || !reviewId)return;
    let active=true; const controller=new AbortController();
    roleReviews.get(reviewId,controller.signal).then(value=>{ if(active)setKnown(value); }).catch(failure=>{ if(active)setError(roleReviewError(failure)); });
    return ()=>{ active=false; controller.abort(); };
  },[readReview,reviewId,context,attempt]);
  if(!readPolicy && !readReview)return null;
  function begin(next:Action) { setMutationError(''); setConfirmationReason(next.kind==='create' ? next.input.reason : ''); setAcknowledged(false); setAction(next); }
  async function save() {
    if(!action || !acknowledged || confirmationReason.trim().length<10 || busy || mutationError)return;
    if(action.kind==='create' && (!manage || !page?.canCreate) || action.kind==='retire' && (!manage || !action.policy.canRetire)
      || action.kind==='decide' && (!decide || !action.review.canDecide))return;
    const pending=action; const operationContext=context; setBusy(true);
    try {
      if(pending.kind==='create') {
        const result=await roleReviews.create({ ...pending.input,reason:confirmationReason.trim() });
        if(current.current===operationContext){ setPage({ role:result.role,policy:result,canCreate:false,requiresFreshMfa:false }); setNotice('Prüfrichtlinie bestätigt. Betroffene Sitzungen müssen sich neu anmelden; fehlende Bestätigung beendet die betroffene Vergabe zur Frist.'); }
      } else if(pending.kind==='retire') {
        const result=await roleReviews.retire(pending.policy,confirmationReason.trim());
        if(current.current===operationContext){ setPage({ role:result.role,policy:result,canCreate:true,requiresFreshMfa:false }); setNotice('Neue Prüfbindungen beendet. Bestehende Fristen bleiben verbindlich; abgelaufene Rechte leben nicht wieder auf.'); }
      } else {
        const result=await roleReviews.decide(pending.review,{ decision:pending.decision,reason:confirmationReason.trim(),acknowledgeScope:true });
        if(current.current===operationContext){
          setQueue(rows=>rows.map(row=>row.id===result.id ? result : row)); setKnown(before=>before?.id===result.id ? result : before);
          setNotice(result.state==='denied' ? 'Konkrete Vergabe entzogen. Andere Vergaben können weiterhin Zugriff gewähren.' : result.state==='exempt' ? 'Bestehende Vergabe unabhängig bestätigt; nach beendeter Richtlinie keine weitere Wiederholung. Die Basislaufzeit bleibt unverändert.' : 'Bestehende Vergabe bestätigt; nächste Prüfung geplant. Keine neue Rolle und keine verlängerte Basislaufzeit.');
        }
      }
      if(current.current===operationContext){ setAction(null); setReason(''); setAcknowledged(false); }
    } catch(failure) { if(current.current===operationContext)setMutationError(roleReviewError(failure)); }
    finally { setBusy(false); }
  }
  function item(row:RoleReview) {
    return <article key={row.id} className="border border-[var(--border)] rounded p-3 space-y-2" aria-label={'Zugriffsprüfung '+row.id}>
      <h3>{row.role} · {labels[row.state]}</h3><p className="break-all">{row.targetKind==='assignment' ? 'Aktive Vergabe' : 'PIM-Berechtigung'}: {row.targetId} · Benutzer-ID: {row.userId}</p>
      <p className="break-all">Prüfung {row.id} · Zyklus {row.cycle} · Version {row.version} · Richtlinie {row.policyVersion}</p>
      <p>Prüfbeginn: {row.dueAt || 'Keine Wiederholung'} · Entzug spätestens: {row.deadlineAt || 'Nur bisherige Basislaufzeit'} · Basisablauf: {row.baseExpiresAt || 'Unbefristete Basisvergabe'}</p>
      {row.selfReview && <p>Eigene Vergabe: keine Selbstprüfung.</p>}
      {row.policyRetired && <p>Richtlinie beendet. Eine rechtzeitige Bestätigung beendet auch weitere Prüffristen; sie erneuert die Basisvergabe nicht.</p>}
      {row.requiresFreshMfa && <button className={button} onClick={startLogin}>Für unabhängige Prüfung neu anmelden</button>}
      {decide && row.canDecide && <div className="flex gap-3"><button className={button} disabled={busy || !!action} onClick={()=>begin({ kind:'decide',review:row,decision:'retain' })}>Vergabe behalten prüfen</button><button className={button} disabled={busy || !!action} onClick={()=>begin({ kind:'decide',review:row,decision:'revoke' })}>Vergabe entziehen prüfen</button></div>}
    </article>;
  }
  return <section aria-label="Wiederkehrende Rollenprüfungen" className="border border-[var(--border)] rounded p-4 space-y-4">
    <h2 className="text-lg font-semibold">Wiederkehrende Zugriffsprüfungen</h2>
    <p>Quelle: kanonische aktive Rollen und PIM-Berechtigungen. Unbeantwortete Fristen entziehen wirksame Rechte auch ohne Hintergrunddienst. Eine Bestätigung verlängert keine Basisvergabe; Selbstprüfung ist verboten.</p>
    <button className={button} disabled={busy || !!action} onClick={()=>{ setAction(null); setError(''); setAttempt(value=>value+1); }}>Prüfstand neu laden</button>
    {notice && <p role="status">{notice}</p>}{error && <p role="alert">{error}</p>}
    {readPolicy && <div className="space-y-3"><form className="flex gap-3" onSubmit={event=>{ event.preventDefault(); try { setTarget(authenticationRole(input.trim())); setAttempt(value=>value+1); } catch(failure){ setError(roleReviewError(failure)); } }}>
      <label className="grow">Kanonische Rolle für Zugriffsprüfung<input className={field} required disabled={busy} value={input} onChange={event=>setInput(event.target.value)} /></label><button className={button} disabled={busy}>Prüfrichtlinie laden</button>
    </form>
    {page && <div className="space-y-3"><h3>{page.role}</h3>
      {!page.policy && <p>Keine Prüfrichtlinie eingerichtet.</p>}
      {page.policy && <><p>{page.policy.retiredAt ? 'Richtlinie beendet' : 'Prüfrichtlinie aktiv'} · Version {page.policy.version} · Wiederholung alle {page.policy.intervalSeconds} Sekunden · Prüffenster {page.policy.windowSeconds} Sekunden</p>
        <p className="break-all">Benannte Prüfer: {page.policy.reviewerUserIds.join(', ')}</p>
        {manage && page.policy.canRetire && <button className={button} disabled={busy || !!action} onClick={()=>begin({ kind:'retire',policy:page.policy! })}>Prüfrichtlinie beenden prüfen</button>}</>}
      {(page.requiresFreshMfa || page.policy?.requiresFreshMfa) && <button className={button} onClick={startLogin}>Für Prüfrichtlinie neu anmelden</button>}
      {manage && page.canCreate && <form className="grid gap-3 max-w-2xl" onSubmit={event=>{ event.preventDefault(); try { begin({ kind:'create',input:{ role:target,intervalSeconds:interval,windowSeconds:window,reviewerUserIds:reviewers.split(/\s+/).filter(Boolean).map(canonicalRoleUser).sort(),reason:reason.trim(),acknowledgeDeadlines:true } }); } catch(failure){ setError(roleReviewError(failure)); } }}>
        <label>Prüfintervall in Sekunden<input className={field} type="number" min={3600} max={31536000} required disabled={busy} value={interval} onChange={event=>setInterval(Number(event.target.value))} /></label>
        <label>Prüffenster in Sekunden<input className={field} type="number" min={60} max={Math.min(604800,interval-1)} required disabled={busy} value={window} onChange={event=>setWindow(Number(event.target.value))} /></label>
        <label>Prüfer-UUIDs (eine je Zeile)<textarea className={field} required maxLength={740} disabled={busy} value={reviewers} onChange={event=>setReviewers(event.target.value)} /></label>
        <label>Begründung der Prüfrichtlinie<textarea className={field} required minLength={10} maxLength={500} disabled={busy} value={reason} onChange={event=>setReason(event.target.value)} /></label><button className={button} disabled={busy || !!action}>Prüfrichtlinie anlegen prüfen</button>
      </form>}
    </div>}</div>}
    {readReview && <form className="flex gap-3" onSubmit={event=>{ event.preventDefault(); try { setReviewId(canonicalRoleUser(reviewInput.trim())); setAttempt(value=>value+1); } catch(failure){ setError(roleReviewError(failure)); } }}><label className="grow">Bekannte Prüfungs-ID<input className={field} required disabled={busy} value={reviewInput} onChange={event=>setReviewInput(event.target.value)} /></label><button className={button} disabled={busy}>Zugriffsprüfung laden</button></form>}
    {known && item(known)}
    {assigned && <div className="space-y-3"><h3>Mir zugewiesene Prüfungen</h3>{!queue.length && <p>Keine zugewiesenen Prüfungen geladen.</p>}{truncated && <p>Auf 100 Prüfungen begrenzt; offene Fristen zuerst.</p>}{queue.map(item)}</div>}
    {action && <form role="alertdialog" aria-label="Zugriffsprüfung bestätigen" className="border rounded p-4 space-y-3" onSubmit={event=>{ event.preventDefault(); void save(); }}>
      <h3>{action.kind==='create' ? 'Prüfrichtlinie aktivieren' : action.kind==='retire' ? 'Prüfrichtlinie beenden' : action.decision==='retain' ? 'Bestehende Vergabe bestätigen' : 'Konkrete Vergabe entziehen'}</h3>
      <p className="break-all">{action.kind==='decide' ? `${action.review.role} · ${action.review.userId} · ${action.review.targetKind} ${action.review.targetId}` : action.kind==='create' ? `${action.input.role} · alle aktuellen und neuen Vergaben · ${action.input.reviewerUserIds.join(', ')}` : `${action.policy.role} · Richtlinie ${action.policy.id}`}</p>
      <p>{action.kind==='create' ? 'Die erste Frist beginnt sofort. Ohne unabhängige Antwort wird Zugriff unwirksam; auch eigene Sitzungen können ungültig werden. Prüfer und kontrollierten Wiederherstellungsweg vorher sicherstellen.' : action.kind==='retire' ? 'Neue Bindungen enden. Bestehende Fristen bleiben verbindlich; abgelaufene Vergaben werden nicht wiederhergestellt.' : action.decision==='revoke' ? 'Nur diese konkrete Vergabe wird widerrufen. Eine PIM-Berechtigung entzieht auch ihre abgeleiteten Aktivierungen; andere unabhängige Quellen können verbleiben.' : action.review.policyRetired ? 'Die Richtlinie ist beendet. Diese rechtzeitige Bestätigung beendet weitere Prüfungen; die bisherige Basislaufzeit bleibt verbindlich.' : 'Nur die bestehende Vergabe bestätigen. Keine neue Rolle, keine verlängerte Basislaufzeit; die nächste Prüfung bleibt verbindlich.'}</p>
      <label>Begründung der Bestätigung<textarea className={field} required minLength={10} maxLength={500} disabled={busy} value={confirmationReason} onChange={event=>setConfirmationReason(event.target.value)} /></label>
      <label><input type="checkbox" required disabled={busy} checked={acknowledged} onChange={event=>setAcknowledged(event.target.checked)} /> Ziel, Fristen und unabhängige Wirkung geprüft</label>
      {mutationError && <p role="alert">{mutationError}</p>}<button className={button} disabled={busy || !acknowledged || !!mutationError}>Zugriffsprüfung verbindlich bestätigen</button>
      <button className={button} type="button" disabled={busy} onClick={()=>{ setAction(null); setAttempt(value=>value+1); }}>Schließen und Prüfstand laden</button>
    </form>}
  </section>;
}
