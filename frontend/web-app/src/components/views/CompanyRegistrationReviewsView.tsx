'use client';

import React, { useEffect, useRef, useState } from 'react';
import { useIdentityAccess } from '@/hooks/useIdentityAccess';
import { companyRegistrationReviews, companyReviewError, RegistrationQueue, RegistrationReview, ReviewStatus } from '@/lib/companyRegistrationReviews';
import OrganizationProfileFields from '@/components/OrganizationProfileFields';

const labels = { 'pending-verification': 'Zur Prüfung', 'pending-activation': 'Freigegeben – Aktivierung ausstehend', rejected: 'Abgelehnt', active: 'Aktiviert', suspended: 'Gesperrt', all: 'Alle Anträge' };
export default function CompanyRegistrationReviewsView() {
  const { access, unavailable, reload } = useIdentityAccess(); const [queue, setQueue] = useState<RegistrationQueue | null>(null); const [selected, setSelected] = useState<RegistrationReview | null>(null);
  const [page, setPage] = useState(1); const [status, setStatus] = useState<ReviewStatus | 'all'>('pending-verification'); const [attempt, setAttempt] = useState(0);
  const [decision, setDecision] = useState<'' | 'approved' | 'rejected'>(''); const [reason, setReason] = useState(''); const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [success, setSuccess] = useState(''); const generation = useRef(0);
  const permitted = access?.companyRegistrationReviewProtocol === 1 && !access.demoMode && access.permissions.includes('company.registrations.review') && !!access.userId;
  useEffect(() => {
    const epoch = ++generation.current; const controller = new AbortController(); setQueue(null); setSelected(null); setDecision(''); setReason(''); setConfirmed(false); setBusy(false); setError(''); setSuccess('');
    if (permitted) companyRegistrationReviews.list(access!.userId!, page, status, controller.signal).then(result => { if (epoch === generation.current) setQueue(result); }).catch(failure => { if (epoch === generation.current) setError(companyReviewError(failure)); });
    return () => { generation.current++; controller.abort(); };
  }, [access, permitted, page, status, attempt]);
  useEffect(() => {
    const invalid = () => { generation.current++; setQueue(null); setSelected(null); setReason(''); setDecision(''); setConfirmed(false); setBusy(false); setSuccess(''); setError('Die Sitzung hat sich geändert. Bitte erneut anmelden und neu laden.'); };
    window.addEventListener('od:session-error', invalid); return () => window.removeEventListener('od:session-error', invalid);
  }, []);
  async function open(id: string) {
    if (!permitted || busy) return; const epoch = ++generation.current; setBusy(true); setSelected(null); setDecision(''); setReason(''); setConfirmed(false); setError(''); setSuccess('');
    try { const result = await companyRegistrationReviews.load(id, access!.userId!); if (epoch === generation.current) setSelected(result); }
    catch (failure) { if (epoch === generation.current) setError(companyReviewError(failure)); } finally { if (epoch === generation.current) setBusy(false); }
  }
  async function save(event: React.FormEvent) {
    event.preventDefault(); if (!selected?.canReview || !decision || !confirmed || busy) return; const epoch = generation.current; setBusy(true); setError(''); setSuccess('');
    try {
      const result = await companyRegistrationReviews.decide(selected, { decision, reason, confirm: true });
      if (epoch === generation.current) { setSelected(result); setQueue(null); setReason(''); setDecision(''); setConfirmed(false); setSuccess('Prüfentscheidung bestätigt. Mandant und Administrator bleiben gesperrt.'); }
    } catch (failure) { if (epoch === generation.current) { setSelected(null); setQueue(null); setReason(''); setConfirmed(false); setError(companyReviewError(failure)); } }
    finally { if (epoch === generation.current) setBusy(false); }
  }
  return <section className="p-6 max-w-5xl space-y-5" style={{ color: 'var(--text-primary)' }}>
    <header><h1 className="text-2xl font-semibold">Firmenprüfung</h1><p className="mt-2">Mandantenübergreifende Antragsprüfung durch ausdrücklich bestellte Plattformprüfer.</p></header>
    <p>Eine Freigabe ist eine interne Prüfentscheidung, keine externe Firmenverifizierung. Sie aktiviert weder Mandant noch Administrator und vergibt keine Rollen.</p>
    {unavailable && <p role="alert">Berechtigungen nicht verfügbar.</p>}{!access && !unavailable && <p role="status">Berechtigungen werden geprüft …</p>}
    {access && !permitted && <p role="alert">Kein bestätigtes Plattformprüfrecht. Eine normale Administratorrolle genügt nicht.</p>}
    {error && <p role="alert">{error} <a href="/mfa" className="underline">MFA-Einstellungen öffnen</a></p>}{success && <p role="status">{success}</p>}
    <button type="button" disabled={busy} className="border rounded px-4 py-2" onClick={() => { generation.current++; setSelected(null); setQueue(null); setAttempt(value => value + 1); reload(); }}>Status neu laden</button>
    {permitted && <>
      <div><label htmlFor="company-review-status" className="block">Antragsstatus</label><select id="company-review-status" className="block border rounded p-2 bg-transparent" value={status} disabled={busy} onChange={event => { setPage(1); setStatus(event.target.value as ReviewStatus | 'all'); }}>
        {Object.entries(labels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select></div>
      {!queue && !selected && !error && <p role="status">Anträge werden geladen …</p>}
      {queue && <><p>{queue.total} tatsächliche Anträge · Seite {queue.page}</p><div className="overflow-x-auto"><table className="w-full text-left"><caption className="sr-only">Firmenanträge</caption>
        <thead><tr><th className="p-2">Unternehmen</th><th className="p-2">Antragsteller</th><th className="p-2">Status</th><th className="p-2">Aktion</th></tr></thead>
        <tbody>{queue.registrations.map(row => <tr key={row.registrationId} className="border-t"><td className="p-2">{row.profile.name}</td><td className="p-2">{row.principal.email}</td><td className="p-2">{labels[row.status]}</td><td className="p-2"><button type="button" disabled={busy} aria-label={`Antrag öffnen: ${row.profile.name}`} className="underline" onClick={() => void open(row.registrationId)}>Antrag öffnen</button></td></tr>)}</tbody>
      </table></div>{!queue.total && <p>Keine Anträge für diesen Filter vorhanden.</p>}
        <div className="flex gap-4"><button type="button" disabled={busy || page <= 1} className="border rounded px-3 py-2" onClick={() => setPage(value => value - 1)}>Zurück</button><button type="button" disabled={busy || page * queue.limit >= queue.total} className="border rounded px-3 py-2" onClick={() => setPage(value => value + 1)}>Weiter</button></div></>}
      {selected && <section className="border rounded-xl p-5 space-y-4"><h2 className="text-xl font-semibold">{selected.profile.name}</h2><p>{labels[selected.status]}</p>
        <dl className="break-all"><dt>Registrierungs-ID</dt><dd>{selected.registrationId}</dd><dt>Mandant</dt><dd>{selected.tenantId}</dd><dt>Antragsteller</dt><dd>{selected.principal.displayName} · {selected.principal.email}</dd></dl>
        <OrganizationProfileFields value={selected.profile} onChange={() => {}} disabled prefix="review-company" />
        {selected.review && <dl><dt>Prüfbegründung</dt><dd>{selected.review.reason}</dd><dt>Prüfzeitpunkt</dt><dd><time dateTime={selected.review.reviewedAt}>{new Date(selected.review.reviewedAt).toLocaleString('de-CH')}</time></dd><dt>Prüfer-ID</dt><dd className="break-all">{selected.review.reviewerUserId}</dd></dl>}
        {selected.canReview && <form onSubmit={save} className="space-y-4"><fieldset disabled={busy} className="space-y-4"><legend className="font-semibold">Abschliessende Prüfentscheidung</legend>
          <div><label htmlFor="company-review-decision" className="block">Entscheidung</label><select id="company-review-decision" required className="block border rounded p-2 bg-transparent" value={decision} onChange={event => setDecision(event.target.value as typeof decision)}><option value="">Bitte auswählen</option><option value="approved">Freigeben – keine Aktivierung</option><option value="rejected">Ablehnen</option></select></div>
          <div><label htmlFor="company-review-reason" className="block">Prüfbegründung</label><textarea id="company-review-reason" required minLength={10} maxLength={500} className="block border rounded p-2 w-full bg-transparent" value={reason} onChange={event => setReason(event.target.value)} /></div>
          <label className="flex gap-3"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} /><span>Ich bestätige diese endgültige, protokollierte Prüfentscheidung. Konten bleiben gesperrt.</span></label>
          <button disabled={!decision || !confirmed || reason.trim().length < 10} className="bg-blue-600 text-white rounded px-4 py-2 disabled:opacity-50">{busy ? 'Wird geprüft …' : 'Prüfentscheidung speichern'}</button>
        </fieldset></form>}
      </section>}
    </>}
  </section>;
}
