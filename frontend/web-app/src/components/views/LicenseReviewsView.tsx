'use client';

import React, { useEffect, useRef, useState } from 'react';
import { LicenseReview, LicenseReviewPolicy, licenseReviews } from '@/lib/licenseReviews';

export default function LicenseReviewsView({ permissions, userId }: { permissions: string[]; userId: string }) {
  const [licenseId, setLicenseId] = useState(''); const [reviewId, setReviewId] = useState('');
  const [policy, setPolicy] = useState<LicenseReviewPolicy | null>(null); const [policyLoaded, setPolicyLoaded] = useState(false);
  const [rows, setRows] = useState<LicenseReview[]>([]); const [selected, setSelected] = useState<LicenseReview | null>(null);
  const [action, setAction] = useState<'retain' | 'deny' | null>(null); const [reason, setReason] = useState(''); const [ack, setAck] = useState(false);
  const [reviewers, setReviewers] = useState(''); const [intervalHours, setIntervalHours] = useState('24'); const [windowMinutes, setWindowMinutes] = useState('60');
  const [pending, setPending] = useState(false); const [error, setError] = useState(''); const [message, setMessage] = useState('');
  const epoch = useRef(0); const permissionKey = permissions.join('|');
  useEffect(() => { epoch.current++; setSelected(null); setAction(null); setAck(false); setReason(''); setPending(false); setRows([]); setPolicy(null); setPolicyLoaded(false); setLicenseId(''); setReviewId(''); setError(''); setMessage('');
    return () => { epoch.current++; }; }, [permissionKey, userId]);
  const can = (suffix: string) => permissions.includes('licenses.reviews.' + suffix);
  const reset = () => { epoch.current++; setSelected(null); setAction(null); setPolicyLoaded(false); setReason(''); setAck(false); setError(''); setMessage(''); };
  const run = async (operation: () => Promise<void>) => {
    const current = epoch.current; setPending(true); setError(''); setMessage('');
    try { await operation(); } catch (failure: unknown) {
      if (current !== epoch.current) return;
      const status = (failure as { response?: { status?: number } })?.response?.status;
      setError(status === 428 ? 'Frische MFA-Anmeldung erforderlich. Danach Prüfung neu laden.' : 'Keine bestätigte Änderung. Ziel oder Berechtigung möglicherweise geändert. Neu laden; nicht blind wiederholen.');
      setAction(null); setAck(false);
    } finally { if (current === epoch.current) setPending(false); }
  };
  const select = (row: LicenseReview) => { reset(); setSelected(row); };
  const validReason = reason.trim().length >= 10 && reason.length <= 500;
  const tag = (row: LicenseReview) => `${row.kind === 'group' ? 'Ganze Gruppe' : 'Direktvergabe'} · ${row.recipientId} · ${row.state}`;
  return <section aria-label="Wiederkehrende Lizenzprüfungen" className="rounded-xl p-4 space-y-4" style={{ border: '1px solid rgba(255,255,255,0.08)' }}>
    <h3 className="font-semibold">Wiederkehrende Lizenzprüfungen</h3>
    <p className="text-xs">Unbeantwortete Fristen begrenzen echte lokale Vergaben. Bestätigen verlängert nur den Prüfzyklus, nicht die ursprüngliche Lizenzlaufzeit. Herstellerstatus separat prüfen.</p>
    {error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    {can('policies.read') && <div className="space-y-3">
      <label className="block">Bekannte Lizenzpool-ID<input value={licenseId} disabled={pending} onChange={event => { reset(); setLicenseId(event.target.value); setPolicyLoaded(false); setPolicy(null); }} className="block w-full p-2 rounded bg-black/20" /></label>
      <button disabled={pending} onClick={() => { reset(); const current = epoch.current; run(async () => { const value = await licenseReviews.policy(licenseId); if (current === epoch.current) { setPolicy(value); setPolicyLoaded(true); } }); }}>Lizenzprüfrichtlinie laden</button>
      {policyLoaded && <p>{policy ? `Richtlinie ${policy.id} · Version ${policy.version} · ${policy.retiredAt ? 'Stillgelegt; bestehende Fristen bleiben verbindlich' : 'Aktiv'}` : 'Keine Richtlinie für diesen Pool'}</p>}
      {can('policies.manage') && policyLoaded && <>
        {(!policy || policy.retiredAt) && <>
          <label className="block">Unabhängige Prüfer-IDs (kommagetrennt)<input value={reviewers} onChange={event => setReviewers(event.target.value)} disabled={pending} className="block w-full p-2 rounded bg-black/20" /></label>
          <label className="block">Prüfintervall in Stunden<input type="number" min="1" value={intervalHours} onChange={event => setIntervalHours(event.target.value)} disabled={pending} className="ml-2 bg-black/20" /></label>
          <label className="block">Antwortfenster in Minuten<input type="number" min="1" value={windowMinutes} onChange={event => setWindowMinutes(event.target.value)} disabled={pending} className="ml-2 bg-black/20" /></label>
        </>}
        <label className="block">Begründung der Richtlinie<textarea value={reason} maxLength={500} disabled={pending} onChange={event => setReason(event.target.value)} className="block w-full p-2 rounded bg-black/20" /></label>
        <label className="flex gap-2"><input type="checkbox" checked={ack} disabled={pending} onChange={event => setAck(event.target.checked)} />Fristen und Entzug geprüft; Stilllegen hebt bestehende Fristen nicht auf.</label>
        <button disabled={pending || !validReason || !ack || !!error} onClick={() => { const current = epoch.current; run(async () => {
          const value = policy && !policy.retiredAt ? await licenseReviews.retire(policy, reason.trim()) : await licenseReviews.create({ licenseId, intervalSeconds: Number(intervalHours) * 3600,
            windowSeconds: Number(windowMinutes) * 60, reviewerUserIds: reviewers.split(',').map(value => value.trim()).filter(Boolean).sort(), reason: reason.trim(), acknowledgeDeadlines: true });
          if (current === epoch.current) { setPolicy(value); setAck(false); setReason(''); setMessage('Richtlinie bestätigt. Bestehende Fristen bleiben verbindlich.'); }
        }); }}>{policy && !policy.retiredAt ? 'Lizenzprüfrichtlinie stilllegen' : 'Lizenzprüfrichtlinie verbindlich erstellen'}</button>
      </>}
    </div>}
    {can('assigned.read') && <div className="space-y-2">
      <button disabled={pending} onClick={() => { reset(); const current = epoch.current; run(async () => { const result = await licenseReviews.self(userId); if (current === epoch.current) { setRows(result.reviews); setMessage(result.truncated ? 'Begrenzte Warteschlange; weitere Prüfungen vorhanden.' : result.reviews.length ? '' : 'Keine zugewiesenen Lizenzprüfungen.'); } }); }}>Meine Lizenzprüfungen laden</button>
      {rows.map(row => <button key={row.id} className="block text-left break-all" disabled={pending} onClick={() => select(row)}>{tag(row)}</button>)}
    </div>}
    {(can('all.read') || can('assigned.read')) && <div>
      <label className="block">Bekannte Lizenzprüfungs-ID<input value={reviewId} disabled={pending} onChange={event => { reset(); setReviewId(event.target.value); }} className="block w-full p-2 rounded bg-black/20" /></label>
      <button disabled={pending} onClick={() => { reset(); const current = epoch.current; run(async () => { const value = await licenseReviews.get(reviewId); if (current === epoch.current) setSelected(value); }); }}>Lizenzprüfung laden</button>
    </div>}
    {selected && <div className="space-y-3 break-words">
      <h4 className="font-semibold">{tag(selected)}</h4>
      <p className="text-xs break-all">Quelle {selected.grantId} · Version {selected.sourceVersion} · Prüfung {selected.version} · Richtlinie {selected.policyVersion}</p>
      <p>Prüfungsfrist: {selected.deadlineAt ? new Date(selected.deadlineAt).toLocaleString('de-CH') : 'Keine'} · Ursprüngliches Ende: {selected.baseExpiresAt ? new Date(selected.baseExpiresAt).toLocaleString('de-CH') : 'Unbefristet'}</p>
      {selected.policyRetired && <p>Richtlinie stillgelegt. Eine rechtzeitige unabhängige Bestätigung beendet nur die Wiederholung, nie die ursprüngliche Laufzeit.</p>}
      {selected.selfReview && <p>Keine Selbstprüfung möglich.</p>}{selected.requiresFreshMfa && <p>Frische MFA-Anmeldung erforderlich. Danach neu laden.</p>}
      {can('decide') && selected.canDecide && !action && <div className="flex gap-4">
        <button disabled={pending || !!error} onClick={() => { setAction('retain'); setReason(''); setAck(false); }}>Lizenzquelle behalten prüfen</button>
        <button disabled={pending || !!error} onClick={() => { setAction('deny'); setReason(''); setAck(false); }}>Lizenzquelle entziehen prüfen</button>
      </div>}
      {action && <>
        <p>{action === 'deny' ? 'Diese Quelle wird entzogen. Eine ganze Gruppenregel wird deaktiviert; andere Gruppen- und Direktvergaben bleiben erhalten.' : 'Nur diese bestehende Quelle und Prüfperiode bestätigen. Kein neuer Lizenzkauf und keine verlängerte ursprüngliche Laufzeit.'}</p>
        <label className="block">Begründung der Lizenzentscheidung<textarea value={reason} maxLength={500} disabled={pending} onChange={event => setReason(event.target.value)} className="block w-full p-2 rounded bg-black/20" /></label>
        <label className="flex gap-2"><input type="checkbox" checked={ack} disabled={pending} onChange={event => setAck(event.target.checked)} />Quelle, Versionen, Frist und unabhängige Wirkung geprüft.</label>
        <button disabled={pending || !ack || !validReason || !!error} onClick={() => { const current = epoch.current; const target = selected; run(async () => {
          const result = await licenseReviews.decide(target, action, reason.trim()); if (current === epoch.current) { setSelected(result); setRows(rows.map(row => row.id === result.id ? result : row)); setAction(null); setAck(false); setReason('');
            setMessage(action === 'deny' ? 'Quelle lokal entzogen. Herstellerstatus separat prüfen.' : 'Bestehende Quelle bestätigt; ursprüngliche Laufzeit unverändert.'); }
        }); }}>Lizenzentscheidung verbindlich bestätigen</button>
      </>}
    </div>}
  </section>;
}
