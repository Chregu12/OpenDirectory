'use client';

import React, { useEffect, useRef, useState } from 'react';
import { PolicyAccess, policyGovernance } from '@/lib/policyGovernance';
import { Publication, PublicationFrame, PublicationKind, policyPublication } from '@/lib/policyPublication';
type Confirmation = { action: 'request'; reviewer: string; seconds: number } | { action: 'approved' | 'denied' | 'withdrawn'; publication: Publication };

export default function PolicyPublicationPanel({ kind, id, version, access, disabled = false, onSelect }: {
  kind: PublicationKind; id: string; version: number; access: PolicyAccess; disabled?: boolean; onSelect: (id: string) => void;
}) {
  const [frame, setFrame] = useState<PublicationFrame | null>(null); const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  const [reviewer, setReviewer] = useState(''); const [seconds, setSeconds] = useState(3600); const [reason, setReason] = useState('');
  const [ack, setAck] = useState(false); const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const epoch = useRef(0); const select = useRef(onSelect); select.current = onSelect;
  const invalidate = () => { epoch.current++; setFrame(null); setConfirmation(null); setReason(''); setAck(false); setBusy(false); select.current(''); };
  useEffect(() => {
    select.current(''); const ended = () => { invalidate(); setError('Freigabesitzung nicht mehr bestätigt. Rechte und Daten neu laden.'); };
    window.addEventListener('od:session-error', ended);
    return () => { epoch.current++; window.removeEventListener('od:session-error', ended); };
  }, [id, version, access.userId, access.subject]);
  async function load() {
    invalidate(); setError(''); const generation = epoch.current; setBusy(true);
    try { const result = await policyPublication.get(kind, id, version); if (generation === epoch.current) setFrame(result); }
    catch { if (generation === epoch.current) { invalidate(); setError('Kein konsistenter Freigaberahmen. Richtlinie und Berechtigungen neu laden.'); } }
    finally { if (generation === epoch.current) setBusy(false); }
  }
  function stage(value: Confirmation) { if (!frame || busy || disabled) return; setReason(''); setAck(false); select.current(''); setConfirmation(value); }
  async function confirm() {
    if (!confirmation || !frame || !ack || reason.trim().length < 10 || busy || disabled) return;
    const captured = confirmation; const scope = frame; const generation = epoch.current; setBusy(true);
    const permission = captured.action === 'request' || captured.action === 'withdrawn' && captured.publication.requestedBy === access.userId ? 'policies.publication.request' : 'policies.publication.review';
    const same = (current: PolicyAccess) => current.userId === access.userId && current.subject === access.subject && current.freshMfa && current.permissions.includes(permission);
    try {
      const current = await policyGovernance.access(); if (generation !== epoch.current) return; if (!same(current)) throw new Error('Original publication actor changed');
      if (captured.action === 'request') await policyPublication.request(scope, captured.reviewer.trim(), captured.seconds, reason.trim(), current.userId);
      else await policyPublication.decide(scope, captured.publication, captured.action, reason.trim(), current.userId);
      if (generation !== epoch.current) return;
      const verified = await policyGovernance.access(); if (generation !== epoch.current) return; if (!same(verified)) throw new Error('Publication actor no longer confirmed');
      const result = await policyPublication.get(kind, id, version); if (generation !== epoch.current) return;
      setFrame(result); setConfirmation(null); setReason(''); setAck(false);
    } catch { if (generation === epoch.current) { invalidate(); setError('Freigabeänderung nicht bestätigt. Rechte und Daten neu laden; nicht blind wiederholen.'); } }
    finally { if (generation === epoch.current) setBusy(false); }
  }
  const ready = access.freshMfa && !!frame && !error && !busy && !disabled;
  const request = access.permissions.includes('policies.publication.request'); const review = access.permissions.includes('policies.publication.review');
  const existing = frame?.publications.some(row => row.configurationVersion === frame.configurationVersion && ['pending', 'approved'].includes(row.state) && Date.parse(row.expiresAt) > Date.now());
  return <section aria-label="Unabhängige Richtlinienfreigabe" className="border border-white/15 rounded p-3 space-y-3">
    <h3>Unabhängige Veröffentlichung</h3><p className="text-xs">Vor Aktivierung oder verwalteter Zustellung ist eine befristete Freigabe des exakten Inhalts und aller Ziele erforderlich. Beitragende dürfen nicht selbst prüfen. Gespeicherte Zustimmung ersetzt keine Live-Prüfung und keine Geräteausführung.</p>
    <button disabled={busy || disabled} onClick={load}>Freigaberahmen laden</button>
    {busy && <p role="status">Freigabe wird geprüft …</p>}{error && <p role="alert">{error}</p>}
    {frame && <>
      <p className="text-xs break-all">Inhaltsgeneration {frame.configurationVersion} · aktuelle Version {frame.resourceVersion} · SHA-256 {frame.configurationHash}</p>
      {!frame.verifiedOrigin && <p role="alert">Unverifizierter Altbestand kann nicht freigegeben werden. Explizit als neuen Entwurf anlegen; keine automatische Übernahme.</p>}
      <details><summary>Vollständigen Inhalt und Zielumfang prüfen</summary><pre className="text-xs whitespace-pre-wrap break-all">{JSON.stringify(frame.frame, null, 2)}</pre><p className="text-xs break-all">Ausgeschlossene Beitragende: {frame.contributors.join(', ') || 'keine verifizierten Beitragenden'}</p></details>
      {request && frame.verifiedOrigin && <fieldset disabled={!ready || !!confirmation} className="space-y-2">
        <legend>Freigabe anfordern</legend><label className="block">Kanonische Prüfer-ID<input aria-label="Kanonische Prüfer-ID" className="block w-full bg-black/20 p-2" value={reviewer} maxLength={36} onChange={event => setReviewer(event.target.value)} /></label>
        <label>Gültigkeit ab Anforderung<select aria-label="Gültigkeit ab Anforderung" className="bg-black/20 p-2" value={seconds} onChange={event => setSeconds(Number(event.target.value))}><option value={300}>5 Minuten</option><option value={3600}>1 Stunde</option><option value={28800}>8 Stunden</option></select></label>
        {existing && <p className="text-xs">Ein offener Vorgang oder eine gültige Zustimmung besteht bereits. Vor Ersatz abschließen, zurückziehen oder Ablauf abwarten; kein Parallelvotum.</p>}
        <button disabled={!reviewer.trim() || existing} onClick={() => stage({ action: 'request', reviewer, seconds })}>Freigabeanforderung prüfen</button>
      </fieldset>}
      <p className="text-xs">{frame.publications.length} von {frame.total} Freigabevorgängen; maximal 50 angezeigt. Live-Quellen werden vor Entscheidung und Verwendung erneut geprüft.</p>
      {frame.publications.map(row => {
        const fresh = Date.parse(row.expiresAt) > Date.now(); const independent = row.reviewerUserId === access.userId && row.requestedBy !== access.userId && !frame.contributors.includes(access.userId);
        const vote = review && independent && row.state === 'pending' && row.resourceVersion === version && row.configurationHash === frame.configurationHash && fresh;
        const withdraw = (request && row.requestedBy === access.userId || review && row.reviewerUserId === access.userId) && ['pending', 'approved'].includes(row.state);
        return <article key={row.id} className="border-t border-white/10 pt-2 space-y-1"><p className="text-xs break-all">{row.id} · {row.state} · Prüfer {row.reviewerUserId} · bis {row.expiresAt}</p>
          {vote && <><button disabled={!ready || !!confirmation} onClick={() => stage({ action: 'approved', publication: row })}>Unabhängige Zustimmung prüfen</button><button disabled={!ready || !!confirmation} onClick={() => stage({ action: 'denied', publication: row })}>Ablehnung prüfen</button></>}
          {withdraw && <button disabled={!ready || !!confirmation} onClick={() => stage({ action: 'withdrawn', publication: row })}>Freigabe zurückziehen prüfen</button>}
          {access.permissions.includes('policies.deploy') && row.current && fresh && <button disabled={!ready || !!confirmation} onClick={() => select.current(row.id)}>Gespeicherte Freigabe auswählen</button>}
        </article>;
      })}
    </>}
    {confirmation && <div role="group" aria-label="Unabhängige Freigabe bestätigen" className="border border-blue-400/40 rounded p-3 space-y-2">
      <p>{confirmation.action} · {id} · exakte Version {version}{confirmation.action === 'request' ? ` · Prüfer ${confirmation.reviewer} · ${confirmation.seconds} Sekunden` : ` · Vorgang ${confirmation.publication.id} · Vorgangsversion ${confirmation.publication.version}`}</p>
      <label className="block">Begründung der Freigabe<textarea aria-label="Begründung der Freigabe" className="block w-full bg-black/20 p-2" maxLength={500} disabled={busy} value={reason} onChange={event => setReason(event.target.value)} /></label>
      <label className="flex gap-2"><input type="checkbox" checked={ack} disabled={busy} onChange={event => setAck(event.target.checked)} />Vollständigen Inhalt, Zielumfang, Unabhängigkeit und Frist geprüft.</label>
      <button disabled={!ready || !ack || reason.trim().length < 10} onClick={confirm}>Freigabeaktion verbindlich bestätigen</button><button disabled={busy} onClick={() => { setConfirmation(null); setAck(false); setReason(''); }}>Freigabeaktion abbrechen</button>
    </div>}
  </section>;
}
