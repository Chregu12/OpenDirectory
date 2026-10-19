'use client';

import React, { useEffect, useRef, useState } from 'react';
import { organizationDelegations, OrganizationDelegationsPage } from '@/lib/organizationDelegations';

export default function OrganizationDelegations({ actorUserId, tenantId }: { actorUserId: string; tenantId: string }) {
  const [page, setPage] = useState<OrganizationDelegationsPage | null>(null); const [error, setError] = useState(''); const [success, setSuccess] = useState('');
  const [userId, setUserId] = useState(''); const [duration, setDuration] = useState('3600'); const [reason, setReason] = useState(''); const [revokeId, setRevokeId] = useState('');
  const [busy, setBusy] = useState(false); const [attempt, setAttempt] = useState(0); const generation = useRef(0);
  useEffect(() => {
    const epoch = ++generation.current; const controller = new AbortController(); setPage(null); setError(''); setSuccess(''); setUserId(''); setReason(''); setRevokeId(''); setBusy(false);
    organizationDelegations.load(actorUserId, tenantId, controller.signal).then(result => { if (epoch === generation.current) setPage(result); })
      .catch(() => { if (epoch === generation.current) setError('Organisationsberechtigungen nicht verfügbar. Bitte neu laden.'); });
    const invalid = () => { generation.current++; setPage(null); setUserId(''); setReason(''); setRevokeId(''); setSuccess(''); setBusy(false); setError('Sitzung geändert. Bitte erneut anmelden.'); };
    window.addEventListener('od:session-error', invalid);
    return () => { generation.current++; controller.abort(); window.removeEventListener('od:session-error', invalid); };
  }, [actorUserId, tenantId, attempt]);
  async function submit(event: React.FormEvent) {
    event.preventDefault(); if (!page?.canManage || busy) return;
    const epoch = generation.current; setBusy(true); setError(''); setSuccess('');
    try {
      const result = await organizationDelegations.change(page, revokeId ? { grantId: revokeId } : { userId: userId.trim(), durationSeconds: Number(duration) }, reason);
      if (epoch === generation.current) { setPage(result); setUserId(''); setReason(''); setRevokeId(''); setSuccess('Berechtigungsänderung und tatsächlicher Bestand bestätigt. Betroffene Personen müssen sich neu anmelden.'); }
    } catch {
      if (epoch === generation.current) { setPage(null); setUserId(''); setReason(''); setRevokeId(''); setError('Änderung nicht bestätigt. Vor einem erneuten Versuch neu laden.'); }
    } finally { if (epoch === generation.current) setBusy(false); }
  }
  return <section className="border rounded-xl p-5 space-y-4" aria-labelledby="organization-delegations-title">
    <h2 id="organization-delegations-title" className="text-lg font-semibold">Firmenprofil delegieren</h2>
    <p>Nur das eigene Firmenprofil lesen und bearbeiten, keine Benutzer-, Rollen-, Geräte- oder Lizenzverwaltung. Laufzeit maximal 8 Stunden; frische MFA ist auch beim delegierten Lesen erforderlich.</p>
    <button type="button" className="border rounded px-3 py-2" disabled={busy} onClick={() => { generation.current++; setPage(null); setAttempt(value => value + 1); }}>Berechtigungen neu laden</button>
    {error && <p role="alert">{error}</p>}{success && <p role="status">{success}</p>}
    {!page && !error && <p role="status">Berechtigungen werden geladen …</p>}
    {page && <>
      {!page.canManage && <p role="alert">Zum Delegieren oder Widerrufen erneut mit MFA anmelden. <a href="/mfa" className="underline">MFA-Einstellungen öffnen</a></p>}
      {page.truncated && <p>Die neuesten 100 Zuweisungen werden angezeigt. Ältere Historie ist hier nicht vollständig enthalten.</p>}
      {!page.grants.length ? <p>Noch keine Profilberechtigungen vergeben.</p> : <div className="overflow-x-auto"><table className="w-full text-left"><thead><tr><th scope="col">Person</th><th scope="col">Gültig bis</th><th scope="col">Status</th><th scope="col">Aktion</th></tr></thead><tbody>
        {page.grants.map(row => <tr key={row.id}><td className="py-2">{row.name}<span className="block text-xs">{row.username}</span></td><td>{new Date(row.expiresAt).toLocaleString('de-CH')}</td><td>{{ active: 'Aktiv', expired: 'Abgelaufen', revoked: 'Widerrufen', inactive: 'Benutzer inaktiv' }[row.status]}</td><td>
          {row.status !== 'revoked' && <button type="button" className="underline" disabled={busy || !page.canManage || row.userId === actorUserId} onClick={() => { setRevokeId(row.id); setReason(''); setSuccess(''); }}>Widerruf vorbereiten: {row.name}</button>}
        </td></tr>)}
      </tbody></table></div>}
      <form onSubmit={submit} className="space-y-3"><fieldset disabled={busy || !page.canManage} className="space-y-3">
        <legend>{revokeId ? 'Ausgewählten Widerruf bestätigen' : 'Profilberechtigung erteilen'}</legend>
        {revokeId ? <p>Zuweisung {revokeId} wird beendet. Die Person verliert ihren delegierten Profilzugriff.</p> : <>
          <label className="block" htmlFor="organization-delegation-user">Kanonische Benutzer-ID (UUID, aus Personen)<input id="organization-delegation-user" className="block border rounded px-3 py-2 bg-transparent w-full" required value={userId} onChange={event => setUserId(event.target.value)} pattern="[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}" /></label>
          <label className="block" htmlFor="organization-delegation-duration">Laufzeit in Sekunden<input id="organization-delegation-duration" className="block border rounded px-3 py-2 bg-transparent" type="number" min={60} max={28800} required value={duration} onChange={event => setDuration(event.target.value)} /></label>
        </>}
        <label className="block" htmlFor="organization-delegation-reason">Begründung der Berechtigung<textarea id="organization-delegation-reason" className="block border rounded p-3 bg-transparent w-full" required minLength={10} maxLength={500} value={reason} onChange={event => setReason(event.target.value)} /></label>
        <button className="rounded px-4 py-2 bg-blue-600 text-white disabled:opacity-50" disabled={busy || !page.canManage || reason.trim().length < 10}>{busy ? 'Wird geprüft …' : revokeId ? 'Widerruf bestätigen' : 'Profilberechtigung erteilen'}</button>
        {revokeId && <button type="button" className="ml-3 underline" onClick={() => { setRevokeId(''); setReason(''); }}>Abbrechen</button>}
      </fieldset></form>
    </>}
  </section>;
}
