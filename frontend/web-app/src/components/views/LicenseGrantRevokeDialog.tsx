'use client';

import React, { useEffect, useRef, useState } from 'react';
import { LicenseGrant, readLicenseGrant, revokeLicenseGrant } from '@/lib/licenseGrants';

export default function LicenseGrantRevokeDialog({ licenseId, grantId, onClose, onRevoked }: {
  licenseId: string; grantId: string; onClose: () => void; onRevoked: (retained: number) => void;
}) {
  const [grant, setGrant] = useState<LicenseGrant | null>(null);
  const [reason, setReason] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState('');
  const generation = useRef(0);
  useEffect(() => {
    const current = ++generation.current;
    setGrant(null); setReason(''); setConfirmed(false); setError(''); setPending(false);
    readLicenseGrant(licenseId, grantId).then(value => {
      if (generation.current === current) setGrant(value);
    }).catch(() => { if (generation.current === current) setError('Lizenzquelle nicht verfügbar. Schliessen und neu laden.'); });
    return () => { generation.current++; };
  }, [licenseId, grantId]);

  const revoke = async () => {
    if (!grant || !confirmed || pending || error || reason.trim().length < 10) return;
    const current = generation.current;
    setPending(true);
    try {
      const result = await revokeLicenseGrant(grant, reason);
      if (generation.current === current) onRevoked(result.usersRetainingAssignment);
    } catch (failure: unknown) {
      if (generation.current !== current) return;
      const status = (failure as { response?: { status?: number } })?.response?.status;
      setError(status === 428 ? 'Frische MFA-Anmeldung erforderlich. Danach schliessen und neu laden.'
        : 'Kein bestätigter Entzug. Quelle oder Sitzung möglicherweise geändert. Schliessen und neu laden; nicht blind wiederholen.');
    } finally { if (generation.current === current) setPending(false); }
  };

  return <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
    <section role="dialog" aria-modal="true" aria-labelledby="grant-revoke-title" className="w-full max-w-xl max-h-[90vh] overflow-y-auto rounded-xl p-6 space-y-4" style={{ background: 'var(--bg-secondary, #14171d)', color: 'var(--text-primary, #fff)' }}>
      <h2 id="grant-revoke-title" className="font-semibold">Lizenzquelle gezielt entziehen</h2>
      {error && <p role="alert">{error}</p>}
      {!grant && !error && <p role="status">Lizenzquelle wird geprüft …</p>}
      {grant && <>
        <p className="break-all text-sm">{grant.kind === 'group' ? 'Ganze Gruppenregel' : 'Direktvergabe'}: {grant.recipientId}</p>
        <p className="break-all text-xs">Quelle {grant.id} · Version {grant.version} · {grant.sourceUsers} lokale Benutzerquellen</p>
        {grant.origin === 'observed' && <p>Übernommener Altbestand; keine nachträgliche Bestätigung der ursprünglichen Genehmigung.</p>}
        <p className="text-sm">Nur diese Quelle wird entzogen. Andere Gruppen- und Direktvergaben bleiben erhalten. Eine Gruppenregel wird deaktiviert, damit der Abgleich sie nicht erneut verteilt.</p>
        <p className="text-sm">Herstellerentzug ist nicht bestätigt. Ein konfigurierter Connector verarbeitet den wirksamen lokalen Entzug separat.</p>
        {grant.state !== 'active' && <p role="status">Diese Quelle ist nicht mehr aktiv. Kein Entzug möglich.</p>}
        <label className="block text-sm">Begründung (10–500 Zeichen)<textarea value={reason} maxLength={500} onChange={event => setReason(event.target.value)} disabled={pending || !!error} className="block w-full rounded p-2 text-black" /></label>
        <label className="flex gap-2 text-sm"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} disabled={pending || !!error} />Ich bestätige den Entzug dieser Quelle und Version.</label>
      </>}
      <div className="flex justify-end gap-4">
        <button onClick={onClose} disabled={pending}>Schliessen</button>
        <button onClick={revoke} disabled={!grant || grant.state !== 'active' || !confirmed || reason.trim().length < 10 || pending || !!error} className="text-red-400 disabled:opacity-50">{pending ? 'Entzug läuft …' : 'Geprüfte Quelle entziehen'}</button>
      </div>
    </section>
  </div>;
}
