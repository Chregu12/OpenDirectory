'use client';

import React, { useEffect, useRef, useState } from 'react';
import { CompanyApplicationsCapabilities, companyApplicationsError } from '@/lib/companyApplications';
import { CompanyProviderSnapshot, companyProviderFailure, inspectCompanyProvider } from '@/lib/companyLicenseProvider';

const statusLabels = { Enabled: 'Aktiv', Warning: 'Warnung', Suspended: 'Ausgesetzt', Deleted: 'Gelöscht', LockedOut: 'Gesperrt' };

export default function CompanyLicenseProviderPanel({ context, onAccessError }: { context: CompanyApplicationsCapabilities; onAccessError?: (failure: unknown) => void }) {
  const [snapshot, setSnapshot] = useState<CompanyProviderSnapshot | null>(null);
  const [pending, setPending] = useState(false); const [error, setError] = useState('');
  const controller = useRef<AbortController | null>(null); const generation = useRef(0);
  useEffect(() => {
    generation.current++; controller.current?.abort(); setSnapshot(null); setError(''); setPending(false);
    const invalidate = () => { generation.current++; controller.current?.abort(); setSnapshot(null); setPending(false); setError('Die Sitzung hat sich geändert. Bitte die Lizenzberechtigungen neu laden.'); };
    window.addEventListener('od:session-error', invalidate);
    return () => { generation.current++; controller.current?.abort(); window.removeEventListener('od:session-error', invalidate); };
  }, [context.actorUserId, context.tenantId]);
  async function inspect() {
    const current = ++generation.current; controller.current?.abort();
    const request = new AbortController(); controller.current = request;
    setPending(true); setSnapshot(null); setError('');
    try {
      const result = await inspectCompanyProvider(context, request.signal);
      if (generation.current === current && !request.signal.aborted) setSnapshot(result);
    } catch (failure) {
      if (generation.current === current && !request.signal.aborted) {
        const status = (failure as { response?: { status?: number } })?.response?.status;
        if ([401, 403, 428].includes(status || 0)) { setError(companyApplicationsError(failure)); onAccessError?.(failure); }
        else setError('Die Microsoft-Verbindung konnte nicht bestätigt werden. Bitte später erneut prüfen.');
      }
    } finally { if (generation.current === current) setPending(false); }
  }
  return <details className="od-panel text-sm">
    <summary>Microsoft 365 · Anbieterbestand</summary>
    <section aria-label="Microsoft-365-Verbindung" className="mt-3 space-y-3">
      <p>Den aktuellen Lizenzbestand bei Microsoft prüfen. Die lokalen Firmen-Zuweisungen bleiben separat verwaltet.</p>
      <button className="fluent-btn-secondary" disabled={pending || !context.permissions.includes('company.apps.read')} onClick={() => void inspect()}>Verbindung prüfen</button>
      {pending && <p role="status">Microsoft-Verbindung wird geprüft …</p>}
      {error && <p role="alert">{error}</p>}
      {snapshot?.state === 'not_configured' && <p role="status">Für diese Firma ist noch keine Microsoft-365-Verbindung eingerichtet.</p>}
      {snapshot?.state === 'failed' && <p role="alert">{companyProviderFailure(snapshot.errorCode)}{snapshot.retryAfter ? ` Wartezeit: ${snapshot.retryAfter} Sekunden.` : ''}</p>}
      {snapshot?.state === 'connected' && <>
        <p role="status">Microsoft-Verbindung bestätigt · {snapshot.products.length} {snapshot.products.length === 1 ? 'Produkt' : 'Produkte'} · geprüft am {new Date(snapshot.checkedAt).toLocaleString('de-CH')}</p>
        <p>Microsoft-Tenant: <span className="break-all">{snapshot.microsoftTenantId}</span></p>
        {!snapshot.products.length ? <p>Microsoft hat keine Lizenzprodukte zurückgegeben.</p> : <ul aria-label="Lizenzbestand von Microsoft 365" className="divide-y divide-[var(--border)]">
          {snapshot.products.map(row => <li key={row.skuId} className="py-3 space-y-3">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1"><h3 className="font-semibold break-all">{row.skuPartNumber}</h3><p>{row.appliesTo === 'User' ? 'Benutzer' : 'Firma'} · {statusLabels[row.capabilityStatus]}</p></div>
            <dl className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
              {[['Aktive Einheiten', row.prepaidUnits.enabled], ['Verbraucht', row.consumedUnits], ['Warnung', row.prepaidUnits.warning], ['Ausgesetzt', row.prepaidUnits.suspended], ['Gesperrt', row.prepaidUnits.lockedOut]].map(([label, value]) =>
                <div key={label}><dt className="text-[var(--text-secondary)]">{label}</dt><dd className="font-medium tabular-nums">{value}</dd></div>)}
            </dl>
          </li>)}
        </ul>}
      </>}
    </section>
  </details>;
}
