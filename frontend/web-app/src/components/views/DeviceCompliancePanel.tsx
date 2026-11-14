'use client';
import React, { useEffect, useRef, useState } from 'react';
import { ComplianceContext, ComplianceReport, ComplianceHistory, complianceAccess, complianceLabels, complianceError, readComplianceReport, readComplianceHistory } from '@/lib/deviceCompliance';
const checks = { 'os-version': 'Betriebssystemversion', 'disk-encryption': 'Systemdatenträger verschlüsselt', firewall: 'Firewall', 'disk-free': 'Freier Speicherplatz' };
const results = { pass: 'Erfüllt', fail: 'Nicht erfüllt', unknown: 'Unbekannt' };
const reasons: Record<string, string> = { checked: 'Gemessen', 'not-reported': 'Nicht gemeldet', 'source-not-current': 'Keine aktuelle passende Messung', 'probe-failed': 'Abfrage fehlgeschlagen oder nicht erlaubt', timeout: 'Zeitüberschreitung', unrecognized: 'Nicht eindeutig erkennbar', 'not-supported': 'Auf diesem System nicht unterstützt' };
function actual(value: unknown): string {
 if (value === null) return 'Unbekannt'; if (value === true) return 'Erforderlich';
 if (typeof value === 'string') return ({ enabled: 'Aktiv', disabled: 'Inaktiv', unknown: 'Unbekannt' } as Record<string, string>)[value] || value;
 if (typeof value === 'object' && value && 'totalBytes' in value && 'availableBytes' in value) return `${String(value.availableBytes)} von ${String(value.totalBytes)} Bytes verfügbar`;
 return String(value);
}
export default function DeviceCompliancePanel({ deviceId, expectedActor, context, onSecurityError }: { deviceId: string; expectedActor?: string; context?: ComplianceContext; onSecurityError?: (error: unknown) => void }) {
 const [data, setData] = useState<ComplianceReport | null>(null), [access, setAccess] = useState<ComplianceContext | null>(context || null), [error, setError] = useState(''), [reload, setReload] = useState(0);
 const [open, setOpen] = useState(false), [history, setHistory] = useState<ComplianceHistory | null>(null), [page, setPage] = useState(1);
 const failed = useRef(onSecurityError); failed.current = onSecurityError;
 useEffect(() => {
  const controller = new AbortController(); setData(null); setError(''); setHistory(null);
  void (async () => { const ctx = context || await complianceAccess(controller.signal); if (expectedActor && ctx.actorUserId !== expectedActor) throw new Error('Unconfirmed actor'); const value = await readComplianceReport(ctx, deviceId, controller.signal); if (!controller.signal.aborted) { setAccess(ctx); setData(value); } })().catch(error => {
   if (controller.signal.aborted) return; setAccess(null); setError(complianceError(error)); if ([401, 428].includes(error?.response?.status)) failed.current?.(error);
  });
  const session = () => { controller.abort(); setAccess(null); setData(null); setHistory(null); setError(complianceError({ response: { status: 401 } })); };
  window.addEventListener('od:session-error', session); return () => { controller.abort(); window.removeEventListener('od:session-error', session); };
 }, [deviceId, expectedActor, context, reload]);
 useEffect(() => { const timer = window.setInterval(() => { if (document.visibilityState === 'visible') setReload(value => value + 1); }, 30000); return () => window.clearInterval(timer); }, [deviceId]);
 useEffect(() => {
  if (!open || !access) return; const controller = new AbortController(); setHistory(null);
  void readComplianceHistory(access, deviceId, page, false, controller.signal).then(value => { if (!controller.signal.aborted) setHistory(value); }).catch(error => { if (!controller.signal.aborted) { setError(complianceError(error)); setData(null); if (error?.response?.status !== 403) failed.current?.(error); } });
  return () => controller.abort();
 }, [open, access, deviceId, page, reload]);
 return <section aria-label="Geräte-Compliance" className="border-t border-[var(--border)] pt-4 space-y-3">
  <div className="flex flex-wrap gap-3 items-center"><h3 className="font-semibold">Geräte-Compliance</h3>{data && <span className="od-badge">{complianceLabels[data.status]}</span>}<button className="fluent-btn-secondary" onClick={() => setReload(value => value + 1)}>Compliance aktualisieren</button><a className="text-blue-500 underline text-sm" href="/compliance">Richtlinien und Übersicht</a></div>
  {error ? <p role="alert">{error}</p> : !data ? <p role="status">Bewertung wird geprüft …</p> : <>
   {data.status === 'not-configured' && <p className="text-sm">Für diese Plattform ist keine aktive Firmenrichtlinie eingerichtet.</p>}
   {data.status === 'pending' && <p className="text-sm">Eine neue Sicherheitsmeldung zur aktuellen Richtlinie ist erforderlich. Agent ab Version 1.3.0 starten; die nächste Meldung bewertet das Gerät.</p>}
   {data.status === 'stale' && <p className="text-sm">Das zulässige Berichtsalter ist überschritten. Die frühere Bewertung bestätigt den aktuellen Zustand nicht mehr.</p>}
   {data.status === 'historical' && <p className="text-sm">Die frühere Geräteverbindung ist widerrufen, abgelaufen oder ersetzt. Eine neue Registrierung übernimmt ihre Bewertung nicht.</p>}
   {data.assessment && <details open={['compliant', 'non-compliant', 'unknown'].includes(data.status)}><summary className="cursor-pointer text-sm">Letzte protokollierte Bewertung · Richtlinie {data.assessment.policyRevision} · {new Date(data.assessment.evaluatedAt).toLocaleString('de-CH')}</summary>
    <ul className="mt-3 space-y-3 text-sm">{data.assessment.checks.map(row => <li key={row.id} className="rounded border border-[var(--border)] p-3"><p className="font-medium">{checks[row.id]} · {results[row.status]}</p><p>Gemeldet: {actual(row.actual)} · Vorgabe: {row.id === 'disk-free' ? `mindestens ${row.expected} % frei` : actual(row.expected)}</p><p className="opacity-70">{reasons[row.reason] || row.reason}</p></li>)}</ul>
    <p className="mt-3 text-xs opacity-70">Agent {data.assessment.security.agentVersion} · Sicherheitsmeldung {new Date(data.assessment.security.receivedAt).toLocaleString('de-CH')} · gültig bis {new Date(data.assessment.validUntil).toLocaleString('de-CH')}. Agent-Angaben sind nicht hardwareattestiert.</p>
   </details>}
   <p className="text-xs opacity-70">Aktuelle Richtlinie: {data.policyRevision} · geprüft am {new Date(data.checkedAt).toLocaleString('de-CH')}.</p>
   <details open={open} onToggle={event => setOpen(event.currentTarget.open)}><summary className="cursor-pointer text-sm">Bewertungsverlauf</summary>
    {!history ? <p className="mt-2 text-sm">Verlauf wird geladen …</p> : <><ol className="mt-3 space-y-3 text-sm">{history.events.map(event => <li key={event.id}><p>{new Date(event.createdAt).toLocaleString('de-CH')} · {'status' in event.after ? complianceLabels[event.after.status] : ''}</p><p className="text-xs break-words opacity-70">Geräteagent · Korrelations-ID {event.correlationId}</p></li>)}</ol>{!history.total && <p className="mt-2 text-sm">Noch keine Sicherheitsbewertung protokolliert.</p>}<nav aria-label="Bewertungsverlaufseiten" className="flex flex-wrap gap-3 items-center mt-3"><button className="fluent-btn-secondary" disabled={page <= 1} onClick={() => setPage(value => value - 1)}>Zurück</button><span>Seite {page} von {Math.max(1, Math.ceil(history.total / 25))}</span><button className="fluent-btn-secondary" disabled={page * 25 >= history.total} onClick={() => setPage(value => value + 1)}>Weiter</button></nav></>}
   </details>
  </>}
 </section>;
}
