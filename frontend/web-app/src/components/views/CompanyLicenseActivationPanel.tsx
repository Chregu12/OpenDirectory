'use client';

import React, { useEffect, useRef, useState } from 'react';
import { companyLicenseActivation, LicenseActivationStatus } from '@/lib/companyLicenseActivation';
import { ensureSession } from '@/lib/auth';

export default function CompanyLicenseActivationPanel({ onAccessChanged, disabled = false }: { onAccessChanged: (reload: boolean) => void; disabled?: boolean }) {
  const callback = useRef(onAccessChanged); callback.current = onAccessChanged;
  const [status, setStatus] = useState<LicenseActivationStatus | null>(null);
  const [version, setVersion] = useState(0); const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  const [duration, setDuration] = useState(3600); const [reason, setReason] = useState(''); const [confirmed, setConfirmed] = useState(false);
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const controller = new AbortController(); let active = true;
    companyLicenseActivation.status(controller.signal).then(value => { if (active) { setStatus(value); setDuration(current => value.durations.includes(current) ? current : value.durations[0]); } }).catch(failure => {
      if (!active) return; setStatus(null);
      const code = failure?.response?.status;
      setError(code === 401 ? 'Bitte erneut anmelden.' : code === 403 ? 'Nur Firmeninhaber und berechtigte Administratoren können diese Aufgaben aktivieren.' : 'Aktivierungsstatus nicht verfügbar. Bitte den Status erneut prüfen.');
    });
    return () => { active = false; controller.abort(); };
  }, [version]);
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 30000); return () => clearInterval(timer); }, []);
  useEffect(() => {
    if (!status?.activation) return;
    const timer = setTimeout(() => { setStatus(null); setError('Das Aktivierungsfenster ist abgelaufen. Bitte den Status prüfen.'); callback.current(true); }, Math.max(0, status.activation.expiresAt * 1000 - Date.now()));
    return () => clearTimeout(timer);
  }, [status]);
  async function change() {
    if (!status || !confirmed || busy || disabled) return;
    setBusy(true); setError(''); callback.current(false);
    try {
      await companyLicenseActivation.change(status.activation ? { activationId: status.activation.id, confirm: true } : { durationSeconds: duration, reason: reason.trim(), confirm: true });
      await ensureSession(true, { rotate: true }); setConfirmed(false); setReason(''); setStatus(null); setVersion(value => value + 1); callback.current(true);
    } catch (failure: any) {
      setStatus(null); setConfirmed(false);
      setError(failure?.response?.status === 428 ? 'Für die Aktivierung ist eine aktuelle MFA-Bestätigung nötig. Bitte die Anmeldung bestätigen.' : 'Änderung nicht bestätigt. Nicht erneut aktivieren; zuerst den Status prüfen.');
    } finally { setBusy(false); }
  }
  async function resume() {
    if (busy || disabled) return;
    setBusy(true); setError(''); callback.current(false);
    try { await ensureSession(true, { rotate: true }); setStatus(null); setVersion(value => value + 1); callback.current(true); }
    catch { setStatus(null); setError('Sitzung nicht bestätigt. Bitte erneut anmelden oder den Aktivierungsstatus prüfen.'); }
    finally { setBusy(false); }
  }
  const active = status?.activation;
  return <section className="od-panel space-y-3" aria-label="Zeitlich begrenzte Lizenzberechtigung">
    <h2 className="font-semibold">Lizenzverwaltung zeitlich aktivieren</h2>
    <p className="text-sm">Aktiviere deine bestehenden Aufgaben für diese Firma nach MFA. Die Freigabe gilt für diese Anmeldung und endet automatisch. Strengere Rollen- und Anmelderegeln gelten weiterhin.</p>
    {error && <p role="alert">{error}</p>}
    {!status && <button className="fluent-btn-secondary" disabled={busy || disabled} onClick={() => { setError(''); setVersion(value => value + 1); }}>Aktivierungsstatus prüfen</button>}
    {status && (active ? <p role="status">Aktiv bis {new Date(active.expiresAt * 1000).toLocaleString('de-CH')} · noch {Math.max(0, Math.ceil((active.expiresAt * 1000 - now) / 60000))} Minuten</p> : <>
      <label className="block">Dauer <select aria-label="Aktivierungsdauer" className="fluent-input" value={duration} disabled={busy || disabled} onChange={event => { setDuration(Number(event.target.value)); setConfirmed(false); }}>
        {status.durations.map(value => <option key={value} value={value}>{value < 3600 ? `${value / 60} Minuten` : `${value / 3600} ${value === 3600 ? 'Stunde' : 'Stunden'}`}</option>)}
      </select></label>
      <label className="block">Begründung <input className="fluent-input" value={reason} maxLength={500} disabled={busy || disabled} onChange={event => { setReason(event.target.value); setConfirmed(false); }} /></label>
    </>)}
    {active && <button className="fluent-btn-secondary" disabled={busy || disabled} onClick={resume}>Aktivierung übernehmen</button>}
    {status && !active && status.requiresFreshMfa ? <div className="flex flex-wrap gap-3">
      <a className="fluent-btn-primary" href="/api/auth/oidc/login?returnTo=%2Fapplications">Anmeldung für Aktivierung bestätigen</a>
      <a className="fluent-btn-secondary" href="/mfa?returnTo=%2Fapplications">MFA einrichten oder prüfen</a>
    </div> : status && <>
      <label className="flex items-center gap-2"><input type="checkbox" checked={confirmed} disabled={busy || disabled} onChange={event => setConfirmed(event.target.checked)} />{active ? 'Aktivierung jetzt beenden' : 'Lizenzaufgaben für die gewählte Dauer aktivieren'}</label>
      <button className="fluent-btn-primary" disabled={disabled || busy || !confirmed || (!active && reason.trim().length < 5)} onClick={change}>{busy ? 'Wird geprüft …' : active ? 'Aktivierung beenden' : 'Berechtigung aktivieren'}</button>
    </>}
  </section>;
}
