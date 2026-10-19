'use client';

import React, { useState } from 'react';
import { mfaRecovery, mfaEnrollment, recoveryError, RecoverySetup } from '@/lib/mfaRecovery';

export default function MfaRecoveryView({ enrollment = false }: { enrollment?: boolean }) {
  const [username, setUsername] = useState(''); const [password, setPassword] = useState(''); const [providerCode, setProviderCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState(''); const [code, setCode] = useState('');
  const [setup, setSetup] = useState<RecoverySetup | null>(null); const [done, setDone] = useState(false); const [uncertain, setUncertain] = useState(false);
  const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  const [clientId, setClientId] = useState('web-app');
  async function submit() {
    if (busy || uncertain || done) return; setBusy(true); setError('');
    try {
      const credentials = { username, password, ...(providerCode ? { mfaCode: providerCode } : {}) };
      if (!setup) setSetup(enrollment ? await mfaEnrollment.start(clientId, credentials) : await mfaRecovery.start(credentials, recoveryCode));
      else { await (enrollment ? mfaEnrollment : mfaRecovery).confirm(setup.challenge, code); setSetup(null); setDone(true); }
    } catch (failure: any) {
      setError(recoveryError(failure, enrollment));
      if (!failure.response || failure.response.status >= 500 || ['invalid_recovery_challenge', 'recovery_identity_changed', 'invalid_enrollment_challenge', 'enrollment_authorization_changed'].includes(failure.response.data?.error)) { setSetup(null); setUncertain(true); }
    } finally { setPassword(''); setProviderCode(''); setRecoveryCode(''); setCode(''); setBusy(false); }
  }
  return <main className="min-h-screen bg-gray-950 text-white p-6 flex justify-center"><section className="w-full max-w-2xl space-y-5 py-10">
    <h1 className="text-2xl font-semibold">{enrollment ? 'OpenDirectory-MFA erstmals einrichten' : 'OpenDirectory-MFA wiederherstellen'}</h1>
    <p>{enrollment ? 'Nur für noch nicht eingerichtete Konten mit gültigem Anwendungszugriff und verbindlicher MFA-Richtlinie. Das aktuelle Passwort und ein Code des neuen Authenticators sind erforderlich; bestehende Faktoren lassen sich hier nicht ersetzen.' : 'Ein bereits gespeicherter Notfallcode und das aktuelle Passwort ersetzen ausschließlich den verlorenen OpenDirectory-Authenticator.'} Ein eventuell erforderlicher Faktor des Passwortanbieters bleibt erforderlich. Es wird keine Anwendungssitzung oder PIM-Berechtigung erteilt.</p>
    <p>{enrollment ? 'Die Ersteinrichtung gilt zehn Minuten und bleibt an den aktuellen Benutzer, die Anwendung, die Richtlinie und ihre Zugriffszuweisung gebunden.' : 'Ohne Notfallcode und Passwort ist diese Selbstwiederherstellung nicht möglich. Die Einrichtung gilt zehn Minuten; jeder Notfallcode wird beim Start genau einmal verbraucht.'} Nicht automatisch wiederholen.</p>
    {error && <p role="alert" className="text-amber-300">{error}</p>}
    {done && <p role="status">{enrollment ? 'Ersteinrichtung bestätigt. Bisherige schwächere Sitzungen sind ungültig.' : 'Faktorwechsel bestätigt. Alte Sitzungen, Notfallcodes und die bisherige Authenticator-Einrichtung sind ungültig.'} Mit Passwort und einem neuen Einmalcode normal anmelden und anschließend neue Notfallcodes erzeugen.</p>}
    {uncertain && <button className="border px-3 py-2 rounded" onClick={() => { setError(''); setUncertain(false); setSetup(null); }}>{enrollment ? 'Ersteinrichtung bewusst neu beginnen' : 'Mit anderem Notfallcode neu beginnen'}</button>}
    {!done && !uncertain && <form className="space-y-4" onSubmit={event => { event.preventDefault(); void submit(); }}>
      {!setup ? <>
        <label className="block">Eigener Benutzername<input className="block w-full border rounded p-2 bg-black/20" required autoComplete="username" disabled={busy} value={username} onChange={event => setUsername(event.target.value)} /></label>
        <label className="block">Aktuelles Passwort<input className="block w-full border rounded p-2 bg-black/20" required type="password" autoComplete="current-password" disabled={busy} value={password} onChange={event => setPassword(event.target.value)} /></label>
        <label className="block">Code des Passwortanbieters (optional)<input className="block w-full border rounded p-2 bg-black/20" autoComplete="one-time-code" disabled={busy} value={providerCode} onChange={event => setProviderCode(event.target.value)} /></label>
        {enrollment ? <label className="block">Anwendungs-ID für Ersteinrichtung<input className="block w-full border rounded p-2 bg-black/20" required autoComplete="off" maxLength={255} disabled={busy} value={clientId} onChange={event => setClientId(event.target.value)} /></label> : <label className="block">Gespeicherter Notfallcode<input className="block w-full border rounded p-2 bg-black/20" type="password" autoComplete="off" autoCapitalize="none" spellCheck={false} required pattern="[a-f0-9]{8}(-[a-f0-9]{8}){3}" disabled={busy} value={recoveryCode} onChange={event => setRecoveryCode(event.target.value)} /></label>}
        <button className="border px-3 py-2 rounded" disabled={busy}>{enrollment ? 'Ersteinrichtung vorbereiten' : 'Notfallcode verbrauchen und Faktor vorbereiten'}</button>
      </> : <>
        <p>Neuen Schlüssel manuell im Authenticator erfassen: SHA-1, sechs Stellen, 30 Sekunden. Erst dessen bestätigter Einmalcode ersetzt den bisherigen Faktor.</p>
        <code aria-label="Neuer MFA-Schlüssel" className="block select-all break-all border rounded p-3">{setup.secret}</code><p>Gültig bis: {setup.expiresAt}</p>
        <label className="block">Einmalcode des neuen Authenticators<input className="block w-full border rounded p-2 bg-black/20" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required disabled={busy} value={code} onChange={event => setCode(event.target.value)} /></label>
        <button className="border px-3 py-2 rounded" disabled={busy}>Neuen Faktor bestätigen</button>
      </>}
    </form>}
    <a className="inline-block underline" href="/login">Zur normalen Anmeldung</a>
  </section></main>;
}
