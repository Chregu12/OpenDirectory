'use client';

import React, { useEffect, useState } from 'react';
import { startLogin } from '@/lib/auth';
import { verifiedMfa, mfaError, MfaStatus, MfaSetup } from '@/lib/verifiedMfa';
import MfaRecoveryCodesView from './MfaRecoveryCodesView';

export default function MFAView() {
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [setup, setSetup] = useState<MfaSetup | null>(null);
  const [username, setUsername] = useState(''); const [password, setPassword] = useState('');
  const [providerCode, setProviderCode] = useState(''); const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  const [attempt, setAttempt] = useState(0); const [changed, setChanged] = useState(false);
  const [uncertain, setUncertain] = useState(false); const [disabling, setDisabling] = useState(false);

  useEffect(() => {
    let active = true; const controller = new AbortController(); setStatus(null);
    verifiedMfa.status(controller.signal).then(value => { if (active) setStatus(value); })
      .catch(failure => { if (active) setError(mfaError(failure)); });
    return () => { active = false; controller.abort(); };
  }, [attempt]);

  async function change(action: 'enroll' | 'confirm' | 'disable') {
    if (busy || uncertain) return; setBusy(true); setError('');
    try {
      const credentials = { username, password, ...(providerCode ? { mfaCode: providerCode } : {}) };
      if (action === 'enroll') setSetup(await verifiedMfa.enroll(credentials));
      else {
        if (action === 'confirm') await verifiedMfa.confirm(code);
        else await verifiedMfa.disable(credentials, code);
        setChanged(true); setSetup(null); setStatus(null);
      }
    } catch (failure: any) {
      setError(mfaError(failure));
      if (!failure?.response || failure.response.status >= 500 || failure.response.status === 401 && failure.response.data?.error !== 'invalid_otp' && failure.response.data?.error !== 'invalid_credentials') { setUncertain(true); setSetup(null); }
    } finally { setPassword(''); setProviderCode(''); setCode(''); setBusy(false); }
  }

  const credentials = <div className="grid gap-3 max-w-lg">
    <label>Eigener Benutzername<input className="block w-full bg-black/20 border p-2 rounded" autoComplete="username" value={username} onChange={event => setUsername(event.target.value)} required disabled={busy} /></label>
    <label>Aktuelles Passwort<input className="block w-full bg-black/20 border p-2 rounded" type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required disabled={busy} /></label>
    <label>Code des Passwortanbieters (optional)<input className="block w-full bg-black/20 border p-2 rounded" autoComplete="one-time-code" value={providerCode} onChange={event => setProviderCode(event.target.value)} disabled={busy} /></label>
  </div>;
  const otp = <label>Neuer OpenDirectory-Einmalcode<input className="block w-full max-w-lg bg-black/20 border p-2 rounded" value={code} onChange={event => setCode(event.target.value)} autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} required disabled={busy} /></label>;

  return <section className="p-6 space-y-5 text-white max-w-4xl">
    <h1 className="text-2xl font-semibold">MFA – eigenes Konto</h1>
    <p>OpenDirectory prüft diesen TOTP-Faktor selbst. Nach der Einrichtung ist er bei jeder neuen Benutzeranmeldung erforderlich. Eine PIM-Aktivierung verlangt Passwort und Einmalcode aus einer höchstens fünf Minuten alten Anmeldung.</p>
    <p>Keine SMS- oder Passkey-Unterstützung in diesem Ausbau. Nach der Einrichtung neu anmelden und eigene Notfallcodes mit Passwort und einem unverbrauchten Einmalcode erzeugen. Diese Codes sicher getrennt aufbewahren; ohne sie gibt es keine Selbstwiederherstellung bei verlorenem Authenticator.</p>
    {error && <p role="alert" className="text-amber-300">{error}</p>}
    {changed && <p role="status">Änderung bestätigt. Alle bisherigen Tokens dieses Kontos sind ungültig. Vor der nächsten Anmeldung einen neuen Einmalcode abwarten.</p>}
    {(changed || uncertain) ? <button className="border rounded px-4 py-2" onClick={startLogin}>Erneut anmelden und Status prüfen</button> : <>
      <button disabled={busy} className="border rounded px-4 py-2" onClick={() => { setError(''); setSetup(null); setDisabling(false); setAttempt(value => value + 1); }}>Status neu laden</button>
      {!status && !error && <p role="status">MFA-Status wird geprüft …</p>}
      {status && <p role="status">{status.enabled ? 'TOTP aktiviert' : status.pending ? 'Einrichtung noch nicht bestätigt' : 'TOTP nicht eingerichtet'}</p>}
      {status && !status.enabled && !setup && <form className="space-y-4" onSubmit={event => { event.preventDefault(); void change('enroll'); }}>
        <p>Die eigenen Anmeldedaten werden erneut geprüft. Ein neuer Start ersetzt eine bisher unbestätigte Einrichtung. Nur diese Browsersitzung darf den Faktor innerhalb von zehn Minuten bestätigen.</p>
        {credentials}<button disabled={busy} className="border rounded px-4 py-2">TOTP einrichten</button>
      </form>}
      {setup && <form className="space-y-4" onSubmit={event => { event.preventDefault(); void change('confirm'); }}>
        <p>Diesen geheimen Schlüssel manuell im Authenticator als zeitbasiertes Konto erfassen: SHA-1, 6 Stellen, 30 Sekunden. Nicht weitergeben.</p>
        <code className="block break-all border p-3 select-all">{setup.secret}</code><p>Einrichtung gültig bis: {setup.expiresAt}</p>
        {otp}<button disabled={busy} className="border rounded px-4 py-2">Einrichtung bestätigen</button>
      </form>}
      {status?.enabled && !disabling && <button className="border rounded px-4 py-2" onClick={() => setDisabling(true)}>Deaktivierung vorbereiten</button>}
      {status?.enabled && !disabling && <MfaRecoveryCodesView />}
      {status?.enabled && disabling && <form className="space-y-4" onSubmit={event => { event.preventDefault(); void change('disable'); }}>
        <p>Deaktivierung erfordert erneut das Passwort und einen unverbrauchten OpenDirectory-Code. Danach bleibt PIM ohne neuen Faktor gesperrt.</p>
        {credentials}{otp}<button disabled={busy} className="border rounded px-4 py-2">TOTP endgültig deaktivieren</button>
      </form>}
    </>}
  </section>;
}
