'use client';

import React, { useEffect, useState } from 'react';
import { mfaRecovery, recoveryError } from '@/lib/mfaRecovery';
import { startLogin } from '@/lib/auth';

export default function MfaRecoveryCodesView() {
  const [remaining, setRemaining] = useState<number | null>(null); const [codes, setCodes] = useState<string[]>([]);
  const [open, setOpen] = useState(false); const [busy, setBusy] = useState(false); const [uncertain, setUncertain] = useState(false);
  const [username, setUsername] = useState(''); const [password, setPassword] = useState(''); const [providerCode, setProviderCode] = useState(''); const [code, setCode] = useState('');
  const [error, setError] = useState('');
  useEffect(() => {
    let active = true; const controller = new AbortController();
    mfaRecovery.status(controller.signal).then(value => { if (active) setRemaining(value); }).catch(failure => { if (active) setError(recoveryError(failure)); });
    return () => { active = false; controller.abort(); };
  }, []);
  async function rotate() {
    if (busy || uncertain) return; setBusy(true); setError(''); setCodes([]);
    try {
      const confirmed = await mfaRecovery.rotate({ username, password, ...(providerCode ? { mfaCode: providerCode } : {}) }, code);
      setCodes(confirmed); setRemaining(confirmed.length); setOpen(false);
    } catch (failure: any) {
      setError(recoveryError(failure));
      if (!failure.response || failure.response.status >= 500 || failure.response.status === 401 && !['invalid_otp', 'invalid_credentials'].includes(failure.response.data?.error)) setUncertain(true);
    } finally { setPassword(''); setProviderCode(''); setCode(''); setBusy(false); }
  }
  return <section className="border border-white/20 rounded p-4 space-y-4" aria-label="Eigene Notfallcodes">
    <h2 className="text-lg font-semibold">Notfallcodes für einen verlorenen Authenticator</h2>
    <p>Jeder Code funktioniert genau einmal, nur zusammen mit dem Passwort und nur zur Einrichtung eines neuen Faktors. Er meldet nicht an und ersetzt keine frische MFA für PIM. Codes offline und getrennt vom Passwort aufbewahren.</p>
    {remaining !== null && <p role="status">Verfügbare Notfallcodes: {remaining}</p>}
    {remaining === 0 && <p className="text-amber-300">Ohne gespeicherten Notfallcode ist diese Selbstwiederherstellung nicht möglich. Jetzt vorsorgen.</p>}
    {error && <p role="alert">{error}</p>}
    {codes.length > 0 && <div className="space-y-3">
      <p role="status">Neue Codes bestätigt. Jetzt sicher aufbewahren; sie werden nur hier einmal angezeigt. Alle bisherigen Codes und offenen Wiederherstellungen sind ungültig.</p>
      <ul aria-label="Neue Notfallcodes" className="space-y-2">{codes.map(value => <li key={value}><code className="select-all break-all">{value}</code></li>)}</ul>
      <button className="border px-3 py-2 rounded" onClick={() => setCodes([])}>Codes ausblenden</button>
    </div>}
    {uncertain ? <button className="border px-3 py-2 rounded" onClick={startLogin}>Vor weiteren Änderungen neu anmelden</button> : remaining !== null && !open && codes.length === 0 && <button className="border px-3 py-2 rounded" onClick={() => setOpen(true)}>Notfallcodes vorbereiten</button>}
    {open && !uncertain && <form className="grid gap-3 max-w-lg" onSubmit={event => { event.preventDefault(); void rotate(); }}>
      <p>Das Ersetzen widerruft alle bisherigen Codes und offenen Wiederherstellungen. Passwort und ein neuer, noch nicht verwendeter Einmalcode sind erforderlich.</p>
      <label>Benutzername für Notfallcodes<input className="block w-full bg-black/20 border p-2 rounded" autoComplete="username" required disabled={busy} value={username} onChange={event => setUsername(event.target.value)} /></label>
      <label>Passwort für Notfallcodes<input className="block w-full bg-black/20 border p-2 rounded" type="password" autoComplete="current-password" required disabled={busy} value={password} onChange={event => setPassword(event.target.value)} /></label>
      <label>Anbieter-Code für Notfallcodes (optional)<input className="block w-full bg-black/20 border p-2 rounded" autoComplete="one-time-code" disabled={busy} value={providerCode} onChange={event => setProviderCode(event.target.value)} /></label>
      <label>Neuer Einmalcode für Notfallcodes<input className="block w-full bg-black/20 border p-2 rounded" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required disabled={busy} value={code} onChange={event => setCode(event.target.value)} /></label>
      <button className="border px-3 py-2 rounded" disabled={busy}>Bisherige Codes ersetzen und neue erzeugen</button>
      <button type="button" className="border px-3 py-2 rounded" disabled={busy} onClick={() => { setOpen(false); setPassword(''); setProviderCode(''); setCode(''); }}>Abbrechen</button>
    </form>}
  </section>;
}
