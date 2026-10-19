'use client';

import React, { useEffect, useRef, useState } from 'react';
import OrganizationProfileFields from '@/components/OrganizationProfileFields';
import { OrganizationProfile } from '@/lib/organizationProfile';
import { companyRegistration, registrationError, CompanyRegistrationReceipt } from '@/lib/companyRegistration';

const empty: OrganizationProfile = { name: '', legalForm: '', registrationNumber: '', taxId: '', addressLine1: '', addressLine2: '', postalCode: '', city: '', country: '', timezone: 'UTC', defaultLanguage: 'de', contactEmail: '', contactPhone: '', website: '' };

export default function RegisterCompanyPage() {
  const [enabled, setEnabled] = useState<boolean | null>(null); const [profile, setProfile] = useState(empty); const [registrationId, setRegistrationId] = useState('');
  const [activationSupported, setActivationSupported] = useState(false); const [activationConfirmed, setActivationConfirmed] = useState(false);
  const [username, setUsername] = useState(''); const [password, setPassword] = useState(''); const [mfaCode, setMfaCode] = useState(''); const [confirmed, setConfirmed] = useState(false);
  const [receipt, setReceipt] = useState<CompanyRegistrationReceipt | null>(null); const [error, setError] = useState(''); const [busy, setBusy] = useState(false); const generation = useRef(0);
  useEffect(() => {
    const epoch = ++generation.current; const controller = new AbortController();
    try { setRegistrationId(sessionStorage.getItem('od_company_registration_id') || crypto.randomUUID()); } catch { setRegistrationId(crypto.randomUUID()); }
    companyRegistration.capabilities(controller.signal).then(result => { if (epoch === generation.current) { setEnabled(result.enabled); setActivationSupported(result.activationSupported); } }).catch(() => { if (epoch === generation.current) setError('Registrierungsdienst nicht verfügbar.'); });
    return () => { generation.current++; controller.abort(); };
  }, []);
  async function send(operation: 'submit' | 'status' | 'activate') {
    if (!enabled || busy || operation === 'submit' && !confirmed || operation === 'activate' && (!activationSupported || !activationConfirmed || receipt?.status !== 'pending-activation' || registrationId !== receipt.registrationId)) return;
    const epoch = generation.current; setBusy(true); setError(''); setReceipt(null);
    try {
      try { sessionStorage.setItem('od_company_registration_id', registrationId); } catch {}
      const credentials = { registrationId, username: username.trim(), password, mfaCode };
      const result = operation === 'submit' ? await companyRegistration.submit({ ...credentials, profile, confirm: true }) : operation === 'activate' ? await companyRegistration.activate({ ...credentials, confirm: true }) : await companyRegistration.status(credentials);
      if (epoch === generation.current) { setReceipt(result); setProfile(empty); setConfirmed(false); setActivationConfirmed(false); }
    } catch (failure) { if (epoch === generation.current) setError(registrationError(failure)); }
    finally { if (epoch === generation.current) { setBusy(false); setPassword(''); setMfaCode(''); } }
  }
  return <main className="min-h-screen bg-gray-50 text-gray-900 px-4 py-10"><div className="max-w-4xl mx-auto space-y-6">
    <header><a href="/login" className="text-blue-700 underline">Zur Anmeldung</a><h1 className="text-3xl font-semibold mt-4">Unternehmen anmelden</h1>
      <p className="mt-3">Erfasse dein Unternehmen zur Prüfung. Ein Antrag allein aktiviert weder Mandant noch Erstadministrator. Erst nach unabhängiger Freigabe kannst du die eigene Firma ausdrücklich aktivieren; vor der ersten Anmeldung ist MFA erforderlich.</p>
      <p className="mt-2">Du benötigst ein bereits vorhandenes Konto beim konfigurierten Anmeldedienst. Hier wird kein Passwortkonto, keine E-Mail-Verifizierung und keine Apple-Integration vorgetäuscht.</p></header>
    {error && <p role="alert" className="border border-red-400 rounded p-4">{error}</p>}
    {enabled === null && !error && <p role="status">Registrierungsdienst wird geprüft …</p>}
    {enabled === false && <p role="status">Die Firmenregistrierung ist durch den Betreiber nicht aktiviert.</p>}
    {receipt && <section role="status" className="bg-white border rounded-xl p-5 space-y-2"><h2 className="text-xl font-semibold">{({ 'pending-verification': 'Zur Prüfung vorgemerkt', 'pending-activation': 'Freigegeben – Aktivierung ausstehend', rejected: 'Antrag abgelehnt', active: 'Unternehmen aktiviert – MFA erforderlich', suspended: 'Unternehmenszugang gesperrt' })[receipt.status]}</h2>
      <p>Der tatsächliche Status ist {receipt.status === 'pending-verification' ? 'Pending Verification' : receipt.status}. {receipt.schemaVersion === 3 ? 'Firmenprofil und eigener Firmen-Owner sind gespeichert. Dies sind keine globalen Administratorrechte.' : 'Mandant und Administrator sind nicht aktiviert.'}</p>
      {receipt.schemaVersion !== 1 && <p>Prüfentscheidung gespeichert: <time dateTime={receipt.reviewedAt}>{new Date(receipt.reviewedAt).toLocaleString('de-CH')}</time>.</p>}
      {receipt.schemaVersion === 3 && receipt.status === 'active' && <p><a href="/auth/mfa-enroll" className="text-blue-700 underline">Pflicht-MFA einrichten</a>, danach <a href="/login" className="text-blue-700 underline">mit MFA anmelden</a>. Die Firmenrechte gelten nur im eigenen Mandanten.</p>}
      <dl className="break-all"><dt>Registrierungs-ID</dt><dd>{receipt.registrationId}</dd><dt>Mandanten-ID</dt><dd>{receipt.tenantId}</dd><dt>Vorgemerkter Administrator</dt><dd>{receipt.administratorId}</dd></dl>
      <p>{receipt.replayed ? 'Bestehende Registrierung bestätigt; kein zweiter Mandant angelegt.' : 'Gespeicherte Registrierung bestätigt.'}</p></section>}
    {enabled && receipt?.status === 'pending-activation' && <section className="bg-white border rounded-xl p-5 space-y-3"><h2 className="text-xl font-semibold">Eigene Firma aktivieren</h2>
      {activationSupported ? <><p>Gib Benutzername und aktuelles Passwort erneut im Formular ein. Die unabhängige Freigabe wird serverseitig geprüft; es werden nur die eigene Firma, das ursprüngliche Profil und der eigene Owner-Zugang aktiviert.</p>
        <label className="flex gap-3"><input type="checkbox" checked={activationConfirmed} disabled={busy} onChange={event => setActivationConfirmed(event.target.checked)} /><span>Ich bestätige die Aktivierung meiner freigegebenen Firma mit Pflicht-MFA und ohne globale Adminrechte.</span></label>
        <button type="button" className="bg-blue-600 text-white rounded px-4 py-2 disabled:opacity-50" disabled={busy || !activationConfirmed || !username.trim() || !password || registrationId !== receipt.registrationId} onClick={() => void send('activate')}>Freigegebene Firma aktivieren</button></> : <p>Der Betreiber hat die technische Aktivierung noch nicht freigeschaltet.</p>}
    </section>}
    {enabled && <form className="bg-white border rounded-xl p-6 space-y-6" onSubmit={event => { event.preventDefault(); void send('submit'); }}>
      <fieldset disabled={busy} className="space-y-4"><legend className="font-semibold mb-3">Bestehendes Anmeldekonto</legend>
        <label className="block" htmlFor="registration-id">Registrierungs-ID (für Statusabfrage aufbewahren)<input id="registration-id" className="block border rounded p-2 w-full" required value={registrationId} maxLength={36} onChange={event => setRegistrationId(event.target.value)} /></label>
        <label className="block" htmlFor="registration-username">Benutzername<input id="registration-username" className="block border rounded p-2 w-full" autoComplete="username" required maxLength={255} value={username} onChange={event => setUsername(event.target.value)} /></label>
        <label className="block" htmlFor="registration-password">Aktuelles Passwort<input id="registration-password" className="block border rounded p-2 w-full" type="password" autoComplete="current-password" required maxLength={4096} value={password} onChange={event => setPassword(event.target.value)} /></label>
        <label className="block" htmlFor="registration-mfa">Code des Anmeldediensts, falls dort erforderlich<input id="registration-mfa" className="block border rounded p-2 w-full" autoComplete="one-time-code" maxLength={128} value={mfaCode} onChange={event => setMfaCode(event.target.value)} /></label>
      </fieldset>
      <OrganizationProfileFields value={profile} onChange={setProfile} disabled={busy} prefix="company-registration" />
      <label className="flex items-start gap-3"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} disabled={busy} /><span>Ich möchte dieses Unternehmen zur Prüfung vormerken. Eine Aktivierung oder zusätzliche Berechtigung wird nicht behauptet.</span></label>
      <div className="flex flex-wrap gap-3"><button disabled={busy || !confirmed} className="bg-blue-600 text-white rounded px-4 py-2 disabled:opacity-50">{busy ? 'Wird geprüft …' : 'Unternehmen zur Prüfung anmelden'}</button>
        <button type="button" disabled={busy || !username.trim() || !password || !registrationId} className="border rounded px-4 py-2 disabled:opacity-50" onClick={() => void send('status')}>Bestehenden Status prüfen</button></div>
      <p className="text-sm">Nur die Registrierungs-ID wird im Sitzungsspeicher abgelegt, nie Passwort oder Firmendaten. Bei verlorener Bestätigung erneut Zugangsdaten eingeben und Status prüfen; keine automatischen Wiederholungen.</p>
    </form>}
  </div></main>;
}
