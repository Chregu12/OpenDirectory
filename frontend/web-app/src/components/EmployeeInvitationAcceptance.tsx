'use client';

import React, { useEffect, useRef, useState } from 'react';
import { employeeInvitation, employeeInvitationError, EmployeeInvitationAcceptance, EmployeeInvitationPreview } from '@/lib/employeeInvitation';

function invitationTokenFromHash() {
  const raw = window.location.hash.slice(1);
  if (!raw) return '';
  try { return raw.startsWith('token=') ? decodeURIComponent(raw.slice(6)) : decodeURIComponent(raw); }
  catch { return ''; }
}

export default function EmployeeInvitationAcceptancePage() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [token, setToken] = useState('');
  const [preview, setPreview] = useState<EmployeeInvitationPreview | null>(null);
  const [accepted, setAccepted] = useState<EmployeeInvitationAcceptance | null>(null);
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const generation = useRef(0);

  useEffect(() => {
    const controller = new AbortController(); const epoch = ++generation.current;
    const value = invitationTokenFromHash();
    if (value) { setToken(value); window.history.replaceState(null, '', window.location.pathname); }
    employeeInvitation.capabilities(controller.signal).then(result => {
      if (generation.current === epoch) setEnabled(result.enabled);
      if (value && generation.current === epoch) void inspect(value, epoch);
    }).catch(() => { if (generation.current === epoch) setError('Der Einladungsdienst ist nicht verfügbar.'); });
    return () => { generation.current++; controller.abort(); };
  }, []);

  async function inspect(value = token, epoch = generation.current) {
    if (!value || busy) return;
    setBusy(true); setError(''); setAccepted(null);
    try {
      const result = await employeeInvitation.inspect(value);
      if (generation.current === epoch) { setPreview(result); setToken(value); setPassword(''); setConfirmation(''); }
    } catch (failure) { if (generation.current === epoch) { setPreview(null); setError(employeeInvitationError(failure)); } }
    finally { if (generation.current === epoch) setBusy(false); }
  }

  async function accept() {
    if (busy || !preview || !token || password.length < 12 || password !== confirmation || preview.status === 'accepted') return;
    const epoch = generation.current; setBusy(true); setError('');
    try {
      const result = await employeeInvitation.accept(token, password);
      if (generation.current === epoch) { setAccepted(result); setPreview({ ...preview, status: 'accepted', credentialCreated: true, identityConfirmed: true }); setToken(''); window.history.replaceState(null, '', window.location.pathname); }
    } catch (failure) { if (generation.current === epoch) setError(employeeInvitationError(failure)); }
    finally { if (generation.current === epoch) { setBusy(false); setPassword(''); setConfirmation(''); } }
  }

  const enrollmentLink = '/login';
  const complete = !!accepted || preview?.status === 'accepted';

  return <main className="min-h-screen bg-gray-50 text-gray-900 px-4 py-10"><section className="max-w-2xl mx-auto space-y-6">
    <header className="space-y-3"><a href="/login" className="text-blue-700 underline">Zur Anmeldung</a><h1 className="text-3xl font-semibold">Mitarbeitereinladung annehmen</h1>
      <p>Prüfe deine Einladung und lege ein eigenes Passwort fest. Die erste Anmeldung führt dich durch die OpenDirectory-MFA-Einrichtung, falls deine App sie verlangt.</p>
      <p>Der Einladungslink ist vertraulich. Das Token wird nur im Arbeitsspeicher dieser Seite verwendet und nicht im Browser-Verlauf, in der URL oder im Sitzungsspeicher abgelegt.</p></header>
    {error && <p role="alert" className="border border-red-400 rounded p-4">{error}</p>}
    {enabled === null && !error && <p role="status">Einladungsdienst wird geprüft …</p>}
    {enabled === false && <p role="status">Die Annahme von Mitarbeitereinladungen ist derzeit deaktiviert.</p>}
    {enabled && !preview && <form className="bg-white border rounded-xl p-6 space-y-4" onSubmit={event => { event.preventDefault(); void inspect(); }}>
      <label className="block" htmlFor="employee-invitation-token">Vertrauliches Einladungs-Token<input id="employee-invitation-token" className="block border rounded p-2 w-full" type="password" autoComplete="off" autoCapitalize="none" spellCheck={false} required maxLength={80} value={token} onChange={event => setToken(event.target.value)} /></label>
      <button className="bg-blue-600 text-white rounded px-4 py-2 disabled:opacity-50" disabled={busy || token.length !== 80}>{busy ? 'Wird geprüft …' : 'Einladung prüfen'}</button>
      <p className="text-sm">Falls du den Link per E-Mail erhalten hast, öffne den Link direkt. Du kannst das Token hier auch manuell einfügen.</p>
    </form>}
    {preview && <section className="bg-white border rounded-xl p-6 space-y-4" aria-live="polite">
      <h2 className="text-xl font-semibold">{complete ? 'Konto aktiviert' : 'Einladung geprüft'}</h2>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2"><dt>Organisation</dt><dd>{preview.organizationName}</dd><dt>Benutzername</dt><dd>{preview.loginName}</dd><dt>Einladung gültig bis</dt><dd><time dateTime={preview.expiresAt}>{new Date(preview.expiresAt).toLocaleString('de-CH')}</time></dd></dl>
      {complete ? <><p>Dein Zugang wurde aktiviert. Melde dich jetzt mit der dir zugewiesenen App und deinem neuen Passwort an. Falls diese App MFA verlangt, richtest du den Faktor direkt auf der Anmeldeseite ein und setzt die Anmeldung danach fort.</p><a className="inline-block bg-blue-600 text-white rounded px-4 py-2" href={enrollmentLink}>Mit OpenDirectory anmelden</a></>
        : <form className="space-y-4" onSubmit={event => { event.preventDefault(); void accept(); }}>
          <p>Lege ein Passwort mit mindestens 12 Zeichen fest. Bei einem abgebrochenen Abschluss kannst du denselben Link und dasselbe Passwort erneut verwenden.</p>
          <label className="block" htmlFor="employee-password">Neues Passwort<input id="employee-password" className="block border rounded p-2 w-full" type="password" autoComplete="new-password" minLength={12} maxLength={72} required value={password} onChange={event => setPassword(event.target.value)} disabled={busy} /></label>
          <label className="block" htmlFor="employee-password-confirmation">Passwort wiederholen<input id="employee-password-confirmation" className="block border rounded p-2 w-full" type="password" autoComplete="new-password" minLength={12} maxLength={72} required value={confirmation} onChange={event => setConfirmation(event.target.value)} disabled={busy} /></label>
          <button className="bg-blue-600 text-white rounded px-4 py-2 disabled:opacity-50" disabled={busy || password.length < 12 || password !== confirmation}>{busy ? 'Zugang wird aktiviert …' : 'Einladung annehmen und Zugang aktivieren'}</button>
        </form>}
      <button type="button" className="underline text-sm" disabled={busy} onClick={() => { setPreview(null); setAccepted(null); setPassword(''); setConfirmation(''); setError(''); }}>Andere Einladung prüfen</button>
    </section>}
  </section></main>;
}
