'use client';

import { FormEvent, useEffect, useState } from 'react';

export default function ResetPasswordPage() {
  const [token, setToken] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const [complete, setComplete] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    setToken(new URLSearchParams(window.location.search).get('token') || '');
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setError('');
    if (!token) return setError('Der Reset-Link enthält keinen gültigen Token.');
    if (password !== confirmation) return setError('Die Passwörter stimmen nicht überein.');
    setBusy(true);
    try {
      const response = await fetch('/api/auth/password-reset/confirm', {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        signal: AbortSignal.timeout(10000),
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ token, newPassword: password }),
      });
      if (!response.ok) {
        const result = await response.json().catch(() => ({}));
        throw new Error(typeof result.error === 'string' ? result.error : 'Passwort konnte nicht zurückgesetzt werden.');
      }
      setComplete(true);
      setPassword('');
      setConfirmation('');
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Passwort konnte nicht zurückgesetzt werden.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <section className="w-full max-w-md rounded-xl border border-gray-200 bg-white p-8 shadow-sm">
        <h1 className="text-2xl font-semibold text-gray-900">Neues Passwort festlegen</h1>
        {complete ? (
          <div role="status" className="mt-5 space-y-4">
            <p className="text-sm text-green-800">Das Passwort wurde geändert. Melde dich mit dem neuen Passwort an.</p>
            <a className="inline-block text-sm text-blue-700 underline" href="/login">Zur Anmeldung</a>
          </div>
        ) : (
          <>
            <p className="mt-2 text-sm text-gray-600">Der Reset-Link ist eine Stunde gültig.</p>
            {error && <p role="alert" className="mt-5 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}
            <form className="mt-6 space-y-4" onSubmit={submit}>
              <label className="block text-sm font-medium text-gray-700" htmlFor="new-password">
                Neues Passwort
                <input id="new-password" className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2" type="password" autoComplete="new-password" required minLength={8} maxLength={128} value={password} onChange={event => setPassword(event.target.value)} />
              </label>
              <label className="block text-sm font-medium text-gray-700" htmlFor="confirm-password">
                Passwort wiederholen
                <input id="confirm-password" className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2" type="password" autoComplete="new-password" required minLength={8} maxLength={128} value={confirmation} onChange={event => setConfirmation(event.target.value)} />
              </label>
              <button className="w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50" type="submit" disabled={busy || !token}>
                {busy ? 'Passwort wird geändert …' : 'Passwort ändern'}
              </button>
            </form>
          </>
        )}
      </section>
    </main>
  );
}
