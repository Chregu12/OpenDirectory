'use client';

import { FormEvent, useState } from 'react';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setMessage('');
    setError('');
    try {
      const response = await fetch('/api/auth/reset-password', {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        signal: AbortSignal.timeout(10000),
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ email: email.trim() }),
      });
      if (!response.ok) throw new Error('Der Reset-Dienst ist derzeit nicht erreichbar.');
      setMessage('Falls ein Konto existiert und der Mailversand eingerichtet ist, wird ein Reset-Link gesendet.');
      setEmail('');
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Reset-Anfrage fehlgeschlagen.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <section className="w-full max-w-md rounded-xl border border-gray-200 bg-white p-8 shadow-sm">
        <h1 className="text-2xl font-semibold text-gray-900">Passwort zurücksetzen</h1>
        <p className="mt-2 text-sm text-gray-600">Gib die E-Mail-Adresse deines OpenDirectory-Kontos ein.</p>
        {message && <p role="status" className="mt-5 rounded-lg border border-green-200 bg-green-50 px-3 py-2 text-sm text-green-800">{message}</p>}
        {error && <p role="alert" className="mt-5 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}
        <form className="mt-6 space-y-4" onSubmit={submit}>
          <label className="block text-sm font-medium text-gray-700" htmlFor="reset-email">
            E-Mail-Adresse
            <input id="reset-email" className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2" type="email" autoComplete="email" required maxLength={254} value={email} onChange={event => setEmail(event.target.value)} />
          </label>
          <button className="w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50" type="submit" disabled={busy}>
            {busy ? 'Anfrage wird gesendet …' : 'Reset-Link anfordern'}
          </button>
        </form>
        <a className="mt-6 inline-block text-sm text-blue-700 underline" href="/login">Zur Anmeldung</a>
      </section>
    </main>
  );
}
