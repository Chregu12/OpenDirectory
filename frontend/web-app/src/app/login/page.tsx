'use client';

import React, { useState } from 'react';
import ThemeSelector from '@/components/layout/ThemeSelector';
import { startLogin } from '@/lib/auth';

export default function LoginPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSignIn = async () => {
    setError('');
    setLoading(true);
    try {
      await startLogin();
      // startLogin() redirects the browser — execution will not continue here
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Anmeldung konnte nicht gestartet werden';
      setError(message);
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-[var(--bg-base)] flex items-center justify-center p-4"><div className="fixed right-4 top-4"><ThemeSelector /></div>
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center mb-4 shadow-md">
            <span className="text-white font-bold text-lg">OD</span>
          </div>
          <h1 className="text-2xl font-semibold text-[var(--text-primary)]">OpenDirectory</h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1">Mit deinem Konto anmelden</p>
        </div>

        {/* Card */}
        <div className="bg-[var(--bg-surface)] rounded-xl shadow-sm border border-[var(--border-strong)] p-8">
          {error && (
            <div role="alert" className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg px-3 py-2 mb-5">
              {error}
            </div>
          )}

          <button
            onClick={handleSignIn}
            disabled={loading}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? 'Weiterleitung …' : 'Mit OpenDirectory anmelden'}
          </button>
          <a className="block text-sm text-[var(--text-link)] underline mt-4" href="/forgot-password">Passwort vergessen?</a>
          <a className="block text-sm text-[var(--text-link)] underline mt-5" href="/auth/mfa-recovery">Authenticator verloren? Mit Notfallcode wiederherstellen</a>
          <a className="block text-sm text-[var(--text-link)] underline mt-3" href="/auth/mfa-enroll">MFA-pflichtige Anwendung: Faktor erstmals einrichten</a>
          <a className="block text-sm text-[var(--text-link)] underline mt-3" href="/register">Unternehmen zur Prüfung anmelden</a>
        </div>

        <p className="text-center text-xs text-gray-400 mt-6">
          OpenDirectory
        </p>
      </div>
    </main>
  );
}
