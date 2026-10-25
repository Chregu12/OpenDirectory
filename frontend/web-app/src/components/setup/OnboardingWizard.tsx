'use client';

import React, { useState } from 'react';
import toast from 'react-hot-toast';
import { api } from '@/lib/api';

type OnboardingWizardProps = {
  currentUser: { name: string; username: string } | null;
};

export default function OnboardingWizard({ currentUser }: OnboardingWizardProps) {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [domain, setDomain] = useState('');
  const [domainError, setDomainError] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validateDomain = (value: string) => /^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$/.test(value.trim());

  const handleStep1 = () => {
    if (!validateDomain(domain)) {
      setDomainError('Bitte eine gültige Domain eingeben (z.B. firma.local)');
      return;
    }
    setDomainError('');
    setStep(2);
  };

  const handleFinish = async () => {
    setLoading(true);
    setError(null);
    try {
      await api.post('/api/config/domain', {
        domain: domain.trim().toLowerCase(),
        issuer: window.location.origin,
      });

      localStorage.setItem('od_onboarded', 'true');
      toast.success('OpenDirectory ist bereit!');
      window.location.href = '/dashboard';
    } catch (err: unknown) {
      const errAny = err as { response?: { data?: { message?: string; error?: string } } };
      setError(errAny?.response?.data?.message || errAny?.response?.data?.error || 'Fehler beim Einrichten. Bitte versuche es erneut.');
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-50 p-4">
      <div className="w-full max-w-lg rounded-2xl bg-white shadow-2xl">
        <div className="flex gap-1 p-6 pb-0">
          {[1, 2, 3].map((item) => (
            <div key={item} className={`h-1.5 flex-1 rounded-full transition-all ${step >= item ? 'bg-blue-600' : 'bg-gray-200'}`} />
          ))}
        </div>

        <div className="p-8">
          {step === 1 && (
            <>
              <div className="mb-6 text-center">
                <div className="mx-auto mb-3 flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-600">
                  <span className="text-xl font-bold text-white">OD</span>
                </div>
                <h1 className="text-2xl font-bold text-gray-900">Willkommen bei OpenDirectory</h1>
                <p className="mt-1 text-sm text-gray-500">Einrichtung in 3 einfachen Schritten</p>
              </div>

              <h2 className="mb-4 text-base font-semibold text-gray-900">Schritt 1 von 3 — Domäne einrichten</h2>
              <label htmlFor="organization-domain" className="mb-1 block text-sm font-medium text-gray-700">Domänenname</label>
              <input
                id="organization-domain"
                type="text"
                autoComplete="url"
                value={domain}
                onChange={(event) => { setDomain(event.target.value); setDomainError(''); }}
                placeholder="firma.local oder firma.example.com"
                className={`w-full rounded-lg border bg-white px-3 py-2 text-sm text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 ${domainError ? 'border-red-400' : 'border-gray-300'}`}
                onKeyDown={(event) => { if (event.key === 'Enter') handleStep1(); }}
              />
              {domainError && <p className="mt-1 text-xs text-red-500">{domainError}</p>}
              <p className="mt-1 text-xs text-gray-500">Zum Beispiel firma.local (intern) oder firma.example.com</p>

              <button onClick={handleStep1} className="mt-6 w-full rounded-lg bg-blue-600 py-2.5 text-sm font-medium text-white transition-colors hover:bg-blue-700">Weiter</button>
            </>
          )}

          {step === 2 && (
            <>
              <h2 className="mb-1 text-base font-semibold text-gray-900">Schritt 2 von 3 — Administratorkonto bestätigen</h2>
              <p className="mb-4 text-sm text-gray-600">Für die Einrichtung wird dein bereits angemeldetes Konto verwendet. Du musst kein weiteres Konto und kein neues Passwort anlegen.</p>
              <div className="rounded-lg border border-blue-100 bg-blue-50 p-4 text-sm text-blue-950">
                <p className="font-medium">Angemeldet als</p>
                <p className="mt-1 break-all">{currentUser?.username || currentUser?.name || 'dein OpenDirectory-Konto'}</p>
              </div>
              <div className="mt-6 flex gap-3">
                <button onClick={() => setStep(1)} className="flex-1 rounded-lg border border-gray-200 py-2.5 text-sm text-gray-700 hover:bg-gray-50">Zurück</button>
                <button onClick={() => setStep(3)} className="flex-1 rounded-lg bg-blue-600 py-2.5 text-sm font-medium text-white hover:bg-blue-700">Weiter</button>
              </div>
            </>
          )}

          {step === 3 && (
            <>
              <h2 className="mb-1 text-base font-semibold text-gray-900">Schritt 3 von 3 — Erstes Gerät anmelden</h2>
              <p className="mb-4 text-sm text-gray-600">Die Anmeldung eines Geräts ist optional. Du kannst Geräte nach Abschluss jederzeit in der Geräteverwaltung hinzufügen.</p>

              <div className="rounded-lg border border-gray-200 bg-gray-50 p-4 text-sm text-gray-700">
                Überspringe diesen Schritt, wenn du noch kein Gerät anmelden möchtest. Der Einrichtungsassistent erstellt keine zusätzlichen Konten oder nicht verwendbaren Registrierungstoken.
              </div>

              {error && <p role="alert" className="mt-3 text-sm text-red-600">{error}</p>}

              <div className="mt-4 flex gap-3">
                <button onClick={() => setStep(2)} disabled={loading} className="flex-1 rounded-lg border border-gray-200 py-2.5 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">Zurück</button>
                <button onClick={handleFinish} disabled={loading} className="flex-1 rounded-lg bg-green-700 py-2.5 text-sm font-medium text-white hover:bg-green-800 disabled:cursor-not-allowed disabled:opacity-50">
                  {loading ? 'Wird eingerichtet…' : 'Überspringen und fertig'}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
