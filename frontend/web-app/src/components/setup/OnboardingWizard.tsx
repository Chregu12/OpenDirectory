'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import toast from 'react-hot-toast';

type OS = 'macos' | 'windows' | 'ubuntu';

const ENROLL_COMMANDS: Record<OS, string> = {
  macos:   'curl -fsSL https://opendirectory.local/api/enroll/macos/profile.mobileconfig?token=ENROLL_TOKEN -o od-enroll.mobileconfig && open od-enroll.mobileconfig',
  windows: 'irm https://opendirectory.local/api/enroll/windows/agent.ps1?token=ENROLL_TOKEN | iex',
  ubuntu:  'curl -fsSL https://opendirectory.local/api/enroll/linux/install.sh?token=ENROLL_TOKEN | sudo bash',
};

const OS_LABELS: Record<OS, { label: string; icon: string }> = {
  macos:   { label: 'macOS',   icon: '' },
  windows: { label: 'Windows', icon: '🪟' },
  ubuntu:  { label: 'Ubuntu',  icon: '🐧' },
};

function PasswordStrengthMeter({ password }: { password: string }) {
  const checks = [
    password.length >= 8,
    /[A-Z]/.test(password),
    /[0-9]/.test(password),
    /[^a-zA-Z0-9]/.test(password),
  ];
  const score = checks.filter(Boolean).length;
  const colors = ['bg-red-400', 'bg-orange-400', 'bg-yellow-400', 'bg-green-500'];
  const labels = ['Schwach', 'Ausreichend', 'Gut', 'Stark'];
  return (
    <div className="mt-1.5">
      <div className="flex gap-1">
        {[0,1,2,3].map(i => (
          <div key={i} className={`h-1.5 flex-1 rounded-full transition-colors ${i < score ? colors[score - 1] : 'bg-gray-200'}`} />
        ))}
      </div>
      {password.length > 0 && <p className={`text-xs mt-1 ${score >= 3 ? 'text-green-600' : score >= 2 ? 'text-yellow-600' : 'text-red-500'}`}>{labels[score - 1] ?? 'Zu kurz'}</p>}
    </div>
  );
}

export default function OnboardingWizard() {
  const router = useRouter();
  const [step, setStep] = useState<1 | 2 | 3>(1);

  // Step 1
  const [domain, setDomain] = useState('');
  const [domainError, setDomainError] = useState('');

  // Step 2
  const [adminName,  setAdminName]  = useState('');
  const [adminEmail, setAdminEmail] = useState('');
  const [adminPass,  setAdminPass]  = useState('');
  const [step2Error, setStep2Error] = useState('');

  // Step 3
  const [selectedOs, setSelectedOs] = useState<OS>('macos');
  const [copied, setCopied] = useState(false);

  const validateDomain = (v: string) => /^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$/.test(v.trim());

  const handleStep1 = () => {
    if (!validateDomain(domain)) { setDomainError('Bitte eine gültige Domain eingeben (z.B. firma.local)'); return; }
    setDomainError('');
    setStep(2);
  };

  const handleStep2 = () => {
    if (!adminName.trim() || !adminEmail.trim() || !adminPass.trim()) { setStep2Error('Alle Felder ausfüllen'); return; }
    if (!/^[^@]+@[^@]+\.[^@]+$/.test(adminEmail)) { setStep2Error('Ungültige E-Mail-Adresse'); return; }
    if (adminPass.length < 8) { setStep2Error('Passwort muss mindestens 8 Zeichen haben'); return; }
    setStep2Error('');
    setStep(3);
  };

  const handleFinish = () => {
    localStorage.setItem('od_onboarded', 'true');
    toast.success('OpenDirectory ist bereit!');
    router.push('/dashboard');
  };

  const copyCommand = () => {
    navigator.clipboard?.writeText(ENROLL_COMMANDS[selectedOs]).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 bg-gray-50 z-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg">
        {/* Progress bar */}
        <div className="flex gap-1 p-6 pb-0">
          {[1,2,3].map(s => (
            <div key={s} className={`flex-1 h-1.5 rounded-full transition-all ${step >= s ? 'bg-blue-600' : 'bg-gray-200'}`} />
          ))}
        </div>

        <div className="p-8">
          {/* ── Step 1: Domain ── */}
          {step === 1 && (
            <>
              <div className="text-center mb-6">
                <div className="w-14 h-14 bg-blue-600 rounded-2xl flex items-center justify-center mx-auto mb-3">
                  <span className="text-white font-bold text-xl">OD</span>
                </div>
                <h1 className="text-2xl font-bold text-gray-900">Willkommen bei OpenDirectory</h1>
                <p className="text-gray-500 text-sm mt-1">Einrichtung in 3 einfachen Schritten</p>
              </div>

              <h2 className="text-base font-semibold text-gray-900 mb-4">Schritt 1 von 3 — Domäne einrichten</h2>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Domänenname</label>
                  <input
                    type="text"
                    value={domain}
                    onChange={e => { setDomain(e.target.value); setDomainError(''); }}
                    placeholder="firma.local oder firma.company.com"
                    className={`w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 ${domainError ? 'border-red-400' : 'border-gray-300'}`}
                    onKeyDown={e => { if (e.key === 'Enter') handleStep1(); }}
                  />
                  {domainError && <p className="text-xs text-red-500 mt-1">{domainError}</p>}
                  <p className="text-xs text-gray-400 mt-1">Empfohlen: firma.local (intern) oder firma.example.com</p>
                </div>
              </div>

              <button onClick={handleStep1} className="w-full mt-6 py-2.5 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors">Weiter</button>
            </>
          )}

          {/* ── Step 2: Admin Account ── */}
          {step === 2 && (
            <>
              <h2 className="text-base font-semibold text-gray-900 mb-1">Schritt 2 von 3 — Admin-Konto einrichten</h2>
              <p className="text-sm text-gray-500 mb-4">Erstelle den ersten Administrator für <span className="font-medium text-gray-700">{domain}</span>.</p>

              <div className="space-y-3">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
                  <input value={adminName} onChange={e => setAdminName(e.target.value)} placeholder="Max Mustermann" className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">E-Mail</label>
                  <input type="email" value={adminEmail} onChange={e => setAdminEmail(e.target.value)} placeholder={`admin@${domain}`} className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Passwort</label>
                  <input type="password" value={adminPass} onChange={e => setAdminPass(e.target.value)} placeholder="Sicheres Passwort" className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
                  <PasswordStrengthMeter password={adminPass} />
                </div>
                {step2Error && <p className="text-xs text-red-500">{step2Error}</p>}
              </div>

              <div className="flex gap-3 mt-6">
                <button onClick={() => setStep(1)} className="flex-1 py-2.5 border border-gray-200 rounded-lg text-sm text-gray-600 hover:bg-gray-50">Zurück</button>
                <button onClick={handleStep2} className="flex-1 py-2.5 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700">Weiter</button>
              </div>
            </>
          )}

          {/* ── Step 3: Enroll first device ── */}
          {step === 3 && (
            <>
              <h2 className="text-base font-semibold text-gray-900 mb-1">Schritt 3 von 3 — Erstes Gerät anmelden</h2>
              <p className="text-sm text-gray-500 mb-4">Führe diesen Befehl auf dem Gerät aus, das du anmelden möchtest.</p>

              {/* OS Picker */}
              <div className="grid grid-cols-3 gap-2 mb-4">
                {(Object.keys(OS_LABELS) as OS[]).map(os => (
                  <button
                    key={os}
                    onClick={() => setSelectedOs(os)}
                    className={`flex flex-col items-center gap-1.5 p-3 rounded-lg border-2 text-xs font-medium transition-colors ${selectedOs === os ? 'border-blue-600 bg-blue-50 text-blue-700' : 'border-gray-200 text-gray-600 hover:border-gray-300'}`}
                  >
                    <span className="text-2xl">{OS_LABELS[os].icon}</span>
                    {OS_LABELS[os].label}
                  </button>
                ))}
              </div>

              <div className="bg-gray-900 rounded-lg p-3 mb-3 relative">
                <p className="text-green-400 text-xs font-mono break-all leading-relaxed">{ENROLL_COMMANDS[selectedOs]}</p>
              </div>

              <button onClick={copyCommand} className={`w-full py-2 text-sm rounded-lg border transition-colors ${copied ? 'bg-green-50 text-green-700 border-green-200' : 'bg-gray-50 text-gray-700 border-gray-200 hover:bg-gray-100'}`}>
                {copied ? 'Kopiert!' : 'Befehl kopieren'}
              </button>

              <div className="flex gap-3 mt-4">
                <button onClick={() => setStep(2)} className="flex-1 py-2.5 border border-gray-200 rounded-lg text-sm text-gray-600 hover:bg-gray-50">Zurück</button>
                <button onClick={handleFinish} className="flex-1 py-2.5 bg-green-600 text-white rounded-lg text-sm font-medium hover:bg-green-700">Fertig</button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
