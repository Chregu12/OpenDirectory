'use client';

import React, { useEffect, useRef, useState } from 'react';
import { directoryUsers } from '@/lib/directoryUsers';
import { OffboardingAccessBinding, offboardingAccessIdentifier, offboardingAccessError } from '@/lib/companyOffboardingAccess';
import CompanyOffboardingAccessPanel from './CompanyOffboardingAccessPanel';

export default function CompanyOffboardingAccessView() {
  const [userId, setUserId] = useState(''); const [workflowId, setWorkflowId] = useState('');
  const [binding, setBinding] = useState<OffboardingAccessBinding | null>(null);
  const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  const generation = useRef(0); const running = useRef(false);
  useEffect(() => {
    const invalidate = () => { generation.current++; running.current = false; setBusy(false); setBinding(null); setError('Sitzung geändert. Erneut anmelden und Arbeitsbereich ausdrücklich öffnen.'); };
    window.addEventListener('od:session-error', invalidate);
    return () => { generation.current++; window.removeEventListener('od:session-error', invalidate); };
  }, []);
  const open = async (event: React.FormEvent) => {
    event.preventDefault(); if (running.current) return;
    setBinding(null); setError('');
    let target: string; let workflow: string;
    try { target = offboardingAccessIdentifier(userId.trim()); workflow = offboardingAccessIdentifier(workflowId.trim()); }
    catch { setError('Kanonische Benutzer-ID und Vorgangs-ID der Kontosperre erforderlich (UUID, Kleinbuchstaben).'); return; }
    const expected = ++generation.current; running.current = true; setBusy(true);
    try {
      const access = await directoryUsers.access();
      if (expected !== generation.current) return;
      if (access.demoMode || !access.userId) throw new Error('Kein bestätigter menschlicher Benutzer.');
      const actor = offboardingAccessIdentifier(access.userId);
      if (actor === target) { setError('Eigene Berechtigungen können in diesem Austrittsschritt nicht widerrufen werden.'); return; }
      setBinding({ expectedActorUserId: actor, userId: target, workflowId: workflow });
    } catch (failure) { if (expected === generation.current) setError(offboardingAccessError(failure)); }
    finally { if (expected === generation.current) { running.current = false; setBusy(false); } }
  };
  return <section className="p-6 max-w-5xl space-y-5" style={{ color: 'var(--text-primary)' }}>
    <header><h1 className="text-2xl font-semibold">Berechtigungsentzug beim Austritt</h1><p className="mt-2">Bekannte Benutzer-ID und ursprünglichen Kontosperrnachweis verwenden. Rollen- und PIM-Rechte werden unabhängig geprüft, ohne Benutzerlisten- oder App-Verwaltungsrecht vorauszusetzen.</p></header>
    <form onSubmit={open} className="space-y-3">
      <label className="block">Benutzer-ID<input className="block w-full rounded border p-2 bg-transparent" value={userId} disabled={busy} onChange={event => { generation.current++; setBinding(null); setUserId(event.target.value); }} /></label>
      <label className="block">Vorgangs-ID der Kontosperre<input className="block w-full rounded border p-2 bg-transparent" value={workflowId} disabled={busy} onChange={event => { generation.current++; setBinding(null); setWorkflowId(event.target.value); }} /></label>
      <button className="fluent-btn-secondary" disabled={busy}>Arbeitsbereich öffnen</button>
    </form>
    {busy && <p role="status">Menschliche Identität wird geprüft …</p>}{error && <p role="alert">{error}</p>}
    {binding && <CompanyOffboardingAccessPanel {...binding} />}
  </section>;
}
