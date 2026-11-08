'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

export default function ServiceAvailabilityGate({ service, label, children }: { service: string; label: string; children: React.ReactNode }) {
  const [available, setAvailable] = useState<boolean | null>(null);
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true; setAvailable(null); setFailed(false);
    api.get('/api/platform/capabilities').then(({ data }) => {
      if (data.configuredServices !== null && (!Array.isArray(data.configuredServices) || data.configuredServices.some((value: unknown) => typeof value !== 'string'))) throw new Error('Invalid service capabilities');
      if (active) setAvailable(data.configuredServices === null || data.configuredServices.includes(service));
    }).catch(() => { if (active) setFailed(true); });
    return () => { active = false; };
  }, [service, attempt]);
  if (available) return <>{children}</>;
  return <section className="p-6 space-y-4" style={{ color: 'var(--text-primary)' }} aria-label={label}>
    <h1 className="text-2xl font-semibold">{label}</h1>
    {failed ? <div role="alert"><p>Der Einrichtungsstatus konnte nicht geprüft werden.</p><button className="fluent-btn-secondary mt-3" onClick={() => setAttempt(value => value + 1)}>Erneut prüfen</button></div>
      : available === null ? <p role="status">Einrichtungsstatus wird geprüft …</p>
      : <div className="od-card p-6 space-y-3"><h2 className="font-semibold">Erweiterung noch nicht eingerichtet</h2><p>Für {label} ist noch kein Dienst verbunden. Hier erscheinen echte Daten, sobald die Erweiterung eingerichtet ist.</p><a className="fluent-btn-secondary" href="/integrations">Integrationen öffnen</a></div>}
  </section>;
}
