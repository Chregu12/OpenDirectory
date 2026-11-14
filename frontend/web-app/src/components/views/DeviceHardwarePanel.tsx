'use client';
import React, { useEffect, useRef, useState } from 'react';
import { AgentInventory, readAgentInventory, gibibytes, uptime } from '@/lib/agentInventory';
import type { Device } from '@/lib/deviceInventory';
import type { AgentConnection } from '@/lib/deviceAgents';
const labels = { current: 'Aktuelle Meldung', stale: 'Ältere Meldung', historical: 'Frühere Geräteverbindung', missing: 'Keine Systemdaten' };
export default function DeviceHardwarePanel({ device, actor, connection, onSecurityError }: { device: Device; actor: string; connection: AgentConnection; onSecurityError: (failure: unknown) => void }) {
  const [data, setData] = useState<AgentInventory | null>(null), [error, setError] = useState('');
  const failure = useRef(onSecurityError); failure.current = onSecurityError;
  useEffect(() => {
    const controller = new AbortController(); setData(null); setError('');
    void readAgentInventory(device, actor, controller.signal).then(value => { if (!controller.signal.aborted) setData(value); }).catch(error => {
      if (controller.signal.aborted) return;
      if ([401, 403, 428].includes(error?.response?.status)) failure.current(error);
      else setError([404, 501].includes(error?.response?.status) ? 'Systemmeldungen sind auf diesem Server noch nicht verfügbar.' : 'Systemdaten konnten nicht bestätigt werden. Verbindungsstatus erneut laden.');
    });
    return () => controller.abort();
  }, [device.id, device.revision, actor, connection]);
  const facts = data?.inventory?.facts;
  return <section aria-label="System und Hardware" className="space-y-3">
    <div className="flex flex-wrap gap-3 items-center"><h4 className="font-semibold">System und Hardware</h4>{data && <span className="od-badge">{labels[data.status]}</span>}</div>
    {error ? <p role="alert">{error}</p> : !data ? <p role="status">Systemdaten werden geladen …</p> : !facts ? <p className="text-sm opacity-70">Noch keine Systemdaten gemeldet. Den registrierten Agenten ab Version 1.2.0 starten.</p> : <>
      <dl className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3 text-sm">
        <div className="rounded border border-[var(--border)] p-3"><dt className="opacity-70">Prozessor</dt><dd className="mt-1 break-words">{facts.cpu ? <>{facts.cpu.model || 'Modell unbekannt'}<span className="block mt-1">{facts.cpu.logicalProcessors} logische Prozessoren</span></> : 'Unbekannt'}</dd></div>
        {([['Arbeitsspeicher', facts.memory], ['Systemdatenträger', facts.systemDisk]] as const).map(([label, value]) => <div key={label} className="rounded border border-[var(--border)] p-3"><dt className="opacity-70">{label}</dt><dd className="mt-1">{value ? <>{gibibytes(value.totalBytes)} gesamt<span className="block mt-1">{gibibytes(value.availableBytes)} verfügbar</span><progress className="mt-2 w-full" aria-label={label + ' belegt'} max={100} value={Number((BigInt(value.totalBytes) - BigInt(value.availableBytes)) * BigInt("100") / BigInt(value.totalBytes))} /></> : 'Unbekannt'}</dd></div>)}
        <div className="rounded border border-[var(--border)] p-3"><dt className="opacity-70">Laufzeit seit Start</dt><dd className="mt-1">{facts.uptimeSeconds === null ? 'Unbekannt' : uptime(facts.uptimeSeconds)}</dd></div>
      </dl>
      <p className="text-xs opacity-70">Gemeldet am {new Date(data.inventory!.receivedAt).toLocaleString('de-CH')} · Agent {data.inventory!.agentVersion} · geprüft am {new Date(data.checkedAt).toLocaleString('de-CH')}. Angaben stammen vom Gerät; dies ist keine Compliance-Bestätigung.</p>
    </>}
  </section>;
}
