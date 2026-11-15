'use client';

import React, { useEffect, useRef, useState } from 'react';
import type { Device } from '@/lib/deviceInventory';
import { readDeviceOuStatus, type DeviceOuAssignment, type DeviceOuCurrentStatus as CurrentStatus } from '@/lib/deviceOrganizationalUnits';

export default function DeviceOuCurrentStatus({ device, actor, assignment, disabled, onSecurityError }: {
  device: Device; actor: string; assignment: DeviceOuAssignment; disabled: boolean; onSecurityError: (error: unknown) => void;
}) {
  const [data, setData] = useState<CurrentStatus | null>(null), [error, setError] = useState(''), [unsupported, setUnsupported] = useState(false), [loading, setLoading] = useState(false), [reload, setReload] = useState(0);
  const callback = useRef(onSecurityError); callback.current = onSecurityError;
  useEffect(() => {
    const controller = new AbortController(); let timer: ReturnType<typeof setTimeout> | undefined;
    setData(null); setError(''); setUnsupported(false); setLoading(true);
    const session = () => { controller.abort(); clearTimeout(timer); setData(null); setLoading(false); setError('Bitte für die aktuelle OU-Prüfung erneut anmelden.'); };
    window.addEventListener('od:session-error', session);
    void readDeviceOuStatus(device, actor, assignment, controller.signal).then(value => {
      if (controller.signal.aborted) return;
      if (value === null) { setUnsupported(true); return; }
      setData(value); timer = setTimeout(() => { setData(null); setError('Die OU-Prüfung ist abgelaufen. Bitte aktualisieren.'); }, Math.max(0, value.validUntil * 1000 - Date.now()));
    }).catch(failure => {
      if (controller.signal.aborted) return;
      const code = failure?.response?.status;
      if (code === 403 && failure?.response?.data?.error === 'device_ou_status_directory_read_required') setError('Für den aktuellen OU-Stand wird zusätzlich „Organisationseinheiten lesen“ benötigt. Der gespeicherte Zuordnungsstand bleibt sichtbar.');
      else {
        setError(code === 412 ? 'Die Gerätezuordnung oder die OU hat sich geändert. Bitte die Zuordnung neu laden.' : 'Der aktuelle OU-Stand konnte nicht bestätigt werden. Bitte erneut prüfen.');
        if ([401, 403, 428].includes(code)) callback.current(failure);
      }
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => { controller.abort(); clearTimeout(timer); window.removeEventListener('od:session-error', session); };
  }, [device.id, device.revision, actor, assignment.revision, assignment.ou?.id, assignment.ou?.generation, reload]);
  if (unsupported) return null;
  return <section aria-label="Aktueller OU-Stand" className="rounded border border-[var(--border)] p-3 space-y-2 text-sm break-words">
    {loading && <p role="status">Aktueller OU-Stand wird geprüft …</p>}
    {error && <p role="alert">{error}</p>}
    {data && <>
      <p>{data.state === 'current' ? 'OU aktuell bestätigt.' : data.state === 'changed' ? 'Die OU wurde seit der Zuordnung geändert.' : data.state === 'unassigned' ? 'Keine OU zugeordnet.' : 'Die ursprüngliche OU ist nicht mehr als aktuelle eigene OU bestätigt.'}</p>
      {data.state === 'changed' && <p>Aktuelle OU: {data.currentOu!.name} · Version {data.currentOu!.revision}. Über „Zuordnung ändern“ kannst du den aktuellen Stand übernehmen.</p>}
      <p className="text-xs opacity-70">Geprüft am {new Date(data.checkedAt).toLocaleString('de-CH')}. Der gespeicherte Verlauf bleibt erhalten.</p>
    </>}
    <button className="fluent-btn-secondary" disabled={disabled || loading} onClick={() => setReload(value => value + 1)}>OU-Stand prüfen</button>
  </section>;
}
