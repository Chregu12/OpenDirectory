'use client';
import React, { useEffect, useRef, useState } from 'react';
import { PolicyAccess, policyGovernance } from '@/lib/policyGovernance';
import { OwnedPolicyCommand, policyCommands } from '@/lib/policyCommands';

export default function PolicyCommandPanel({ resourceId, access, refresh, disabled = false }: { resourceId: string; access: PolicyAccess; refresh: number; disabled?: boolean }) {
  const [commands, setCommands] = useState<OwnedPolicyCommand[] | null>(null); const [truncated, setTruncated] = useState(false); const [offset, setOffset] = useState(0);
  const [pending, setPending] = useState(false); const [error, setError] = useState(''); const [message, setMessage] = useState(''); const [attempt, setAttempt] = useState(0);
  const [confirmation, setConfirmation] = useState<{ command: OwnedPolicyCommand; operationId: string } | null>(null); const [reason, setReason] = useState(''); const [ack, setAck] = useState(false); const epoch = useRef(0);
  const permitted = access.freshMfa && access.permissions.includes('policies.deploy');
  useEffect(() => { setOffset(0); }, [resourceId, access.userId, access.subject]);
  useEffect(() => {
    const generation = ++epoch.current; setCommands(null); setConfirmation(null); setReason(''); setAck(false); setError(''); setMessage(''); setTruncated(false);
    if (!permitted) { setPending(false); return; }
    setPending(true); policyCommands.list(resourceId, access.userId, offset).then(result => { if (generation === epoch.current) { setCommands(result.commands); setTruncated(result.truncated); } })
      .catch(() => { if (generation === epoch.current) setError('Eigene Geräteaufträge nicht bestätigt. Keine Annahme eines leeren Auftragsbestands.'); })
      .finally(() => { if (generation === epoch.current) setPending(false); });
    return () => { epoch.current++; };
  }, [resourceId, access.userId, access.subject, permitted, refresh, attempt, offset]);
  const reload = () => { setConfirmation(null); setReason(''); setAck(false); setAttempt(value => value + 1); };
  const stage = (command: OwnedPolicyCommand) => { setReason(''); setAck(false); setError(''); setMessage(''); setConfirmation({ command: JSON.parse(JSON.stringify(command)), operationId: crypto.randomUUID() }); };
  const confirm = async () => {
    if (!confirmation || !permitted || disabled || pending || !ack || reason.trim().length < 10) return;
    const captured = confirmation; const justification = reason.trim(); const generation = epoch.current; setPending(true); setError('');
    try {
      const current = await policyGovernance.access(); if (generation !== epoch.current) return;
      if (current.userId !== access.userId || current.subject !== access.subject || !current.freshMfa || !current.permissions.includes('policies.deploy')) throw new Error('Current original actor required');
      const retained = await policyCommands.cancel(captured.command.policyReceipt, current.userId, captured.operationId, justification); if (generation !== epoch.current) return;
      setCommands(rows => rows!.map(row => row.id === captured.command.id ? { ...row, status: 'cancelled', cancellationReceipt: retained, previouslyOffered: retained.previouslyOffered } : row));
      setMessage('Weitere Angebote dieses Auftrags gestoppt. Bereits empfangene oder ausgeführte Geräteaktionen werden nicht rückgängig gemacht.');
    } catch { if (generation === epoch.current) { setCommands(null); setError('Stornierung nicht bestätigt. Gespeicherten Status neu laden, nicht blind wiederholen.'); } }
    finally { if (generation === epoch.current) { setPending(false); setConfirmation(null); setReason(''); setAck(false); } }
  };
  return <section aria-label="Dauerhafte Geräteaufträge" className="border border-blue-400/30 rounded p-3 space-y-3">
    <h2>SQL-bestätigte Geräteaufträge</h2><p className="text-xs">Nur eigene Aufträge dieses Blueprints. Ein Freigabewiderruf storniert gespeicherte Aufträge nicht automatisch. Eine Stornierung stoppt weitere Angebote, widerruft aber keine bereits empfangene Geräteaktion.</p>
    {!permitted && <p>Eigene Aufträge und Stornierungen benötigen Zustellberechtigung und frische MFA.</p>}
    {permitted && <button disabled={pending || disabled} onClick={reload}>Gespeicherten Auftragsstatus neu laden</button>}
    {pending && <p role="status">Auftragsnachweise werden geprüft …</p>}{error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    {commands?.length === 0 && <p>Keine eigenen Aufträge in diesem Ausschnitt.</p>}
    {commands?.map(row => <article key={row.id} className="border-t border-white/15 pt-2 space-y-2">
      <p className="text-xs break-all">Geräteauftrag {row.id} · Abholfrist {row.policyReceipt.expiresAt}</p><p className="text-xs break-all">Gerät {row.policyReceipt.deviceId} · Konfigurationsversion {row.policyReceipt.reference.resourceVersion} · Status {row.status}</p>
      <p className="text-xs">{row.previouslyOffered ? 'Bereits zur Abholung angeboten; Geräteempfang oder Ausführung nicht unabhängig bestätigt.' : 'Noch kein Geräteangebot protokolliert.'}</p>
      {row.cancellationReceipt && <p className="text-xs break-all">Stornierung {row.cancellationReceipt.operationId} · {row.cancellationReceipt.cancelledAt} · Begründung: {row.cancellationReceipt.reason}</p>}
      {['pending','expired'].includes(row.status) && <button disabled={pending || disabled || !!confirmation} onClick={() => stage(row)}>Eigenen Geräteauftrag stoppen prüfen</button>}
    </article>)}
    {commands && <div><button disabled={pending || disabled || !!confirmation || offset === 0} onClick={() => setOffset(value => Math.max(0, value - 200))}>Neuere Aufträge</button><button disabled={pending || disabled || !!confirmation || !truncated || offset >= 999800} onClick={() => setOffset(value => value + 200)}>Ältere Aufträge</button>{truncated && <p>Weitere eigene Aufträge vorhanden; keine Vollständigkeit dieses Ausschnitts behauptet.</p>}</div>}
    {confirmation && <div role="group" aria-label="Geräteauftrag stoppen bestätigen" className="border border-amber-400/40 rounded p-3 space-y-2">
      <p className="text-xs break-all">Exakter Auftrag {confirmation.command.id} · Gerät {confirmation.command.policyReceipt.deviceId} · Version {confirmation.command.policyReceipt.reference.resourceVersion}</p>
      <label className="block">Begründung der Auftragsstornierung<textarea aria-label="Begründung der Auftragsstornierung" className="block w-full" value={reason} maxLength={500} disabled={pending} onChange={event => setReason(event.target.value)} /></label>
      <label className="flex gap-2"><input type="checkbox" checked={ack} disabled={pending} onChange={event => setAck(event.target.checked)} />Exakten eigenen Auftrag und Grenze bereits angebotener Geräteaktionen geprüft.</label>
      <button disabled={pending || disabled || !ack || reason.trim().length < 10} onClick={confirm}>Geräteauftrag verbindlich stoppen</button><button disabled={pending} onClick={() => { setConfirmation(null); setReason(''); setAck(false); }}>Stornierung abbrechen</button>
    </div>}
  </section>;
}
