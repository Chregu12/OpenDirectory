'use client';
import React, { useEffect, useRef, useState } from 'react';
import type { Device } from '@/lib/deviceInventory';
import { deviceInventoryError } from '@/lib/deviceInventory';
import { AgentConnection, readAgent, manageAgent } from '@/lib/deviceAgents';
import { DirectoryConfirmation } from './UserDetailPanel';
const labels = { 'not-enrolled': 'Nicht verbunden', pending: 'Registrierung ausstehend', connected: 'Online', offline: 'Offline', expired: 'Zugang abgelaufen', revoked: 'Zugang widerrufen' };
const events = { issue: 'Registrierungscode erstellt · vorheriger Zugang gesperrt', register: 'Agent registriert', revoke: 'Gerätezugang widerrufen' };
const date = (value: string | null) => value ? new Date(value).toLocaleString('de-CH') : '—';
export default function DeviceAgentPanel({ device, actor, canManage, disabled, onBusy, onSecurityError }: { device: Device; actor: string; canManage: boolean; disabled: boolean; onBusy: (busy: boolean) => void; onSecurityError: (failure: unknown) => void }) {
  const [state, setState] = useState<AgentConnection | null>(null);
  const page = useRef(1);
  const setPage = (value: number) => { page.current = value; setReload(previous => previous + 1); };
  const [reload, setReload] = useState(0);
  const [error, setError] = useState('');
  const [action, setAction] = useState<'issue' | 'revoke' | null>(null);
  const [reason, setReason] = useState('');
  const [secret, setSecret] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
  const generation = useRef(0);
  const command = useRef<AbortController | null>(null);
  const securityError = useRef(onSecurityError); securityError.current = onSecurityError;
  const authority = useRef({ id: device.id, revision: device.revision, actor, canManage }); authority.current = { id: device.id, revision: device.revision, actor, canManage };
  useEffect(() => {
    const expected = ++generation.current; const controller = new AbortController();
    setState(null); setSecret(null); setError(''); setAction(null); setWorking(false);
    const failed = (failure: unknown) => {
      if (generation.current !== expected || controller.signal.aborted) return;
      const status = (failure as any)?.response?.status;
      if ([401, 403, 428].includes(status)) securityError.current(failure);
      else setError(status === 501 || status === 404 ? 'Agent-Anbindung ist auf diesem Server noch nicht verfügbar.' : deviceInventoryError(failure));
    };
    const load = () => readAgent(device, actor, page.current, controller.signal).then(result => { if (generation.current === expected && !controller.signal.aborted) setState(result); }).catch(failed);
    void load();
    const session = () => { generation.current += 1; controller.abort(); command.current?.abort(); onBusy(false); setWorking(false); setState(null); setSecret(null); setAction(null); };
    window.addEventListener('od:session-error', session);
    return () => { generation.current += 1; controller.abort(); if (command.current) { command.current.abort(); command.current = null; onBusy(false); } window.removeEventListener('od:session-error', session); };
  }, [device.id, device.revision, actor, canManage, reload]);
  useEffect(() => { if (!secret) return; const timer = window.setTimeout(() => setSecret(null), 5 * 60 * 1000); return () => window.clearTimeout(timer); }, [secret]);
  const confirm = async () => {
    if (!state || !action || !canManage || disabled || working || reason.trim().length < 10) return;
    const expected = generation.current; const original = { ...authority.current }; const controller = new AbortController(); command.current = controller;
    setWorking(true); onBusy(true); setSecret(null); setError('');
    try {
      const result = await manageAgent(device, actor, state, action, reason, controller.signal);
      if (generation.current !== expected || controller.signal.aborted || JSON.stringify(authority.current) !== JSON.stringify(original)) return;
      setState(result.connection); setSecret(result.enrollmentToken); setAction(null); page.current = 1;
    } catch (failure) {
      if (generation.current !== expected || controller.signal.aborted) return;
      setState(null); setAction(null);
      if ([401, 403, 428].includes((failure as any)?.response?.status)) securityError.current(failure);
      else setError(deviceInventoryError(failure));
    } finally { if (generation.current === expected) { setWorking(false); onBusy(false); } }
  };
  const supported = ['windows', 'macos', 'linux'].includes(device.platform);
  const endpoint = typeof window === 'undefined' ? '' : window.location.origin;
  return <section aria-label="Geräteverbindung" className="border-t border-[var(--border)] pt-4 space-y-4">
    <div className="flex flex-wrap gap-3 items-center"><h3 className="font-semibold">Geräteverbindung</h3>{state && <span className="od-badge" role="status">{labels[state.status]}</span>}
      <button className="fluent-btn-secondary" disabled={disabled || working} onClick={() => setReload(value => value + 1)}>Verbindungsstatus aktualisieren</button></div>
    {error && <p role="alert">{error}</p>}
    {!state && !error && <p role="status">Geräteverbindung wird geprüft …</p>}
    {state && <>
      <p className="text-sm opacity-70">Der OpenDirectory-Agent meldet seinen Status alle 60 Sekunden. Nach drei Minuten ohne Meldung gilt er als offline. Geräteangaben stammen vom Agenten; Compliance ist unbekannt.</p>
      <dl className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">{Object.entries({ 'Letzter Kontakt': date(state.lastSeen), Registriert: date(state.enrolledAt), 'Zugang gültig bis': date(state.credentialExpiresAt), Hostname: state.report?.hostname || '—', Architektur: state.report?.architecture || '—', Agentversion: state.report?.agentVersion || '—' }).map(([label, value]) => <div key={label}><dt className="opacity-70">{label}</dt><dd className="break-words">{value}</dd></div>)}</dl>
      {canManage && <div className="flex flex-wrap gap-3">{supported && ['available', 'assigned'].includes(device.lifecycle) && <button className="fluent-btn-primary" disabled={disabled || working} onClick={() => { setReason(''); setAction('issue'); setSecret(null); }}>Registrierungscode erstellen</button>}
        {!['not-enrolled', 'revoked'].includes(state.status) && <button className="fluent-btn-secondary" disabled={disabled || working} onClick={() => { setReason(''); setAction('revoke'); setSecret(null); }}>Gerätezugang widerrufen</button>}</div>}
      {!supported && <p className="text-sm">Für diese Plattform ist noch kein Agent verfügbar.</p>}
      {secret && <div className="rounded border border-[var(--border)] p-4 space-y-3">
        <p className="font-medium">Einmaliger Registrierungscode</p><p className="text-sm">Gültig bis {date(state.enrollmentExpiresAt)}. Nur auf diesem Gerät verwenden. Der Code wird nur jetzt angezeigt und nach fünf Minuten ausgeblendet.</p>
        <label className="block text-sm">Registrierungscode<input className="input-apple font-mono" readOnly value={secret} autoComplete="off" spellCheck={false} onFocus={event => event.target.select()} /></label>
        <p className="text-sm">Auf dem Zielgerät den Rust-Agenten installieren, den Code als OD_ENROLLMENT_TOKEN setzen und registrieren:</p>
        <code className="block text-sm break-all">od-agent-service --server-url {endpoint} enroll</code>
        <code className="block text-sm">od-agent-service run</code>
        <p className="text-sm">Bei einer privaten Zertifizierungsstelle deren PEM-Zertifikat über OD_CA_CERT angeben. <a className="text-blue-500 underline" href="https://github.com/Chregu12/OpenDirectory/blob/main/docs/features/device-agents.md" target="_blank" rel="noreferrer">Installationsanleitung</a></p>
        <button className="fluent-btn-secondary" onClick={() => setSecret(null)}>Code ausblenden</button>
      </div>}
      <details><summary className="cursor-pointer text-sm">Verbindungsprotokoll · {state.history.total} Ereignisse</summary>
        <ol className="space-y-3 mt-3 text-sm">{state.history.events.map(event => <li key={event.id}><p>{events[event.action]} · {date(event.createdAt)}</p><p className="break-words">{event.actorUserId ? `Benutzer: ${event.actorUserId}` : 'Geräteagent'} · Korrelations-ID: {event.correlationId}</p>{event.reason && <p>{event.reason}</p>}</li>)}</ol>
        <nav aria-label="Verbindungsprotokollseiten" className="flex flex-wrap gap-3 mt-3"><button className="fluent-btn-secondary" disabled={disabled || state.history.page === 1} onClick={() => setPage(state.history.page - 1)}>Vorherige Ereignisse</button><span>Seite {state.history.page} von {Math.max(1, Math.ceil(state.history.total / 25))}</span><button className="fluent-btn-secondary" disabled={disabled || state.history.page * 25 >= state.history.total} onClick={() => setPage(state.history.page + 1)}>Weitere Ereignisse</button></nav>
      </details>
    </>}
    {action && state && <DirectoryConfirmation title={action === 'issue' ? 'Gerät registrieren' : 'Gerätezugang widerrufen'} busy={working} error="" confirmDisabled={reason.trim().length < 10 || disabled && !working} onClose={() => setAction(null)} onConfirm={() => void confirm()}>
      <p>{device.assetId} · {device.serialNumber}</p><p className="mt-3">{action === 'issue' ? 'Ein neuer Code gilt zehn Minuten und ersetzt alle bisherigen Codes und den bisherigen Agent-Zugang dieses Geräts.' : 'Der Agent kann sich danach nicht mehr verbinden. Inventar und Benutzerzuweisung bleiben erhalten.'}</p>
      <label className="block mt-3">Begründung<input className="input-apple" minLength={10} maxLength={500} disabled={working} value={reason} onChange={event => setReason(event.target.value)} /></label>
    </DirectoryConfirmation>}
  </section>;
}
