'use client';

import React, { useEffect, useState } from 'react';
import { registeredClients, RegisteredClient, ClientMetadata, ClientAccess, clientError } from '@/lib/registeredClients';
import AppAssignmentsView from './AppAssignmentsView';
import AppAuthenticationView from './AppAuthenticationView';

const fieldClass = 'w-full rounded border border-[var(--border)] bg-[var(--bg-surface-raised)] p-2';
const buttonClass = 'rounded border border-[var(--border)] px-3 py-2 disabled:opacity-40';
export default function AppRegistrationsView() {
  const [access, setAccess] = useState<ClientAccess | null>(null); const [clients, setClients] = useState<RegisteredClient[]>([]);
  const [error, setError] = useState(''); const [attempt, setAttempt] = useState(0); const [truncated, setTruncated] = useState(false);
  const [form, setForm] = useState<{ target: RegisteredClient | null; name: string; redirects: string; scopes: string; mode: string } | null>(null);
  const [action, setAction] = useState<{ client: RegisteredClient; kind: 'enabled' | 'rotate' | 'delete' } | null>(null);
  const [secret, setSecret] = useState<{ client: RegisteredClient; clientSecret: string | null } | null>(null);
  const [busy, setBusy] = useState(false); const [mutationError, setMutationError] = useState(''); const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(true);
  const [assignmentClient,setAssignmentClient] = useState('');
  const [authenticationClient, setAuthenticationClient] = useState('');
  const can = (permission: string) => access?.permissions.includes(permission) === true;
  const editable = (client: RegisteredClient) => client.clientId !== access?.clientId && (!client.protected || can('applications.permissions.assign'));
  const reload = () => { setClients([]); setAttempt(value => value + 1); };
  useEffect(() => {
    let active = true; const controller = new AbortController(); setAccess(null); setClients([]); setError(''); setLoading(true); setTruncated(false);
    registeredClients.access(controller.signal).then(async current => {
      if (!active) return; setAccess(current);
      if (!current.permissions.includes('applications.read')) return;
      const page = await registeredClients.list(controller.signal); if (active) { setClients(page.clients); setTruncated(page.truncated); }
    }).catch(failure => { if (active) { setError(clientError(failure)); setClients([]); } }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [attempt]);
  function open(client: RegisteredClient | null) {
    setMutationError(''); setNotice('');
    setForm({ target: client, name: client?.name || '', redirects: client?.redirectUris.join('\n') || '', scopes: client?.scopes.join(' ') || 'openid profile email',
      mode: client && !client.grantTypes.includes('authorization_code') ? 'workload' : client?.publicClient ? 'public' : 'web' });
  }
  async function save(event: React.FormEvent) {
    event.preventDefault(); if (!form || busy || mutationError || !can(form.target ? 'applications.update' : 'applications.create')) return;
    const metadata: ClientMetadata = { name: form.name.trim(), redirectUris: form.mode === 'workload' ? [] : form.redirects.split('\n').map(uri => uri.trim()).filter(Boolean),
      scopes: form.scopes.split(/\s+/).filter(Boolean), grantTypes: form.target?.grantTypes || (form.mode === 'workload' ? ['client_credentials'] : ['authorization_code','refresh_token']),
      publicClient: form.target?.publicClient ?? form.mode === 'public', enabled: form.target?.enabled ?? false };
    setBusy(true);
    try {
      if (form.target) { await registeredClients.update(form.target, metadata); setNotice('Konfiguration gespeichert. Bisherige Tokens und Anmeldegrants sind ungültig.'); }
      else { const receipt = await registeredClients.create(metadata); setSecret(receipt); setNotice('Registriert, noch deaktiviert. Aktivierung ist ein separater bestätigter Schritt.'); }
      setForm(null); reload();
    } catch (failure) { setMutationError(clientError(failure)); } finally { setBusy(false); }
  }
  async function perform() {
    if (!action || busy || mutationError || !editable(action.client)) return;
    setBusy(true);
    try {
      if (action.kind === 'delete') await registeredClients.remove(action.client);
      else if (action.kind === 'rotate') setSecret(await registeredClients.rotate(action.client));
      else { const client = action.client; await registeredClients.update(client, { name: client.name, redirectUris: client.redirectUris, scopes: client.scopes, grantTypes: client.grantTypes, publicClient: client.publicClient, enabled: !client.enabled }); }
      setNotice('Änderung bestätigt. Bisherige Tokens, Refresh- und ausstehende Anmeldegrants sind ungültig.'); setAction(null); reload();
    } catch (failure) { setMutationError(clientError(failure)); } finally { setBusy(false); }
  }
  const begin = (client: RegisteredClient, kind: 'enabled' | 'rotate' | 'delete') => { setMutationError(''); setAction({ client, kind }); };
  return <section className="space-y-4 text-[var(--text-primary)]" aria-label="Anwendungsregistrierungen">
    <header><h2 className="text-lg font-semibold">Anwendungsregistrierungen</h2><p className="text-sm">Kanonische OAuth/OIDC-Clients. Keine AD/Kerberos-Servicekonten oder Softwareinstallationen.</p></header>
    {error && <p role="alert">{error} <button className={buttonClass} onClick={reload}>Neu laden</button></p>}
    {!access && !error && <p role="status">Berechtigungen werden geprüft …</p>}
    {access?.demoMode && <p role="alert">Expliziter Entwicklungsspeicher. Keine persistente Anwendungsautorität.</p>}
    {access && !can('applications.read') && <p>Keine Leseberechtigung für das Anwendungsregister.</p>}
    {notice && <p role="status">{notice}</p>}
    {secret && <aside className="space-y-2 rounded border border-amber-500 p-4" aria-label="Einmalige Zugangsdaten">
      <h3 className="font-semibold">{secret.client.name}: einmalige Zugangsdaten</h3><p>Client-ID: <code>{secret.client.clientId}</code></p>
      {secret.clientSecret ? <><p>Jetzt sicher übernehmen. Das Geheimnis wird nicht erneut lesbar gespeichert.</p><code className="block break-all" data-testid="client-secret">{secret.clientSecret}</code></> : <p>Öffentlicher Client: kein Geheimnis, S256 PKCE erforderlich.</p>}
      <button className={buttonClass} onClick={() => setSecret(null)}>Zugangsdaten schließen</button>
    </aside>}
    <div className="flex gap-2">{can('applications.create') && <button className={buttonClass} onClick={() => open(null)}>Anwendung registrieren</button>}{access && <button className={buttonClass} onClick={reload}>Register neu laden</button>}</div>
    {truncated && <p role="alert">Nur die ersten 100 Registrierungen werden angezeigt. Kein vollständiger Bestandsbericht.</p>}
    {loading && access && <p role="status">Register wird geprüft …</p>}
    {!error && !loading && access && can('applications.read') && <div className="space-y-3">{clients.length === 0 ? <p>Keine Registrierungen bestätigt.</p> : clients.map(client => <article key={client.clientId} className="space-y-2 rounded border border-[var(--border)] p-4" aria-label={client.name}>
      <h3 className="font-semibold">{client.name}</h3><p className="break-all"><code>{client.clientId}</code> · {client.enabled ? 'Aktiviert' : 'Deaktiviert'} · {client.publicClient ? 'Öffentlich' : 'Vertraulich'}</p>
      <p className="break-all">Scopes: {client.scopes.join(' ') || 'keine'}</p><p className="break-all">{client.grantTypes.join(' · ')}</p>{client.redirectUris.map(uri => <p className="break-all" key={uri}>{uri}</p>)}
      {can('applications.assignments.read') && client.grantTypes.some(grant => ['authorization_code','urn:ietf:params:oauth:grant-type:device_code'].includes(grant)) && <button className={buttonClass} onClick={() => setAssignmentClient(client.clientId)}>Anwendungszugriff verwalten</button>}
      {can('applications.authentication.read') && <button className={buttonClass} onClick={() => setAuthenticationClient(client.clientId)}>Anmelderichtlinie verwalten</button>}
      {client.protected && <p>Privilegierte Scopes: nur globale Administration.</p>}{client.clientId === access.clientId && <p>Eigener Anmeldeclient: Änderungen benötigen einen unabhängigen Verwaltungsclient.</p>}
      {editable(client) && <div className="flex flex-wrap gap-2">{can('applications.update') && <><button className={buttonClass} onClick={() => open(client)}>Konfiguration bearbeiten</button><button className={buttonClass} onClick={() => begin(client, 'enabled')}>{client.enabled ? 'Deaktivieren' : 'Aktivieren'}</button></>}
        {!client.publicClient && can('applications.credentials.rotate') && <button className={buttonClass} onClick={() => begin(client, 'rotate')}>Geheimnis ersetzen</button>}
        {can('applications.delete') && <button className={buttonClass} onClick={() => begin(client, 'delete')}>Registrierung löschen</button>}</div>}
    </article>)}</div>}
    {access && <AppAssignmentsView access={access} selectedClientId={assignmentClient} />}
    {access && <AppAuthenticationView access={access} selectedClientId={authenticationClient} />}
    {form && <form onSubmit={save} role="dialog" aria-label={form.target ? 'Anwendung bearbeiten' : 'Neue Anwendung'} className="space-y-3 rounded border border-[var(--border)] p-4">
      <h3>{form.target ? 'Anwendung bearbeiten' : 'Neue Anwendung'}</h3><p>Jede Konfigurationsänderung beendet bestehende Client-Generationen. Neue Registrierungen starten deaktiviert.</p>
      <label className="block">Name<input className={fieldClass} required maxLength={255} value={form.name} onChange={event => setForm({ ...form, name: event.target.value })} /></label>
      {!form.target && <div><label className="block" htmlFor="registered-client-type">Client-Typ</label><select id="registered-client-type" className={fieldClass} value={form.mode} onChange={event => setForm({ ...form, mode: event.target.value })}><option value="web">Vertrauliche Webanwendung</option><option value="public">Öffentlich, S256 PKCE</option><option value="workload">Workload, Client Credentials</option></select></div>}
      {form.mode !== 'workload' && <label className="block">Redirect-URIs, eine pro Zeile<textarea className={fieldClass} required value={form.redirects} onChange={event => setForm({ ...form, redirects: event.target.value })} /></label>}
      <label className="block">Scopes, durch Leerzeichen getrennt<input className={fieldClass} value={form.scopes} onChange={event => setForm({ ...form, scopes: event.target.value })} /></label>
      {!can('applications.permissions.assign') && <p>Nur Identitäts- und eigene Sitzungs-Scopes. Keine Plattformrollen, administrativen Scopes oder Einwilligungsdelegation.</p>}
      {mutationError && <p role="alert">{mutationError}</p>}<div className="flex gap-2"><button className={buttonClass} type="submit" disabled={busy || !!mutationError}>Verbindlich speichern</button><button className={buttonClass} type="button" disabled={busy} onClick={() => setForm(null)}>Schließen und Stand prüfen</button></div>
    </form>}
    {action && <div role="dialog" aria-label="Registeränderung bestätigen" className="space-y-3 rounded border border-amber-500 p-4"><h3>Änderung für {action.client.name} bestätigen</h3><p>{action.kind === 'rotate' ? 'Das alte Geheimnis wird sofort ersetzt.' : action.kind === 'delete' ? 'Die Registrierung wird dauerhaft stillgelegt; ihre ID bleibt als Evidenz erhalten.' : action.client.enabled ? 'Anmeldungen werden deaktiviert.' : 'Anmeldungen werden aktiviert.'} Bisherige Tokens und ausstehende Anmeldegrants werden ungültig. Bereits ausgeführte Fremdsystemaktionen werden nicht zurückgerollt.</p>
      {mutationError && <p role="alert">{mutationError}</p>}<div className="flex gap-2"><button className={buttonClass} disabled={busy || !!mutationError} onClick={perform}>Änderung bestätigen</button><button className={buttonClass} disabled={busy} onClick={() => setAction(null)}>Abbrechen und Stand prüfen</button></div></div>}
  </section>;
}
