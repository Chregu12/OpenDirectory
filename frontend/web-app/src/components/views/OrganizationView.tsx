'use client';

import React, { useEffect, useRef, useState } from 'react';
import { useIdentityAccess } from '@/hooks/useIdentityAccess';
import { normalizeProfile, profileFields, organizationError, organizationProfile, OrganizationPage, OrganizationProfile } from '@/lib/organizationProfile';
import OrganizationDelegations from '@/components/OrganizationDelegations';
import OrganizationProfileFields from '@/components/OrganizationProfileFields';
import OrganizationUnits from '@/components/OrganizationUnits';

export default function OrganizationView() {
  const { access, unavailable, reload } = useIdentityAccess();
  const [page, setPage] = useState<OrganizationPage | null>(null); const [form, setForm] = useState<OrganizationProfile | null>(null);
  const [reason, setReason] = useState(''); const [error, setError] = useState(''); const [success, setSuccess] = useState(''); const [busy, setBusy] = useState(false); const generation = useRef(0);
  useEffect(() => {
    const epoch = ++generation.current; const controller = new AbortController(); setPage(null); setForm(null); setError(''); setSuccess(''); setReason(''); setBusy(false);
    if (access?.organizationProfileProtocol === 1 && !access.demoMode && access.permissions.includes('organization.read')) {
      organizationProfile.load(controller.signal).then(result => {
        if (epoch !== generation.current) return;
        if (result.actorUserId !== access.userId) throw new Error('organization_actor_changed');
        setPage(result); setForm(result.organization ? profileFields(result.organization) : { name: result.tenant.name, legalForm: '', registrationNumber: '', taxId: '', addressLine1: '', addressLine2: '', postalCode: '', city: '', country: '', timezone: 'UTC', defaultLanguage: 'de', contactEmail: '', contactPhone: '', website: '' });
      }).catch(failure => { if (epoch === generation.current) setError(organizationError(failure)); });
    }
    return () => { generation.current++; controller.abort(); };
  }, [access]);
  useEffect(() => {
    const invalid = () => { generation.current++; setPage(null); setForm(null); setReason(''); setSuccess(''); setBusy(false); setError('Die Sitzung hat sich geändert. Bitte erneut anmelden und neu laden.'); };
    window.addEventListener('od:session-error', invalid); return () => window.removeEventListener('od:session-error', invalid);
  }, []);

  async function save(event: React.FormEvent) {
    event.preventDefault(); if (!page?.canManage || !form || busy) return;
    let draft: OrganizationProfile;
    try { draft = normalizeProfile(form); } catch (failure) { setError(organizationError(failure)); return; }
    const epoch = generation.current; setBusy(true); setError(''); setSuccess('');
    try {
      const result = await organizationProfile.save(page, draft, reason);
      if (epoch !== generation.current) return;
      setPage(result); setForm(profileFields(result.organization!)); setReason(''); setSuccess(`Organisationsprofil gespeichert. Version ${result.organization!.version}.`);
    } catch (failure) {
      if (epoch === generation.current) { setPage(null); setForm(null); setError(organizationError(failure)); }
    } finally { if (epoch === generation.current) setBusy(false); }
  }

  return <section className="p-6 space-y-6 max-w-5xl" style={{ color: 'var(--text-primary)' }}>
    <header><h1 className="text-2xl font-semibold">Organisation</h1><p className="mt-2" style={{ color: 'var(--text-secondary)' }}>Firmenprofil des angemeldeten Unternehmens</p></header>
    <p>Das Profil speichert Unternehmensdaten. Es aktiviert keinen Mandanten und bestätigt weder eine Firma noch eine Domain.</p>
    {unavailable && <p role="alert">Berechtigungen nicht verfügbar. Es werden keine Beispieldaten angezeigt.</p>}
    {!access && !unavailable && <p role="status">Berechtigungen werden geprüft …</p>}
    {access && !access.permissions.includes('organization.read') && <p role="alert">Keine Berechtigung zum Lesen des Organisationsprofils.</p>}
    {access && access.permissions.includes('organization.read') && (access.organizationProfileProtocol !== 1 || access.demoMode) && <p role="alert">Der mandantengebundene Organisationsdienst ist nicht verfügbar.</p>}
    {access?.organizationProfileProtocol === 1 && access.permissions.includes('organization.read') && !page && !error && <p role="status">Organisationsprofil wird geladen …</p>}
    {error && <p role="alert">{error} <a href="/mfa" className="underline">MFA-Einstellungen öffnen</a></p>}{success && <p role="status">{success}</p>}
    <button type="button" disabled={busy} onClick={() => { generation.current++; setPage(null); setForm(null); setSuccess(''); reload(); }} className="border rounded px-4 py-2">Neu laden</button>
    {page && form && <>
      <p>{page.organization ? `Gespeicherte Version ${page.organization.version}` : 'Noch kein Organisationsprofil gespeichert.'}</p>
      {page.requiresFreshMfa && <p role="alert">Zum Speichern ist eine frische MFA-Anmeldung erforderlich. <a className="underline" href="/mfa">MFA-Einstellungen öffnen</a>, danach erneut mit MFA anmelden und neu laden.</p>}
      <form onSubmit={save} className="space-y-6">
        <OrganizationProfileFields value={form} onChange={setForm} disabled={busy || !page.canManage || !access?.permissions.includes('organization.manage')} />
        {access?.permissions.includes('organization.manage') && <div className="space-y-3">
          <label htmlFor="organization-reason" className="block">Begründung der Änderung<textarea id="organization-reason" className="block mt-1 w-full border rounded p-3 bg-transparent" value={reason} onChange={event => setReason(event.target.value)} required minLength={10} maxLength={500} disabled={busy || !page.canManage} /></label>
          <button className="rounded px-5 py-2 bg-blue-600 text-white disabled:opacity-50" disabled={busy || !page.canManage || reason.trim().length < 10}>{busy ? 'Wird gespeichert …' : 'Organisationsprofil speichern'}</button>
        </div>}
      </form>
      {access?.permissions.includes('ous.read') && <OrganizationUnits access={access} />}
      {access?.organizationDelegationProtocol === 1 && access.permissions.includes('organization.delegations.manage') && <OrganizationDelegations actorUserId={page.actorUserId} tenantId={page.tenant.id} />}
    </>}
  </section>;
}
