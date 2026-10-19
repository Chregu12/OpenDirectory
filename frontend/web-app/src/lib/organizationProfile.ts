import { api } from './api';
import { getAccessToken } from './auth';
import { FIELDS, normalizeProfile, organizationEtag, OrganizationProfile } from '../../../../packages/organization-profile-contract';

export { FIELDS, normalizeProfile };
export type { OrganizationProfile };
export interface OrganizationRecord extends OrganizationProfile { id: string; version: string; createdAt: string; updatedAt: string }
export interface OrganizationPage {
  schemaVersion: 1;
  actorUserId: string;
  tenant: { id: string; name: string; version: string; generation: string };
  organization: OrganizationRecord | null;
  etag: string;
  canManage: boolean;
  requiresFreshMfa: boolean;
  verificationSupported: false;
}
const identifier = (value: unknown) => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
const revision = (value: unknown) => typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value) <= BigInt('9223372036854775807');
function unavailable(): never { throw new Error('Organisationsantwort nicht bestätigt. Bitte neu laden, bevor du erneut speicherst.'); }
export function profileFields(value: OrganizationProfile): OrganizationProfile {
  return Object.fromEntries(Object.keys(FIELDS).map(field => [field, value[field as keyof OrganizationProfile]])) as unknown as OrganizationProfile;
}
function parsePage(response: { data: any; headers: any }): OrganizationPage {
  const page = response.data;
  if (page?.schemaVersion !== 1 || !identifier(page.actorUserId) || !identifier(page.tenant?.id) || !revision(page.tenant.version) || !revision(page.tenant.generation)
    || typeof page.tenant.name !== 'string' || typeof page.canManage !== 'boolean' || typeof page.requiresFreshMfa !== 'boolean' || page.canManage && page.requiresFreshMfa
    || page.verificationSupported !== false || page.organization === undefined) unavailable();
  if (page.organization !== null) {
    if (!identifier(page.organization.id) || !revision(page.organization.version) || !['createdAt', 'updatedAt'].every(field => typeof page.organization[field] === 'string' && Number.isFinite(Date.parse(page.organization[field])))) unavailable();
    try {
      const raw = profileFields(page.organization);
      if (JSON.stringify(normalizeProfile(raw)) !== JSON.stringify(raw)) unavailable();
    } catch { unavailable(); }
  }
  if (page.etag !== organizationEtag(page.tenant, page.organization?.version || '0') || response.headers?.etag !== page.etag) unavailable();
  return page;
}
function unchangedSession(token: string | null) { if (token && getAccessToken() !== token) unavailable(); }

export function organizationError(error: any): string {
  if (error?.response?.status === 428) return 'Eine frische MFA-Anmeldung und die aktuelle Profilversion sind erforderlich. Bitte erneut anmelden und neu laden.';
  if (error?.response?.status === 412) return 'Das Organisationsprofil wurde zwischenzeitlich geändert. Bitte neu laden; es wurde nicht überschrieben.';
  if (error?.response?.status === 401) return 'Die Sitzung ist nicht mehr gültig. Bitte erneut anmelden.';
  if (error?.response?.status === 403) return 'Keine Berechtigung für das Organisationsprofil.';
  if (error?.status === 400 || error?.response?.status === 400) return 'Bitte Firmenname, Adresse, Länderkürzel, Zeitzone und Kontaktdaten prüfen.';
  return 'Speicherung oder Abruf nicht bestätigt. Bitte neu laden, bevor du erneut speicherst.';
}

export const organizationProfile = {
  async load(signal?: AbortSignal): Promise<OrganizationPage> {
    const token = getAccessToken();
    const response = await api.get('/api/identity/organization', { signal });
    unchangedSession(token); return parsePage(response);
  },
  async save(previous: OrganizationPage, values: OrganizationProfile, reason: string): Promise<OrganizationPage> {
    const profile = normalizeProfile(values); const token = getAccessToken(); const current = await organizationProfile.load();
    if (!current.canManage || current.actorUserId !== previous.actorUserId || current.tenant.id !== previous.tenant.id || current.tenant.generation !== previous.tenant.generation || current.etag !== previous.etag) unavailable();
    unchangedSession(token);
    const response = await api.put('/api/identity/organization', { profile, reason: reason.trim() }, { headers: { 'If-Match': previous.etag } });
    unchangedSession(token); const result = parsePage(response);
    if (result.actorUserId !== previous.actorUserId || result.tenant.id !== previous.tenant.id || result.tenant.generation !== previous.tenant.generation || result.tenant.version !== previous.tenant.version
      || !result.organization || result.organization.version !== String(BigInt(previous.organization?.version || '0') + BigInt(1))
      || previous.organization && result.organization.id !== previous.organization.id || JSON.stringify(profileFields(result.organization)) !== JSON.stringify(profile)) unavailable();
    return result;
  },
};
