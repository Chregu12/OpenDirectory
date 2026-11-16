import { z } from 'zod';
import { api } from './api';
import { CompanyApplicationsCapabilities } from './companyApplications';
import { companyUuid } from './companyAssignmentProtocol';

const count = z.number().int().min(0).max(2147483647);
export const companyProviderProductSchema = z.object({ skuId: companyUuid, skuPartNumber: z.string().min(1).max(255).refine(value => !!value.trim() && !/[\u0000-\u001f\u007f]/.test(value)),
  appliesTo: z.enum(['User', 'Company']), capabilityStatus: z.enum(['Enabled', 'Warning', 'Suspended', 'Deleted', 'LockedOut']),
  prepaidUnits: z.object({ enabled: count, warning: count, suspended: count, lockedOut: count }).strict(), consumedUnits: count }).strict();
const envelope = { schemaVersion: z.literal(1), companyLicenseProviderProtocol: z.literal(1), actorUserId: companyUuid, tenantId: companyUuid, provider: z.literal('microsoft-365') };
const schema = z.discriminatedUnion('state', [
  z.object({ ...envelope, state: z.literal('not_configured') }).strict(),
  z.object({ ...envelope, state: z.literal('connected'), microsoftTenantId: companyUuid,
    checkedAt: z.string().datetime({ offset: true }).refine(value => Number.isFinite(Date.parse(value))), products: z.array(companyProviderProductSchema).max(1000).refine(rows => new Set(rows.map(row => row.skuId)).size === rows.length) }).strict(),
  z.object({ ...envelope, state: z.literal('failed'), errorCode: z.string().regex(/^graph_capacity_[a-z0-9_]{1,80}$/), retryAfter: z.number().int().min(1).max(3600).optional() }).strict(),
]);

export type CompanyProviderSnapshot = z.infer<typeof schema>;
export async function inspectCompanyProvider(context: CompanyApplicationsCapabilities, signal?: AbortSignal): Promise<CompanyProviderSnapshot> {
  if (!context.permissions.includes('company.apps.read')) throw new Error('Company license access required');
  const response = await api.get('/api/licenses/company/provider', { signal });
  const result = schema.parse(response.data);
  if (response.status !== 200 || signal?.aborted || result.actorUserId !== context.actorUserId || result.tenantId !== context.tenantId) throw new Error('Company provider observation unconfirmed');
  return result;
}

export function companyProviderFailure(code: string) {
  if (code.endsWith('_http_429')) return 'Microsoft begrenzt die Anfragen. Bitte die angegebene Wartezeit einhalten und danach erneut prüfen.';
  if (code.endsWith('_http_401')) return 'Microsoft hat die Zugangsdaten abgelehnt. Bitte die Verbindungskonfiguration prüfen lassen.';
  if (code.endsWith('_http_403')) return 'Microsoft verweigert den Zugriff. Bitte Leseberechtigung und Administratorzustimmung prüfen lassen.';
  return 'Der Microsoft-Lizenzbestand konnte nicht bestätigt werden. Bitte später erneut prüfen.';
}
