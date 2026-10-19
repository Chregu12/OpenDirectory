import { api } from './api';
import { authenticationRole } from './roleAuthentication';
import { directoryError } from './directoryUsers';

export interface PrivilegedAccessPolicy { role: string; version: string; required: boolean; maxDurationSeconds: number; reviewerUserIds: string[]; protected: boolean; locked: boolean; canManage: boolean; requiresFreshMfa: boolean }
export interface PrivilegedAccessChange { required: boolean; maxDurationSeconds: number; reviewerUserIds?: string[]; reason: string; acknowledgeInvalidation: true }
function unconfirmed(): never { throw new Error('PIM-Richtlinie nicht bestätigt. Stand prüfen; nicht automatisch wiederholen.'); }
function record(data: any): PrivilegedAccessPolicy {
  const fields = ['role','version','required','maxDurationSeconds','reviewerUserIds','protected','locked','canManage','requiresFreshMfa'];
  if (!data || typeof data !== 'object' || Array.isArray(data) || Object.keys(data).length !== fields.length || fields.some(key => !Object.hasOwn(data,key))
    || typeof data.version !== 'string' || !/^[1-9][0-9]{0,18}$/.test(data.version) || BigInt(data.version) > BigInt('9223372036854775807')
    || !Number.isInteger(data.maxDurationSeconds) || data.maxDurationSeconds < 60 || data.maxDurationSeconds > 28800
    || ['required','protected','locked','canManage','requiresFreshMfa'].some(key => typeof data[key] !== 'boolean')
    || !Array.isArray(data.reviewerUserIds) || data.reviewerUserIds.length>20
    || data.reviewerUserIds.some((identifier: unknown,index: number) => typeof identifier!=='string'
      || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(identifier) || index>0 && data.reviewerUserIds[index-1]>=identifier)
    || data.role==='admin' && data.required && !data.reviewerUserIds.length
    || data.canManage && (data.locked || data.requiresFreshMfa) || data.locked !== (data.role === 'user')
    || data.locked && (data.required || data.maxDurationSeconds !== 28800)) return unconfirmed();
  authenticationRole(data.role); return data;
}
export const privilegedAccessPolicy = {
  async get(role: string, signal?: AbortSignal): Promise<PrivilegedAccessPolicy> {
    const { data,status } = await api.get('/api/identity/pim/policies/' + encodeURIComponent(authenticationRole(role)),{ signal });
    if (status !== 200) return unconfirmed();
    const result = record(data); if (result.role !== role) return unconfirmed(); return result;
  },
  async change(before: PrivilegedAccessPolicy, input: PrivilegedAccessChange): Promise<PrivilegedAccessPolicy> {
    const { data,status } = await api.put('/api/identity/pim/policies/' + encodeURIComponent(authenticationRole(before.role)),input,
      { headers:{ 'If-Match':`"od-role-activation:${before.role}:${before.version}"` } });
    if (status !== 200) return unconfirmed();
    const result = record(data);
    if (result.role !== before.role || BigInt(result.version) !== BigInt(before.version)+BigInt(1)
      || result.required !== input.required || result.maxDurationSeconds !== input.maxDurationSeconds || JSON.stringify(result.reviewerUserIds)!==JSON.stringify(input.reviewerUserIds || [])) return unconfirmed();
    return result;
  },
};
export function privilegedPolicyError(error: any): string {
  const code = error?.response?.data?.error;
  if (code === 'fresh_mfa_required') return 'Frische Anmeldung mit geprüftem OpenDirectory-TOTP erforderlich (höchstens fünf Minuten).';
  if (code === 'activation_policy_changed') return 'Die PIM-Richtlinie wurde inzwischen geändert. Neu laden; nicht automatisch wiederholen.';
  if (code === 'global_administrator_required') return 'Geschützte Rollen erfordern globale Administration.';
  if (code === 'fixed_activation_policy') return 'Die Basisrolle user kann nicht zur PIM-Pflichtrolle werden.';
  if (code === 'invalid_activation_reviewers') return 'Benannte Genehmiger als eindeutige kanonische UUIDs angeben. Die globale Adminrolle benötigt mindestens einen unabhängigen PIM-Genehmiger.';
  if (code === 'independent_reviewer_required' || code === 'reviewer_unavailable') return 'Genehmiger müssen unabhängig, aktiviert und auch nach der Änderung zur PIM-Prüfung berechtigt sein.';
  if (code === 'activation_path_unavailable') return 'Vor der globalen PIM-Pflicht eine gültige Admin-Berechtigung für einen aktivierten, von den benannten Genehmigern verschiedenen Benutzer vorbereiten.';
  return directoryError(error);
}
