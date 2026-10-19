import { api } from './api';
import { directoryError } from './directoryUsers';

export interface RoleAuthenticationPolicy {
  role: string; version: string; required: boolean; maxAgeSeconds: number; protected: boolean; locked: boolean; canManage: boolean; requiresFreshMfa: boolean;
}
export interface RoleAuthenticationChange { required: boolean; maxAgeSeconds: number; reason: string }
export function authenticationRole(value: string): string {
  if (typeof value !== 'string' || !/^[a-z][a-z-]{0,63}$/.test(value)) throw new Error('Gültige kanonische Rolle erforderlich.');
  return value;
}
function unconfirmed(): never { throw new Error('Rollenrichtlinie nicht bestätigt. Stand prüfen; nicht automatisch wiederholen.'); }
function record(data: any): RoleAuthenticationPolicy {
  const fields = ['role','version','required','maxAgeSeconds','protected','locked','canManage','requiresFreshMfa'];
  if (!data || typeof data !== 'object' || Array.isArray(data) || Object.keys(data).length !== fields.length || fields.some(field => !Object.hasOwn(data,field))
    || typeof data.version !== 'string' || !/^[1-9][0-9]{0,18}$/.test(data.version) || BigInt(data.version) > BigInt('9223372036854775807')
    || !Number.isInteger(data.maxAgeSeconds) || data.maxAgeSeconds < 300 || data.maxAgeSeconds > 86400
    || ['required','protected','locked','canManage','requiresFreshMfa'].some(field => typeof data[field] !== 'boolean')
    || data.canManage && (data.requiresFreshMfa || data.locked) || data.locked && (!data.required || data.maxAgeSeconds !== 300)) return unconfirmed();
  authenticationRole(data.role); return data;
}
export const roleAuthentication = {
  async get(role: string, signal?: AbortSignal): Promise<RoleAuthenticationPolicy> {
    const { data,status } = await api.get('/api/identity/authentication/roles/' + encodeURIComponent(authenticationRole(role)),{ signal });
    if (status !== 200) return unconfirmed();
    const result = record(data); if (result.role !== role) return unconfirmed(); return result;
  },
  async change(before: RoleAuthenticationPolicy, input: RoleAuthenticationChange): Promise<RoleAuthenticationPolicy> {
    const { data,status } = await api.put('/api/identity/authentication/roles/' + encodeURIComponent(authenticationRole(before.role)), input,
      { headers: { 'If-Match': `"od-role-authentication:${before.role}:${before.version}"` } });
    if (status !== 200) return unconfirmed();
    const result = record(data);
    if (result.role !== before.role || BigInt(result.version) !== BigInt(before.version) + BigInt(1) || result.required !== input.required || result.maxAgeSeconds !== input.maxAgeSeconds) return unconfirmed();
    return result;
  },
};
export function roleAuthenticationError(error: any): string {
  const code = error?.response?.data?.error;
  if (code === 'fresh_mfa_required') return 'Eine höchstens fünf Minuten alte Anmeldung mit geprüftem OpenDirectory-TOTP ist erforderlich.';
  if (code === 'authentication_policy_changed') return 'Die Rollenrichtlinie wurde inzwischen geändert. Stand neu laden; nicht automatisch wiederholen.';
  if (code === 'fixed_authentication_policy') return 'Die frische MFA für diese Sicherheitsrolle ist unveränderlich.';
  if (code === 'global_administrator_required') return 'Für geschützte Rollen ist globale Administration erforderlich.';
  return directoryError(error);
}
