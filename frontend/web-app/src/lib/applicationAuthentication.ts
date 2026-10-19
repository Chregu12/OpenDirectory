import { api } from './api';
import { clientError } from './registeredClients';

export interface AuthenticationPolicy {
  clientId: string; name: string; version: string; required: boolean; maxAgeSeconds: number; protected: boolean; canManage: boolean; requiresFreshMfa: boolean;
}
export interface AuthenticationChange { required: boolean; maxAgeSeconds: number; reason: string }
export function policyClientId(value: string): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9._~-]{1,255}$/.test(value)) throw new Error('Gültige Anwendungs-ID erforderlich.');
  return value;
}
function record(data: any): AuthenticationPolicy {
  const fields = ['clientId', 'name', 'version', 'required', 'maxAgeSeconds', 'protected', 'canManage', 'requiresFreshMfa'];
  if (!data || typeof data !== 'object' || Array.isArray(data) || Object.keys(data).length !== fields.length || fields.some(field => !Object.hasOwn(data, field))
    || typeof data.name !== 'string' || !data.name.trim() || data.name.length > 255 || typeof data.version !== 'string' || !/^[1-9][0-9]{0,18}$/.test(data.version)
    || BigInt(data.version) > BigInt('9223372036854775807') || !Number.isInteger(data.maxAgeSeconds) || data.maxAgeSeconds < 300 || data.maxAgeSeconds > 86400
    || ['required', 'protected', 'canManage', 'requiresFreshMfa'].some(field => typeof data[field] !== 'boolean') || data.canManage && data.requiresFreshMfa) throw new Error('Anmelderichtlinie nicht bestätigt. Stand neu laden, nicht automatisch wiederholen.');
  policyClientId(data.clientId); return data;
}
export const applicationAuthentication = {
  async get(clientId: string, signal?: AbortSignal): Promise<AuthenticationPolicy> {
    const { data, status } = await api.get('/api/clients/' + encodeURIComponent(policyClientId(clientId)) + '/authentication', { signal });
    if (status !== 200) throw new Error('Anmelderichtlinie nicht bestätigt.');
    const result = record(data); if (result.clientId !== clientId) throw new Error('Falsche Anwendungsrichtlinie.'); return result;
  },
  async change(before: AuthenticationPolicy, input: AuthenticationChange): Promise<AuthenticationPolicy> {
    const { data, status } = await api.put('/api/clients/' + encodeURIComponent(policyClientId(before.clientId)) + '/authentication', input, { headers: { 'If-Match': `"od-client:${before.clientId}:${before.version}"` } });
    if (status !== 200) throw new Error('Änderung nicht bestätigt. Stand prüfen; nicht automatisch wiederholen.');
    const result = record(data);
    if (result.clientId !== before.clientId || BigInt(result.version) !== BigInt(before.version) + BigInt(1) || result.required !== input.required || result.maxAgeSeconds !== input.maxAgeSeconds) throw new Error('Änderung nicht bestätigt. Ergebnis prüfen; nicht automatisch wiederholen.');
    return result;
  },
};
export function authenticationPolicyError(error: any): string {
  if (error?.response?.data?.error === 'fresh_mfa_required') return 'Eine höchstens fünf Minuten alte Anmeldung mit geprüftem OpenDirectory-TOTP ist erforderlich.';
  return clientError(error);
}
