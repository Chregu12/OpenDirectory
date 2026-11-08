import { api } from './api';

export interface LicenseActivation { schemaVersion: 1; scope: 'company-licenses'; id: string; tenant: { id: string; version: string; generation: string }; expiresAt: number }
export interface LicenseActivationStatus { schemaVersion: 1; scope: 'company-licenses'; tenant: LicenseActivation['tenant']; durations: number[]; requiresFreshMfa: boolean; activation: LicenseActivation | null }
const durations = [900, 3600, 7200, 14400, 28800, 36000];
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
function exact(value: any, keys: string[]) { return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function tenant(value: any) { return exact(value, ['id', 'version', 'generation']) && uuid.test(value.id) && [value.version, value.generation].every(v => typeof v === 'string' && /^[1-9][0-9]{0,18}$/.test(v) && BigInt(v) <= BigInt('9223372036854775807')); }
function activation(value: any): boolean { return value === null || (exact(value, ['schemaVersion', 'scope', 'id', 'tenant', 'expiresAt']) && value.schemaVersion === 1 && value.scope === 'company-licenses' && typeof value.id === 'string' && uuid.test(value.id) && tenant(value.tenant) && Number.isSafeInteger(value.expiresAt) && value.expiresAt > 0); }
export const companyLicenseActivation = {
  async status(signal?: AbortSignal): Promise<LicenseActivationStatus> {
    const { data } = await api.get('/api/mfa/company-license-activation', { signal });
    if (!exact(data, ['schemaVersion', 'scope', 'tenant', 'durations', 'requiresFreshMfa', 'activation']) || data.schemaVersion !== 1 || data.scope !== 'company-licenses' || !tenant(data.tenant)
      || !Array.isArray(data.durations) || !data.durations.length || data.durations.some((v: unknown, i: number) => !durations.includes(v as number) || (i > 0 && (v as number) <= data.durations[i - 1]))
      || typeof data.requiresFreshMfa !== 'boolean' || !activation(data.activation) || (data.activation && ['id', 'version', 'generation'].some(key => data.activation.tenant[key] !== data.tenant[key]))) throw new Error('Aktivierungsstatus nicht bestätigt.');
    return data;
  },
  async change(input: { durationSeconds: number; reason: string; confirm: true } | { activationId: string; confirm: true }): Promise<LicenseActivation | null> {
    const { data } = await api.post('/api/mfa/company-license-activation', input);
    if (!exact(data, ['schemaVersion', 'activation']) || data.schemaVersion !== 1 || !activation(data.activation)
      || ('activationId' in input ? data.activation !== null : data.activation === null)) throw new Error('Änderung nicht bestätigt. Nicht erneut ausführen; zuerst den Status prüfen.');
    return data.activation;
  },
};
