import { api } from './api';

export interface RegisteredClient {
  clientId: string; name: string; publicClient: boolean; enabled: boolean; version: string;
  redirectUris: string[]; scopes: string[]; grantTypes: string[]; protected: boolean; createdAt: string; updatedAt: string;
}
export interface ClientAccess { permissions: string[]; subject: string; userId: string | null; clientId: string; demoMode: boolean }
export type ClientMetadata = Pick<RegisteredClient, 'name' | 'redirectUris' | 'scopes' | 'grantTypes' | 'publicClient' | 'enabled'>;
const permissionNames = ['applications.read','applications.create','applications.update','applications.delete','applications.credentials.rotate','applications.permissions.assign','applications.assignments.read','applications.assignments.manage','applications.authentication.read','applications.authentication.manage'];
const unconfirmed = (): never => { throw new Error('Vorgang nicht bestätigt. Vor einem weiteren Versuch aktuellen Registerstand prüfen.'); };
const identifier = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9._~-]{1,255}$/.test(value) && value.trim() === value;
const version = (value: unknown): value is string => typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value).toString() === value && BigInt(value) <= BigInt('9223372036854775807');
const strings = (value: unknown, maximum: number): value is string[] => Array.isArray(value) && value.length <= maximum && value.every(item => typeof item === 'string') && new Set(value).size === value.length;
function record(data: any): RegisteredClient {
  if (!identifier(data?.clientId) || typeof data.name !== 'string' || !data.name.trim() || data.name.length > 255 || !version(data.version)
    || typeof data.publicClient !== 'boolean' || typeof data.enabled !== 'boolean' || typeof data.protected !== 'boolean'
    || !strings(data.redirectUris, 8) || !strings(data.scopes, 64) || !strings(data.grantTypes, 4)
    || !Number.isFinite(Date.parse(data.createdAt)) || !Number.isFinite(Date.parse(data.updatedAt)) || 'clientSecretHash' in data || 'secret_hash' in data || 'secret' in data) return unconfirmed();
  return { clientId: data.clientId, name: data.name, version: data.version, publicClient: data.publicClient, enabled: data.enabled, protected: data.protected,
    redirectUris: data.redirectUris, scopes: data.scopes, grantTypes: data.grantTypes, createdAt: data.createdAt, updatedAt: data.updatedAt };
}
function path(client: RegisteredClient) { if (!identifier(client.clientId) || !version(client.version)) return unconfirmed(); return `/api/clients/${encodeURIComponent(client.clientId)}`; }
function condition(client: RegisteredClient) { return { headers: { 'If-Match': `"od-client:${client.clientId}:${client.version}"` } }; }
function changed(data: unknown, previous: RegisteredClient) { const client = record(data); if (client.clientId !== previous.clientId || BigInt(client.version) !== BigInt(previous.version) + BigInt(1)) return unconfirmed(); return client; }
function credential(data: any) { const client = record(data); if (client.publicClient ? data.clientSecret !== null : typeof data.clientSecret !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(data.clientSecret)) return unconfirmed(); return { client, clientSecret: data.clientSecret as string | null }; }
function confirmed(client: RegisteredClient, expected: ClientMetadata) { for (const key of ['name','redirectUris','scopes','grantTypes','publicClient','enabled'] as const) if (JSON.stringify(client[key]) !== JSON.stringify(expected[key])) return unconfirmed(); }
export function clientError(error: any): string {
  const status = error?.response?.status;
  if (status === 412 || status === 428) return 'Register inzwischen geändert. Neu laden; keine automatische Wiederholung.';
  if (status === 403) return 'Keine Berechtigung für diese Anwendung oder ihre privilegierten Scopes.';
  if (status === 409) return 'Änderung nicht möglich. Für den eigenen Anmeldeclient ist ein unabhängiger Verwaltungsclient erforderlich.';
  if (status === 503) return 'Anwendungsautorität nicht verfügbar. Ausgang prüfen; nicht blind wiederholen.';
  return error instanceof Error ? error.message : 'Vorgang nicht bestätigt. Aktuellen Stand prüfen.';
}
export const registeredClients = {
  async access(signal?: AbortSignal): Promise<ClientAccess> {
    const { data } = await api.get('/api/clients/access', { signal });
    if (!strings(data?.permissions, permissionNames.length) || data.permissions.some((permission: string) => !permissionNames.includes(permission))
      || typeof data.subject !== 'string' || !data.subject || !identifier(data.clientId) || typeof data.demoMode !== 'boolean'
      || (data.userId !== null && (typeof data.userId !== 'string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(data.userId)))) return unconfirmed();
    return data;
  },
  async list(signal?: AbortSignal) {
    const { data } = await api.get('/api/clients', { signal });
    if (!Array.isArray(data?.clients) || data.clients.length > 100 || typeof data.truncated !== 'boolean') return unconfirmed();
    const clients = data.clients.map((value: any) => { if (!value || typeof value !== 'object' || 'clientSecret' in value) return unconfirmed(); return record(value); });
    if (new Set(clients.map((client: RegisteredClient) => client.clientId)).size !== clients.length) return unconfirmed();
    return { clients: clients as RegisteredClient[], truncated: data.truncated as boolean };
  },
  async create(metadata: ClientMetadata) {
    const { data, status } = await api.post('/api/clients', metadata);
    if (status !== 201) return unconfirmed(); const receipt = credential(data);
    if (receipt.client.version !== '1' || receipt.client.enabled !== metadata.enabled || receipt.client.publicClient !== metadata.publicClient) return unconfirmed();
    confirmed(receipt.client, metadata);
    return receipt;
  },
  async update(client: RegisteredClient, metadata: ClientMetadata) {
    const { data, status } = await api.put(path(client), metadata, condition(client));
    if (status !== 200 || !data || 'clientSecret' in data) return unconfirmed(); const result = changed(data, client); confirmed(result, metadata); return result;
  },
  async rotate(client: RegisteredClient) {
    const { data, status } = await api.post(path(client) + '/rotate-secret', {}, condition(client));
    if (status !== 200) return unconfirmed(); confirmed(changed(data, client), client); return credential(data);
  },
  async remove(client: RegisteredClient) { const { status } = await api.delete(path(client), condition(client)); if (status !== 204) return unconfirmed(); },
};
