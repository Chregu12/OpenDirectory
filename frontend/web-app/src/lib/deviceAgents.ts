import { z } from 'zod';
import { api } from './api';
import type { Device } from './deviceInventory';
const uuid = z.string().regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
const timestamp = z.string().datetime({ offset: true });
const report = z.object({ hostname: z.string().min(1).max(255), platform: z.enum(['windows', 'macos', 'linux']), architecture: z.string().min(1).max(40), osVersion: z.string().max(120), agentVersion: z.string().min(1).max(40) }).strict();
const connection = z.object({
  schemaVersion: z.literal(1), agentProtocol: z.literal(1), actorUserId: uuid, tenantId: uuid, deviceId: uuid,
  revision: z.string().regex(/^(0|[1-9][0-9]{0,18})$/).refine(value => BigInt(value) <= BigInt('9223372036854775807')),
  status: z.enum(['not-enrolled', 'pending', 'connected', 'offline', 'expired', 'revoked']),
  enrolledAt: timestamp.nullable(), lastSeen: timestamp.nullable(), credentialExpiresAt: timestamp.nullable(), enrollmentExpiresAt: timestamp.nullable(), report: report.nullable(),
  history: z.object({ total: z.number().int().nonnegative().safe(), page: z.number().int().min(1).max(1000000), limit: z.literal(25), events: z.array(z.object({ id: uuid, action: z.enum(['issue', 'register', 'revoke']), actorUserId: uuid.nullable(), reason: z.string().min(10).max(500).nullable(), correlationId: uuid, createdAt: timestamp }).strict()).max(25) }).strict(),
}).strict().refine(value => value.history.events.length === Math.min(25, Math.max(0, value.history.total - (value.history.page - 1) * 25)) && new Set(value.history.events.map(event => event.id)).size === value.history.events.length
  && (value.status !== 'connected' && value.status !== 'offline' || Boolean(value.enrolledAt && value.lastSeen && value.credentialExpiresAt && value.report)));
export type AgentConnection = z.infer<typeof connection>;
export function parseAgent(value: unknown, device: Device, actor: string, page = 1) {
  const result = connection.parse(value);
  if (result.deviceId !== device.id || result.tenantId !== device.tenantId || result.actorUserId !== actor || result.history.page !== page || result.report && result.report.platform !== device.platform) throw new Error('Unconfirmed agent response');
  return result;
}
export async function readAgent(device: Device, actor: string, page: number, signal: AbortSignal) {
  const response = await api.get('/api/devices/' + device.id + '/agent', { params: { page }, signal });
  return parseAgent(response.data, device, actor, page);
}
export async function manageAgent(device: Device, actor: string, state: AgentConnection, action: 'issue' | 'revoke', reason: string, signal: AbortSignal) {
  if (state.deviceId !== device.id || state.tenantId !== device.tenantId || state.actorUserId !== actor || reason.trim().length < 10 || reason.trim().length > 500) throw new Error('Unconfirmed agent decision');
  const response = await api.post('/api/devices/' + device.id + '/agent/' + action, { reason: reason.trim(), confirm: true }, { headers: { 'If-Match': `"agent-${device.id}-${state.revision}"` }, signal });
  if (response.status !== (action === 'issue' ? 201 : 200)) throw new Error('Unconfirmed agent decision');
  if (action === 'revoke') { const result = parseAgent(response.data, device, actor); if (result.status !== 'revoked') throw new Error('Unconfirmed revocation'); return { connection: result, enrollmentToken: null }; }
  const result = z.object({ connection, enrollmentToken: z.string().regex(/^odae_[A-Za-z0-9_-]{43}$/), expiresAt: timestamp }).strict().parse(response.data);
  const current = parseAgent(result.connection, device, actor);
  if (current.status !== 'pending' || result.expiresAt !== current.enrollmentExpiresAt || Date.parse(result.expiresAt) <= Date.now()) throw new Error('Unconfirmed enrollment');
  return { connection: current, enrollmentToken: result.enrollmentToken };
}
