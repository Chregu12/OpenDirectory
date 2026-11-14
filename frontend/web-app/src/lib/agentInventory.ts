import { z } from 'zod';
import { api } from './api';
import { agentStatuses } from './deviceAgents';
import type { Device } from './deviceInventory';
const uuid = z.string().regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
const timestamp = z.string().datetime({ offset: true });
const counter = z.string().regex(/^(0|[1-9][0-9]{0,18})$/).refine(value => BigInt(value).toString() === value && BigInt(value) <= BigInt("9223372036854775807"));
const positive = counter.refine(value => value !== '0');
const capacity = z.object({ totalBytes: positive, availableBytes: counter }).strict().refine(value => BigInt(value.availableBytes) <= BigInt(value.totalBytes));
const facts = z.object({ schemaVersion: z.literal(1),
  cpu: z.object({ model: z.string().refine(value => value.trim() === value && Array.from(value).length <= 200 && !/[\u0000-\u001f\u007f-\u009f]/.test(value)), logicalProcessors: z.number().int().min(1).max(65536) }).strict().nullable(),
  memory: capacity.nullable(), systemDisk: capacity.nullable(), uptimeSeconds: counter.nullable(),
}).strict();
export const agentInventoryFactsSchema = facts;
const envelope = z.object({ schemaVersion: z.literal(1), inventoryProtocol: z.literal(1), actorUserId: uuid, tenantId: uuid, deviceId: uuid, checkedAt: timestamp,
  connectionStatus: z.enum(agentStatuses), status: z.enum(['missing', 'current', 'stale', 'historical']),
  inventory: z.object({ schemaVersion: z.literal(1), receivedAt: timestamp, enrolledAt: timestamp, revision: positive, platform: z.enum(['macos', 'windows', 'linux']), agentVersion: z.string().min(1).max(40), facts }).strict().nullable(),
}).strict().refine(value => value.status === 'missing' ? value.inventory === null : value.inventory !== null && Date.parse(value.inventory.receivedAt) <= Date.parse(value.checkedAt)
  && Date.parse(value.inventory.enrolledAt) <= Date.parse(value.inventory.receivedAt)
  && (value.status !== 'current' || value.connectionStatus === 'connected' && Date.parse(value.checkedAt) - Date.parse(value.inventory.receivedAt) <= 300000)
  && (value.status !== 'stale' || ['connected', 'offline'].includes(value.connectionStatus)));
export type AgentInventory = z.infer<typeof envelope>;
export async function readAgentInventory(device: Device, actor: string, signal: AbortSignal): Promise<AgentInventory> {
  const response = await api.get('/api/devices/' + device.id + '/agent/inventory', { signal });
  const result = envelope.parse(response.data);
  if (response.status !== 200 || result.actorUserId !== actor || result.tenantId !== device.tenantId || result.deviceId !== device.id
    || ['current', 'stale'].includes(result.status) && result.inventory?.platform !== device.platform) throw new Error('Unconfirmed agent inventory');
  return result;
}
export function gibibytes(value: string): string {
  return (Number(BigInt(value) * BigInt("10") / BigInt("1073741824")) / 10).toLocaleString('de-CH', { maximumFractionDigits: 1 }) + ' GiB';
}
export function uptime(value: string): string {
  const seconds = BigInt(value);
  return `${seconds / BigInt("86400")} Tage · ${seconds % BigInt("86400") / BigInt("3600")} Std. · ${seconds % BigInt("3600") / BigInt("60")} Min.`;
}
