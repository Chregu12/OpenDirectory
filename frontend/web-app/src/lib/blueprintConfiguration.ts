import { api } from './api';
import { canonical } from './policyGovernance';
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
export interface BlueprintRecord { id: string; name: string; platform: string; version: number; created_by: string | null }
export interface BlueprintConfiguration { id: string; blueprint_id: string; config_type: string; config_name: string; payload: Record<string, unknown> }
export interface BlueprintTarget { id: string; blueprint_id: string; target_type: string; target_id: string }
export interface BlueprintFrame { row: BlueprintRecord; configurations: BlueprintConfiguration[]; assignments: BlueprintTarget[] }
export type BlueprintAction = 'create' | 'configuration' | 'remove' | 'assign' | 'delete' | 'deliver';
export interface PolicyCommandReceipt { schemaVersion: 1; commandId: string; operationId: string; deviceId: string; deviceGeneration: string; operatorUserId: string; reference: { resourceKind: 'blueprint'; resourceId: string; resourceVersion: number; publicationId: string; configurationId: string }; configurationVersion: number; configurationHash: string; publicationVersion: number; payloadHash: string; expiresAt: string; persistence: 'committed' }
const fail = (): never => { throw new Error('Blueprint-Änderung nicht bestätigt. Neu laden, nicht blind wiederholen.'); };
export const blueprintTag = (row: BlueprintRecord) => `"od-blueprint:${row.id}:${row.version}"`;
function parse(row: BlueprintRecord): BlueprintRecord {
  if (!row || !uuid.test(row.id) || typeof row.name !== 'string' || !row.name || !['windows','macos','linux','all'].includes(row.platform) || !Number.isInteger(row.version) || row.version < 1
    || row.created_by !== null && typeof row.created_by !== 'string') return fail(); return row;
}
function delivery(row: any, current: BlueprintRecord, userId: string, publicationId: string) {
  const operations = new Set<string>(); const items = new Set<string>();
  for (const result of row.results) {
    const receipt = result?.policyReceipt as PolicyCommandReceipt;
    if (!receipt || Object.keys(receipt).length !== 13 || receipt.schemaVersion !== 1 || typeof receipt.commandId !== 'string' || !uuid.test(receipt.commandId) || result.commandId !== receipt.commandId || typeof receipt.operationId !== 'string' || !uuid.test(receipt.operationId)
      || result.targetType !== 'device' || typeof result.targetId !== 'string' || !/^(?!\.{1,2}$)[A-Za-z0-9._~-]{1,255}$/.test(result.targetId) || receipt.deviceId !== result.targetId
      || receipt.operatorUserId !== userId || typeof receipt.deviceGeneration !== 'string' || !/^[1-9][0-9]{0,18}$/.test(receipt.deviceGeneration) || BigInt(receipt.deviceGeneration) > BigInt('9223372036854775807')
      || receipt.persistence !== 'committed' || !receipt.reference || Object.keys(receipt.reference).length !== 5 || receipt.reference.resourceKind !== 'blueprint' || receipt.reference.resourceId !== current.id
      || receipt.reference.resourceVersion !== current.version || receipt.reference.publicationId !== publicationId || typeof receipt.reference.configurationId !== 'string' || !uuid.test(receipt.reference.configurationId)
      || !Number.isSafeInteger(receipt.configurationVersion) || receipt.configurationVersion < 1 || receipt.configurationVersion > current.version || !Number.isSafeInteger(receipt.publicationVersion) || receipt.publicationVersion < 2
      || typeof receipt.configurationHash !== 'string' || !/^[a-f0-9]{64}$/.test(receipt.configurationHash) || typeof receipt.payloadHash !== 'string' || !/^[a-f0-9]{64}$/.test(receipt.payloadHash)
      || typeof receipt.expiresAt !== 'string' || !Number.isFinite(Date.parse(receipt.expiresAt)) || new Date(receipt.expiresAt).toISOString() !== receipt.expiresAt
      || Date.parse(receipt.expiresAt) <= Date.now() || Date.parse(receipt.expiresAt) > Date.now() + 305000 || result.queued !== true) return fail();
    const key = receipt.deviceId + ':' + receipt.reference.configurationId; if (items.has(key)) return fail(); items.add(key); operations.add(receipt.operationId);
  }
  if (operations.size > 1 || row.results.length > 0 && !['queued','partial'].includes(row.phase) || row.results.length === 0 && row.phase === 'queued') return fail();
  return row;
}
export const blueprintConfiguration = {
  async list(): Promise<BlueprintRecord[]> {
    const result = await api.get('/api/blueprints'); if (result.status !== 200 || !Array.isArray(result.data?.blueprints) || result.data.blueprints.length > 1000 || result.data.total !== result.data.blueprints.length) return fail();
    const rows: BlueprintRecord[] = result.data.blueprints.map(parse); if (new Set(rows.map(row => row.id)).size !== rows.length) return fail(); return rows;
  },
  async get(id: string): Promise<BlueprintFrame> {
    if (!uuid.test(id)) return fail(); const [detail, targets] = await Promise.all([api.get(`/api/blueprints/${id}`), api.get(`/api/blueprints/${id}/assignments`)]); const row = parse(detail.data);
    if (detail.status !== 200 || targets.status !== 200 || row.id !== id || detail.headers?.etag !== blueprintTag(row) || targets.headers?.etag !== blueprintTag(row) || targets.data.parentVersion !== row.version
      || !Array.isArray(detail.data.configurations) || detail.data.configurations.length > 1000 || !Array.isArray(targets.data.assignments) || targets.data.assignments.length > 1000) return fail();
    const configurations = detail.data.configurations as BlueprintConfiguration[]; const assignments = targets.data.assignments as BlueprintTarget[];
    if (configurations.some(item => !uuid.test(item.id) || item.blueprint_id !== id || typeof item.config_type !== 'string' || typeof item.config_name !== 'string' || !item.payload || typeof item.payload !== 'object' || Array.isArray(item.payload))
      || assignments.some(item => !uuid.test(item.id) || item.blueprint_id !== id || !['device','group'].includes(item.target_type) || typeof item.target_id !== 'string')
      || new Set(configurations.map(item => item.id)).size !== configurations.length || new Set(assignments.map(item => item.id)).size !== assignments.length) return fail();
    return { row, configurations, assignments };
  },
  async write(action: BlueprintAction, current: BlueprintRecord | null, body: Record<string, unknown>, reason: string, userId: string, childId?: string, publicationId?: string) {
    if (action !== 'create' && !current || childId && !uuid.test(childId) || action === 'deliver' && (!publicationId || !uuid.test(publicationId))) return fail();
    const root = current ? `/api/blueprints/${current.id}` : '/api/blueprints';
    const path = action === 'configuration' ? root + '/configurations' : action === 'remove' ? root + '/configurations/' + childId : action === 'assign' ? root + '/assign' : action === 'deliver' ? root + '/apply' : root;
    const headers = current ? { 'If-Match': blueprintTag(current) } : {};
    const data = action === 'deliver' ? { acknowledgeScope: true, publicationId } : { ...body, reason, acknowledgeScope: true };
    const result = ['remove','delete'].includes(action) ? await api.delete(path, { data, headers }) : await api.post(path, data, { headers });
    if (action === 'deliver') {
      const row = result.data; if (result.status !== 200 || row?.blueprintId !== current?.id || row.configurationVersion !== current?.version || row.enforcementConfirmed !== false || row.receiverVerified !== true
        || !['queued','partial','no-targets'].includes(row.phase) || !Number.isInteger(row.commandsQueued) || row.commandsQueued < 0 || !Array.isArray(row.results) || row.results.length !== row.commandsQueued) return fail(); return delivery(row,current!,userId,publicationId!);
    }
    if (action === 'create') { const row = parse(result.data); if (result.status !== 201 || row.version !== 1 || row.created_by !== userId || row.name !== body.name || row.platform !== body.platform || result.headers?.etag !== blueprintTag(row)) return fail(); return row; }
    if (!current || result.headers?.etag !== blueprintTag({ ...current, version: current.version + 1 })) return fail();
    if (['delete','remove'].includes(action)) { if (result.status !== 204) return fail(); return null; }
    const row = result.data; if (result.status !== 201 || !uuid.test(row?.id) || row.blueprint_id !== current.id || row.parentVersion !== current.version + 1) return fail();
    if (action === 'configuration' && (row.config_type !== body.config_type || row.config_name !== body.config_name || JSON.stringify(canonical(row.payload)) !== JSON.stringify(canonical(body.payload)))
      || action === 'assign' && (row.target_type !== body.target_type || row.target_id !== body.target_id || row.assigned_by !== userId)) return fail(); return row;
  },
};
