import { z } from 'zod';
import { api } from './api';
import { CompanyApplicationsV2Client } from './companyApplicationsV2';
import { companyProviderProductSchema } from './companyLicenseProvider';
import { CompanyWorkflowContext, CompanyWorkflowSession, CompanyWire, companyUuid as uuid, companyRevision as revision, companyTimestamp as timestamp, companyReason, companyUnconfirmed } from './companyAssignmentProtocol';

const base = '/api/licenses/company/provider/microsoft';
const envelope = { schemaVersion: z.literal(1), companyMicrosoftProtocol: z.literal(1), actorUserId: uuid, tenantId: uuid };
const binding = { id: uuid, tenantId: uuid, revision, createdAt: timestamp, updatedAt: timestamp };
const connection = z.object({ ...binding, status: z.enum(['active', 'disconnected']), tenantGeneration: revision, microsoftTenantId: uuid, readClientId: uuid, writeClientId: uuid }).strict();
const pool = z.object({ ...binding, status: z.enum(['active', 'retired']), connectionId: uuid, poolId: uuid, skuId: uuid, disabledPlans: z.array(uuid).max(0) }).strict();
const person = z.object({ ...binding, status: z.enum(['active', 'retired']), connectionId: uuid, userId: uuid, objectId: uuid }).strict();
const stateSchema = z.object({ ...envelope, state: z.enum(['not_configured', 'configured', 'connected', 'review_required']), microsoftTenantId: uuid.nullable(), connection: connection.nullable(), readClientId: uuid.optional(), writeClientId: uuid.optional() }).strict().refine(value => value.state === 'not_configured'
  ? value.microsoftTenantId === null && !value.readClientId && !value.writeClientId
  : !!value.microsoftTenantId && !!value.readClientId && !!value.writeClientId && (value.state !== 'connected' || value.connection?.status === 'active'
    && value.connection.microsoftTenantId === value.microsoftTenantId && value.connection.readClientId === value.readClientId && value.connection.writeClientId === value.writeClientId));
const mappingsSchema = z.object({ ...envelope, poolId: uuid, pool: pool.nullable(), users: z.array(person).max(25), page: z.number().int().min(1).max(10000), hasMore: z.boolean() }).strict();
const productsSchema = z.object({ ...envelope, microsoftTenantId: uuid, checkedAt: timestamp, products: z.array(companyProviderProductSchema).max(1000) }).strict();
const event = z.object({ id: uuid, operationId: uuid, type: z.enum(['connect', 'renew', 'disconnect', 'bind_pool', 'retire_pool', 'bind_user', 'retire_user']), actorKind: z.literal('human'), actorUserId: uuid, reason: z.string().min(10).max(500), createdAt: timestamp, resource: z.union([connection, pool, person]) }).strict();
const historySchema = z.object({ ...envelope, events: z.array(event).max(25), page: z.number().int().min(1).max(10000), hasMore: z.boolean() }).strict();
export type MicrosoftState = CompanyWire<z.infer<typeof stateSchema>>;
export type MicrosoftMappings = CompanyWire<z.infer<typeof mappingsSchema>>;
export type MicrosoftProducts = CompanyWire<z.infer<typeof productsSchema>>;
export type MicrosoftHistory = CompanyWire<z.infer<typeof historySchema>>;
type Mapping = CompanyWire<z.infer<typeof pool | typeof person>>;
type Kind = 'connection' | 'pool' | 'user';
export interface MicrosoftIntent { operationId: string; action: 'connect' | 'renew' | 'bind_pool' | 'bind_user' | 'disconnect' | 'retire_pool' | 'retire_user'; path: string; kind: Kind; field: 'connection' | 'pool' | 'user' | 'binding'; etag: string | null; expectedId: string; expectedRevision: string; body: Record<string, unknown>; connectionId: string | null; targetId: string | null }
export interface MicrosoftReceipt { operationId: string; action: MicrosoftIntent['action']; historical: boolean }
const etag = (kind: Kind, row: { id: string; revision: string }) => `"company-microsoft-${kind}-${uuid.parse(row.id)}-${revision.parse(row.revision)}"`;

export class CompanyMicrosoftClient {
  private session: CompanyWorkflowSession<MicrosoftState>;
  private people: CompanyApplicationsV2Client;
  private expectations = new WeakMap<MicrosoftIntent, MicrosoftState>();
  constructor(expected: CompanyWorkflowContext) { this.session = new CompanyWorkflowSession(base + '/state', stateSchema, expected); this.people = new CompanyApplicationsV2Client(expected); }
  invalidate() { this.session.invalidate(); this.people.invalidate(); }
  dispose() { this.session.dispose(); this.people.dispose(); }
  async state() { return this.session.own(await this.session.access()); }
  canRetry(intent: MicrosoftIntent) { return this.session.captured(intent); }
  private read<Schema extends z.ZodTypeAny>(path: string, schema: Schema, params?: Record<string, string | number>, validate?: (value: CompanyWire<z.infer<Schema>>) => void): Promise<CompanyWire<z.infer<Schema>>> {
    return this.session.run(async (signal, check) => {
      this.session.require(); const response = await api.get(base + path, { params, signal }); check(); if (response.status !== 200) companyUnconfirmed();
      const value = schema.parse(response.data) as CompanyWire<z.infer<Schema>> & CompanyWorkflowContext; this.session.bind(value); await this.session.fresh(signal, check); validate?.(value); return this.session.own(value);
    });
  }
  async mappings(poolId: string, page = 1) {
    uuid.parse(poolId); z.number().int().min(1).max(10000).parse(page);
    return this.read('/pools/' + poolId + '/mappings', mappingsSchema, { page }, value => {
    if (value.poolId !== poolId || value.page !== page || value.pool && (value.pool.poolId !== poolId || value.pool.status !== 'active')
      || value.users.some(row => row.status !== 'active') || value.hasMore && value.users.length !== 25 || new Set(value.users.map(row => row.userId)).size !== value.users.length
      || new Set(value.users.map(row => row.id)).size !== value.users.length || new Set(value.users.map(row => row.objectId)).size !== value.users.length
      || [value.pool, ...value.users].some(row => row && (row.tenantId !== value.tenantId || row.connectionId !== this.session.require().connection?.id))) companyUnconfirmed(true);
    if (value.pool) this.session.own(value.pool); value.users.forEach(row => this.session.own(row));
    });
  }
  async products() {
    return this.read('/products', productsSchema, undefined, value => {
    if (value.microsoftTenantId !== this.session.require().microsoftTenantId || new Set(value.products.map(row => row.skuId)).size !== value.products.length) companyUnconfirmed(true);
    });
  }
  async history(page = 1) {
    z.number().int().min(1).max(10000).parse(page); return this.read('/history', historySchema, { page }, value => {
      if (value.page !== page || value.hasMore && value.events.length !== 25 || new Set(value.events.map(row => row.id)).size !== value.events.length || value.events.some(row => row.resource.tenantId !== value.tenantId)) companyUnconfirmed(true);
    });
  }
  async users(page = 1, search = '') {
    return this.session.run(async (signal, check) => {
      this.session.require(); await this.people.access(signal); check(); const value = await this.people.users(page, search, signal); check(); await this.session.fresh(signal, check); return value;
    });
  }
  private intent(state: MicrosoftState, values: Omit<MicrosoftIntent, 'operationId' | 'body'>, body: Record<string, unknown>, reason: string) {
    if (!this.session.captured(state)) companyUnconfirmed();
    const operationId = uuid.parse(crypto.randomUUID());
    const intent = this.session.own({ ...values, operationId, expectedId: values.expectedId || operationId, body: { ...body, reason: companyReason(reason), confirm: true } });
    this.expectations.set(intent, state); return intent;
  }
  connect(state: MicrosoftState, reason: string, renew = false) {
    if (renew ? !state.connection || !['connected', 'review_required'].includes(state.state) || state.connection.microsoftTenantId !== state.microsoftTenantId : state.state !== 'configured' || state.connection) companyUnconfirmed();
    const row = state.connection;
    return this.intent(state, { action: renew ? 'renew' : 'connect', path: renew ? '/connections/' + row.id + '/renew' : '/connections', kind: 'connection', field: 'connection',
      etag: renew ? etag('connection', row) : null, expectedId: renew ? row.id : '', expectedRevision: renew ? String(BigInt(row.revision) + BigInt(1)) : '1', connectionId: null, targetId: null },
      { microsoftTenantId: uuid.parse(state.microsoftTenantId), readClientId: uuid.parse(state.readClientId), writeClientId: uuid.parse(state.writeClientId) }, reason);
  }
  bindPool(state: MicrosoftState, products: MicrosoftProducts, poolId: string, skuId: string, reason: string) {
    uuid.parse(poolId); uuid.parse(skuId);
    if (state.state !== 'connected' || !state.connection || !this.session.captured(products) || products.microsoftTenantId !== state.microsoftTenantId
      || !products.products.some(row => row.skuId === skuId && row.appliesTo === 'User' && row.capabilityStatus === 'Enabled' && row.prepaidUnits.enabled > 0)) companyUnconfirmed();
    return this.intent(state, { action: 'bind_pool', path: '/pools/' + poolId + '/bind', kind: 'pool', field: 'pool', etag: etag('connection', state.connection), expectedId: '', expectedRevision: '1', connectionId: state.connection.id, targetId: poolId }, { skuId, exclusiveDirectManagement: true }, reason);
  }
  bindUser(state: MicrosoftState, userId: string, objectId: string, reason: string) {
    uuid.parse(userId); uuid.parse(objectId); if (state.state !== 'connected' || !state.connection) companyUnconfirmed();
    return this.intent(state, { action: 'bind_user', path: '/users/' + userId + '/bind', kind: 'user', field: 'user', etag: etag('connection', state.connection), expectedId: '', expectedRevision: '1', connectionId: state.connection.id, targetId: userId }, { objectId, exclusiveDirectManagement: true }, reason);
  }
  retire(state: MicrosoftState, kind: Kind, row: Mapping | NonNullable<MicrosoftState['connection']>, reason: string) {
    if (row.tenantId !== state.tenantId || row.status !== 'active' || (kind === 'connection' ? row !== state.connection : !this.session.captured(row))) companyUnconfirmed();
    const path = { connection: 'connections', pool: 'pool-mappings', user: 'user-mappings' }[kind];
    return this.intent(state, { action: kind === 'connection' ? 'disconnect' : kind === 'pool' ? 'retire_pool' : 'retire_user', path: '/' + path + '/' + row.id + '/retire', kind, field: 'binding', etag: etag(kind, row), expectedId: row.id, expectedRevision: String(BigInt(row.revision) + BigInt(1)), connectionId: kind === 'connection' ? null : (row as Mapping).connectionId,
      targetId: kind === 'user' ? (row as CompanyWire<z.infer<typeof person>>).userId : kind === 'pool' ? (row as CompanyWire<z.infer<typeof pool>>).poolId : null }, {}, reason);
  }
  async write(intent: MicrosoftIntent): Promise<MicrosoftReceipt> {
    return this.session.write(intent, async (signal, check) => {
      const response = await api.post(base + intent.path, intent.body, { headers: { 'Idempotency-Key': intent.operationId, ...(intent.etag ? { 'If-Match': intent.etag } : {}) }, signal }); check();
      const rowSchema = { connection, pool, user: person }[intent.kind];
      const value = z.object({ ...envelope, [intent.field]: rowSchema, historical: z.boolean() }).strict().parse(response.data); this.session.bind(value as CompanyWorkflowContext);
      const row = value[intent.field] as z.infer<typeof connection> & z.infer<typeof pool> & z.infer<typeof person>;
      const original = this.expectations.get(intent); if (!original) companyUnconfirmed();
      if (response.status !== (value.historical || !['connect', 'bind_pool', 'bind_user'].includes(intent.action) ? 200 : 201) || row.tenantId !== value.tenantId || row.id !== intent.expectedId || row.revision !== intent.expectedRevision
        || response.headers.etag !== etag(intent.kind, row) || row.status !== (intent.action === 'disconnect' ? 'disconnected' : intent.action.startsWith('retire_') ? 'retired' : 'active')
        || intent.connectionId && row.connectionId !== intent.connectionId || intent.action === 'bind_pool' && (row.poolId !== intent.targetId || row.skuId !== intent.body.skuId)
        || intent.action === 'bind_user' && (row.userId !== intent.targetId || row.objectId !== intent.body.objectId)
        || ['connect', 'renew'].includes(intent.action) && (row.microsoftTenantId !== original.microsoftTenantId || row.readClientId !== original.readClientId || row.writeClientId !== original.writeClientId)) companyUnconfirmed();
      return { operationId: intent.operationId, action: intent.action, historical: value.historical };
    });
  }
}
