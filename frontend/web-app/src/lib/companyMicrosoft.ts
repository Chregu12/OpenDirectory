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
const stateSchema = z.object({ ...envelope, state: z.enum(['not_configured', 'configuration_unavailable', 'configured', 'connected', 'review_required']), microsoftTenantId: uuid.nullable(), connection: connection.nullable(), readClientId: uuid.optional(), writeClientId: uuid.optional() }).strict().refine(value => ['not_configured', 'configuration_unavailable'].includes(value.state)
  ? value.microsoftTenantId === null && !value.readClientId && !value.writeClientId
  : !!value.microsoftTenantId && !!value.readClientId && !!value.writeClientId && (value.state !== 'connected' || value.connection?.status === 'active'
    && value.connection.microsoftTenantId === value.microsoftTenantId && value.connection.readClientId === value.readClientId && value.connection.writeClientId === value.writeClientId));
const mappingsSchema = z.object({ ...envelope, poolId: uuid, pool: pool.nullable(), users: z.array(person).max(25), page: z.number().int().min(1).max(10000), hasMore: z.boolean() }).strict();
const productsSchema = z.object({ ...envelope, microsoftTenantId: uuid, checkedAt: timestamp, products: z.array(companyProviderProductSchema).max(1000) }).strict();
const event = z.object({ id: uuid, operationId: uuid, type: z.enum(['connect', 'renew', 'disconnect', 'bind_pool', 'retire_pool', 'bind_user', 'retire_user', 'sync_prepared', 'sync_dispatched', 'sync_finished', 'recover', 'review']), actorKind: z.enum(['human', 'workload']), actorUserId: uuid.nullable(), reason: z.string().min(10).max(500), createdAt: timestamp, resource: z.union([connection, pool, person]).nullable() }).strict().refine(value => value.actorKind === 'human' ? value.actorUserId !== null : value.actorUserId === null);
const historySchema = z.object({ ...envelope, events: z.array(event).max(25), page: z.number().int().min(1).max(10000), hasMore: z.boolean() }).strict();
const targetState = z.object({ id: uuid, revision: revision.nullable(), eligibilityRevision: revision, enabled: z.boolean(), deleted: z.boolean() }).strict().refine(value => value.deleted ? !value.enabled && value.revision === null : value.revision !== null);
const originSchema = z.object({ sourceType: z.enum(['direct', 'blueprint']), sourceId: z.union([z.literal('direct'), uuid]), grantId: uuid,
  eligibilityRevision: revision, live: z.boolean(), deadline: timestamp.nullable(), bindingValid: z.literal(true),
  rule: z.object({ id: uuid, groupId: uuid, revision, status: z.enum(['active', 'unlinked']) }).strict().nullable() }).strict().refine(value => value.sourceType === 'direct' ? value.sourceId === 'direct' && value.rule === null : value.sourceId !== 'direct');
const groupProof = z.object({ ruleId: uuid, groupId: uuid, revision, hash: z.string().regex(/^[a-f0-9]{64}$/), active: z.boolean(), membershipId: uuid.nullable(), eligibilityRevision: revision.nullable(), reviewDeadlineAt: timestamp.nullable() }).strict();
const deliveryTarget = z.object({ id: uuid, revision, status: z.enum(['processing', 'verifying', 'confirmed', 'conflict', 'failed', 'unknown']), owned: z.boolean(), lastOperationId: uuid, pendingOperationId: uuid.nullable(), uncertainOperationId: uuid.nullable(), errorCode: z.string().max(120).nullable(), retryAt: timestamp.nullable(), checkedAt: timestamp.nullable() }).strict();
const previewSchema = z.object({ ...envelope, poolId: uuid, userId: uuid, connection, pool, user: person,
  target: deliveryTarget.nullable(),
  local: z.object({ raw: z.object({ poolId: uuid, poolRevision: revision, target: targetState,
    assignment: z.object({ id: uuid, eligibilityRevision: revision }).strict().nullable(), origins: z.array(originSchema).max(10000) }).strict(), groups: z.array(groupProof).max(10000), desired: z.boolean() }).strict(),
  remote: z.object({ present: z.boolean(), direct: z.boolean(), active: z.boolean(), plansMatch: z.boolean(), inherited: z.boolean(), accountEnabled: z.boolean() }).strict(), stock: companyProviderProductSchema.nullable(),
  fingerprint: z.string().regex(/^[a-f0-9]{64}$/), action: z.enum(['assign', 'remove', 'confirmed', 'conflict', 'review', 'recover', 'verify', 'external_retained']), checkedAt: timestamp }).strict();
export type MicrosoftPreview = CompanyWire<z.infer<typeof previewSchema>>;
const syncResultFields = { operationId: uuid, poolId: uuid, userId: uuid, action: z.enum(['assign', 'remove', 'confirmed', 'conflict', 'review', 'verify', 'external_retained']), targetId: uuid, targetRevision: revision, status: z.enum(['verifying', 'confirmed', 'conflict', 'failed', 'unknown']), owned: z.boolean(), pendingOperationId: uuid.nullable(), uncertainOperationId: uuid.nullable(), errorCode: z.string().regex(/^[a-z0-9_]{1,120}$/).nullable(), eventId: uuid,
  kind: z.enum(['observed', 'acknowledged', 'rejected', 'unknown', 'not_sent']), retryAfter: z.number().int().min(1).max(3600).nullable(), retryAt: timestamp.nullable() };
const syncResultSchema = z.object(syncResultFields).strict().refine(value => value.kind !== 'acknowledged' || value.status === 'verifying' && value.pendingOperationId === value.operationId);
const syncReceiptSchema = z.object({ ...envelope, historical: z.boolean(), result: syncResultSchema }).strict();
export type MicrosoftSyncReceipt = CompanyWire<z.infer<typeof syncReceiptSchema>>;
export interface MicrosoftSyncIntent { operationId: string; poolId: string; userId: string; targetId: string | null; targetRevision: string; action: Exclude<MicrosoftPreview['action'], 'recover'>; body: { fingerprint: string; action: Exclude<MicrosoftPreview['action'], 'recover'>; reason: string; confirm: true } }
const recoveryPreviewSchema = z.object({ ...envelope, poolId: uuid, userId: uuid, recipient: targetState, connection, pool, user: person, target: deliveryTarget.nullable(),
  attempt: z.object({ id: uuid, phase: z.enum(['prepared', 'dispatched']), desired: z.boolean(), actorUserId: uuid, reason: z.string().min(10).max(500), createdAt: timestamp }).strict().nullable(),
  fingerprint: z.string().regex(/^[a-f0-9]{64}$/).nullable(), checkedAt: timestamp }).strict().refine(value => value.attempt ? value.target?.status === 'processing' && value.target.lastOperationId === value.attempt.id && !!value.fingerprint : value.target?.status !== 'processing' && value.fingerprint === null);
const recoveryReceiptSchema = z.object({ ...envelope, historical: z.boolean(), result: z.object({ ...syncResultFields, action: z.literal('recover'), interruptedOperationId: uuid, interruptedPhase: z.enum(['prepared', 'dispatched']), originalEventId: uuid }).strict() }).strict();
export type MicrosoftRecoveryPreview = CompanyWire<z.infer<typeof recoveryPreviewSchema>>;
export type MicrosoftRecoveryReceipt = CompanyWire<z.infer<typeof recoveryReceiptSchema>>;
export interface MicrosoftRecoveryIntent { operationId: string; poolId: string; userId: string; targetId: string; targetRevision: string; owned: boolean; pendingOperationId: string | null; uncertainOperationId: string | null; body: { fingerprint: string; interruptedOperationId: string; interruptedPhase: 'prepared' | 'dispatched'; reason: string; confirm: true } }
const reviewDecision = z.enum(['adopt', 'release']);
const reviewPreviewSchema = previewSchema.omit({ action: true }).extend({ target: deliveryTarget, stock: z.null(), assignmentError: z.literal('graph_assignment_error').nullable(),
  attempt: z.object({ id: uuid, desired: z.boolean(), actorUserId: uuid, reason: z.string().min(10).max(500), createdAt: timestamp, finishedAt: timestamp, before: previewSchema.shape.remote, notBefore: timestamp }).strict(),
  decisions: z.array(reviewDecision).min(1).max(2) }).strict();
const reviewReceiptSchema = z.object({ ...envelope, historical: z.boolean(), result: z.object({ operationId: uuid, poolId: uuid, userId: uuid, action: z.literal('review'), decision: reviewDecision, uncertainOperationId: uuid,
  targetId: uuid, targetRevision: revision, status: z.enum(['confirmed', 'conflict', 'failed']), owned: z.boolean(), pendingOperationId: z.null(), uncertainOperationIdAfter: z.null(), errorCode: z.string().regex(/^[a-z0-9_]{1,120}$/).nullable(), eventId: uuid, kind: z.literal('reviewed') }).strict() }).strict();
export type MicrosoftReviewPreview = CompanyWire<z.infer<typeof reviewPreviewSchema>>;
export type MicrosoftReviewReceipt = CompanyWire<z.infer<typeof reviewReceiptSchema>>;
export interface MicrosoftReviewIntent { operationId: string; poolId: string; userId: string; targetId: string; targetRevision: string; owned: boolean; canConfirm: boolean; cleanup: boolean; body: { fingerprint: string; uncertainOperationId: string; decision: 'adopt' | 'release'; reason: string; confirm: true } }
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
  canRetry(intent: MicrosoftIntent | MicrosoftSyncIntent | MicrosoftRecoveryIntent | MicrosoftReviewIntent) { return this.session.captured(intent); }
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
      if (value.page !== page || value.hasMore && value.events.length !== 25 || new Set(value.events.map(row => row.id)).size !== value.events.length || value.events.some(row => row.resource && row.resource.tenantId !== value.tenantId)) companyUnconfirmed(true);
    });
  }
  async users(page = 1, search = '') {
    return this.session.run(async (signal, check) => {
      this.session.require(); await this.people.access(signal); check(); const value = await this.people.users(page, search, signal); check(); await this.session.fresh(signal, check); return value;
    });
  }
  preview(poolId: string, userId: string): Promise<MicrosoftPreview> {
    uuid.parse(poolId); uuid.parse(userId);
    return this.session.run(async (signal, check) => {
      this.session.require(); const response = await api.post(base + '/pools/' + poolId + '/users/' + userId + '/preview', {}, { signal }); check();
      if (response.status !== 200) companyUnconfirmed(); const value = previewSchema.parse(response.data) as MicrosoftPreview; this.session.bind(value); await this.session.fresh(signal, check);
      const state = this.session.require();
      if (value.poolId !== poolId || value.pool.poolId !== poolId || value.local.raw.poolId !== poolId || value.userId !== userId || value.user.userId !== userId || value.local.raw.target.id !== userId
        || [value.connection, value.pool, value.user].some(row => row.tenantId !== value.tenantId) || value.connection.id !== state.connection?.id || value.connection.revision !== state.connection.revision
        || value.pool.connectionId !== value.connection.id || value.user.connectionId !== value.connection.id || value.connection.microsoftTenantId !== state.microsoftTenantId
        || value.connection.readClientId !== state.readClientId || value.connection.writeClientId !== state.writeClientId || [value.connection, value.pool, value.user].some(row => row.status !== 'active')
        || value.action === 'assign' && !value.local.desired || value.action === 'remove' && value.local.desired
        || value.stock && value.stock.skuId !== value.pool.skuId || value.action === 'assign' && (!value.stock || value.stock.appliesTo !== 'User' || value.stock.capabilityStatus !== 'Enabled' || value.stock.prepaidUnits.enabled <= value.stock.consumedUnits)
        || value.local.desired && (!value.local.raw.target.enabled || value.local.raw.target.deleted || value.local.raw.assignment?.eligibilityRevision !== value.local.raw.target.eligibilityRevision)
        || value.remote.direct && !value.remote.present || value.remote.active && !value.remote.direct || value.remote.plansMatch && !value.remote.direct || value.remote.inherited && !value.remote.present
        || value.local.groups.some(row => row.active && (!row.membershipId || row.eligibilityRevision !== value.local.raw.target.eligibilityRevision))
        || new Set(value.local.raw.origins.map(row => row.grantId)).size !== value.local.raw.origins.length || new Set(value.local.groups.map(row => row.ruleId)).size !== value.local.groups.length) companyUnconfirmed(true);
      return this.session.own(value);
    });
  }
  captureSync(value: MicrosoftPreview, reason: string): MicrosoftSyncIntent {
    const action = value.action;
    if (!this.session.captured(value) || action === 'recover' || value.target?.retryAt && Date.parse(value.target.retryAt) > Date.now()) return companyUnconfirmed();
    return this.session.own({ operationId: uuid.parse(crypto.randomUUID()), poolId: value.poolId, userId: value.userId, targetId: value.target?.id || null, targetRevision: value.target ? String(BigInt(value.target.revision) + BigInt(2)) : '2', action,
      body: { fingerprint: value.fingerprint, action, reason: companyReason(reason), confirm: true as const } });
  }
  sync(intent: MicrosoftSyncIntent): Promise<MicrosoftSyncReceipt> {
    return this.session.write(intent, async (signal, check) => {
      const response = await api.post(base + '/pools/' + intent.poolId + '/users/' + intent.userId + '/sync', intent.body, { headers: { 'Idempotency-Key': intent.operationId }, timeout: 60000, signal }); check();
      if (response.status !== 200) companyUnconfirmed(); const value = syncReceiptSchema.parse(response.data) as MicrosoftSyncReceipt; this.session.bind(value);
      if (value.result.operationId !== intent.operationId || value.result.poolId !== intent.poolId || value.result.userId !== intent.userId || value.result.action !== intent.action
        || intent.targetId && value.result.targetId !== intent.targetId || value.result.targetRevision !== intent.targetRevision
        || value.result.kind === 'acknowledged' && !['assign', 'remove'].includes(intent.action)
        || value.result.kind === 'unknown' && (value.result.status !== 'unknown' || value.result.uncertainOperationId !== intent.operationId)) companyUnconfirmed();
      return value;
    });
  }
  recoveryPreview(poolId: string, userId: string): Promise<MicrosoftRecoveryPreview> {
    uuid.parse(poolId); uuid.parse(userId);
    return this.session.run(async (signal, check) => {
      this.session.require(); const response = await api.post(base + '/pools/' + poolId + '/users/' + userId + '/recovery-preview', {}, { signal }); check();
      if (response.status !== 200) companyUnconfirmed(); const value = recoveryPreviewSchema.parse(response.data) as MicrosoftRecoveryPreview; this.session.bind(value); await this.session.fresh(signal, check);
      const state = this.session.require();
      if (value.poolId !== poolId || value.pool.poolId !== poolId || value.userId !== userId || value.user.userId !== userId || value.recipient.id !== userId
        || value.connection.id !== state.connection?.id || value.connection.revision !== state.connection.revision
        || [value.connection, value.pool, value.user].some(row => row.tenantId !== value.tenantId || row.status !== 'active')
        || value.pool.connectionId !== value.connection.id || value.user.connectionId !== value.connection.id) companyUnconfirmed(true);
      return this.session.own(value);
    });
  }
  captureRecovery(value: MicrosoftRecoveryPreview, reason: string): MicrosoftRecoveryIntent {
    if (!this.session.captured(value) || !value.target || !value.attempt || !value.fingerprint) return companyUnconfirmed();
    return this.session.own({ operationId: uuid.parse(crypto.randomUUID()), poolId: value.poolId, userId: value.userId, targetId: value.target.id, targetRevision: String(BigInt(value.target.revision) + BigInt(1)), owned: value.target.owned,
      pendingOperationId: value.target.pendingOperationId, uncertainOperationId: value.target.uncertainOperationId,
      body: { fingerprint: value.fingerprint, interruptedOperationId: value.attempt.id, interruptedPhase: value.attempt.phase, reason: companyReason(reason), confirm: true as const } });
  }
  recover(intent: MicrosoftRecoveryIntent): Promise<MicrosoftRecoveryReceipt> {
    return this.session.write(intent, async (signal, check) => {
      const response = await api.post(base + '/pools/' + intent.poolId + '/users/' + intent.userId + '/recover', intent.body, { headers: { 'Idempotency-Key': intent.operationId }, timeout: 15000, signal }); check();
      if (response.status !== 200) companyUnconfirmed(); const value = recoveryReceiptSchema.parse(response.data) as MicrosoftRecoveryReceipt; this.session.bind(value);
      const result = value.result, prepared = intent.body.interruptedPhase === 'prepared';
      if (result.operationId !== intent.operationId || result.poolId !== intent.poolId || result.userId !== intent.userId || result.targetId !== intent.targetId || result.targetRevision !== intent.targetRevision
        || result.interruptedOperationId !== intent.body.interruptedOperationId || result.interruptedPhase !== intent.body.interruptedPhase || result.owned !== intent.owned || result.pendingOperationId !== intent.pendingOperationId
        || result.uncertainOperationId !== (prepared ? intent.uncertainOperationId : intent.body.interruptedOperationId)
        || result.kind !== (prepared ? 'not_sent' : 'unknown') || result.status !== (prepared ? 'failed' : 'unknown')
        || result.errorCode !== (prepared ? 'process_recovered_before_send' : 'process_recovered_after_dispatch') || result.retryAfter !== null || result.retryAt !== null) companyUnconfirmed();
      return value;
    });
  }
  reviewPreview(poolId: string, userId: string): Promise<MicrosoftReviewPreview> {
    uuid.parse(poolId); uuid.parse(userId);
    return this.session.run(async (signal, check) => {
      this.session.require(); const response = await api.post(base + '/pools/' + poolId + '/users/' + userId + '/review-preview', {}, { signal }); check();
      if (response.status !== 200) companyUnconfirmed(); const value = reviewPreviewSchema.parse(response.data) as MicrosoftReviewPreview; this.session.bind(value); await this.session.fresh(signal, check);
      const state = this.session.require();
      if (value.poolId !== poolId || value.pool.poolId !== poolId || value.local.raw.poolId !== poolId || value.userId !== userId || value.user.userId !== userId || value.local.raw.target.id !== userId
        || value.connection.id !== state.connection?.id || value.connection.revision !== state.connection.revision || [value.connection, value.pool, value.user].some(row => row.tenantId !== value.tenantId || row.status !== 'active')
        || value.pool.connectionId !== value.connection.id || value.user.connectionId !== value.connection.id || value.target.uncertainOperationId !== value.attempt.id || value.target.status === 'processing' || value.target.pendingOperationId !== null
        || new Set(value.decisions).size !== value.decisions.length || !value.decisions.includes('release')
        || value.decisions.includes('adopt') && (!value.attempt.desired || value.target.owned || value.attempt.before.present || !value.remote.direct || !value.remote.plansMatch || value.local.desired && (!value.remote.active || !value.remote.accountEnabled || value.assignmentError !== null))
        || Date.parse(value.attempt.notBefore) < Date.parse(value.attempt.finishedAt) + 30000 || Date.parse(value.attempt.notBefore) > Date.parse(value.attempt.finishedAt) + 3600000
        || [value.remote, value.attempt.before].some(row => row.direct && !row.present || row.active && !row.direct || row.plansMatch && !row.direct || row.inherited && !row.present)
        || value.local.desired && (!value.local.raw.target.enabled || value.local.raw.target.deleted || value.local.raw.assignment?.eligibilityRevision !== value.local.raw.target.eligibilityRevision)) companyUnconfirmed(true);
      return this.session.own(value);
    });
  }
  captureReview(value: MicrosoftReviewPreview, decision: 'adopt' | 'release', reason: string): MicrosoftReviewIntent {
    reviewDecision.parse(decision);
    if (!this.session.captured(value) || !value.decisions.includes(decision) || Date.parse(value.attempt.notBefore) > Date.now()) return companyUnconfirmed();
    const owned = decision === 'adopt' || value.target.owned && value.remote.direct;
    return this.session.own({ operationId: uuid.parse(crypto.randomUUID()), poolId: value.poolId, userId: value.userId, targetId: value.target.id, targetRevision: String(BigInt(value.target.revision) + BigInt(1)), owned,
      canConfirm: value.local.desired && owned && value.remote.direct && value.remote.active && value.remote.plansMatch && value.remote.accountEnabled || !value.local.desired && !value.remote.present,
      cleanup: decision === 'adopt' && !value.local.desired, body: { fingerprint: value.fingerprint, uncertainOperationId: value.attempt.id, decision, reason: companyReason(reason), confirm: true as const } });
  }
  review(intent: MicrosoftReviewIntent): Promise<MicrosoftReviewReceipt> {
    return this.session.write(intent, async (signal, check) => {
      const response = await api.post(base + '/pools/' + intent.poolId + '/users/' + intent.userId + '/review', intent.body, { headers: { 'Idempotency-Key': intent.operationId }, timeout: 60000, signal }); check();
      if (response.status !== 200) companyUnconfirmed(); const value = reviewReceiptSchema.parse(response.data) as MicrosoftReviewReceipt; this.session.bind(value); const result = value.result;
      if (result.operationId !== intent.operationId || result.poolId !== intent.poolId || result.userId !== intent.userId || result.targetId !== intent.targetId || result.targetRevision !== intent.targetRevision
        || result.uncertainOperationId !== intent.body.uncertainOperationId || result.decision !== intent.body.decision || result.owned !== intent.owned || result.status === 'confirmed' && !intent.canConfirm
        || intent.cleanup && (result.status !== 'conflict' || result.errorCode !== 'review_adopted_for_cleanup')) companyUnconfirmed();
      return value;
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
