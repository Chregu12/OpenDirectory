import { z } from 'zod';
import { api } from './api';
import { companyBlueprintPayload, CompanyBlueprintConfigType } from './companyBlueprints';
import { directoryUsers, UserPage } from './directoryUsers';
import {
  CompanyWorkflowContext, CompanyWorkflowSession, companyUuid as uuid, companyRevision as revision, companyTimestamp as timestamp,
  companyCount as count, companySourcesSchema, companyText, companyReason, companyPage, companyCheckPage, companyUnconfirmed, companyFreeze,
} from './companyAssignmentProtocol';

const base = '/api/company-blueprint-assignments';
const envelope = { schemaVersion: z.literal(1), actorUserId: uuid, tenantId: uuid };
const capabilities = z.object({ ...envelope, companyBlueprintAssignmentsProtocol: z.literal(1), permissions: z.tuple([
  z.literal('company.blueprints.assignments.read'), z.literal('company.blueprints.assign'),
]), configurationMode: z.literal('local-only'), allocationMode: z.literal('local-only'), supportedTargets: z.tuple([z.literal('user')]), maxApplications: z.literal(25) }).strict();
const ordinal = z.number().int().min(1).max(2147483647);
const poolCapture = z.object({ poolId: uuid, poolRevision: revision }).strict();
const bindingFields = { id: uuid, tenantId: uuid, userId: uuid, blueprintId: uuid, version: ordinal, eligibilityRevision: revision, revision,
  status: z.enum(['active', 'removed']), operationId: uuid, removalOperationId: uuid.nullable(), createdAt: timestamp, removedAt: timestamp.nullable(),
  appPoolIds: z.array(uuid).max(25).refine(values => new Set(values).size === values.length) };
const binding = z.union([z.object({ ...bindingFields, actorUserId: uuid }).strict(), z.object({ ...bindingFields, actorUserId: z.null(),
  actor: z.object({ kind: z.literal('application'), id: uuid, clientId: z.string().min(1).max(255), clientRevision: revision }).strict() }).strict()]).refine(value => value.status === 'active'
    ? value.removalOperationId === null && value.removedAt === null && value.revision === '1'
    : value.removalOperationId !== null && value.removedAt !== null && BigInt(value.revision) > BigInt(1) && Date.parse(value.removedAt) >= Date.parse(value.createdAt));
const source = z.object({ blueprintId: uuid, configurationId: uuid }).strict();
const variant = z.object({ payloadJson: z.string().max(65536), sources: z.array(source).min(1).max(10000) }).strict();
const configType = z.enum(['screen_lock', 'filevault', 'software_update']);
const resolution = {
  effectiveConfigurations: z.array(variant.extend({ configType }).strict()).max(3),
  conflicts: z.array(z.object({ configType, variants: z.array(variant).min(2).max(10000) }).strict()).max(3), hasConflicts: z.boolean(),
};
const previewSchema = z.object({ ...envelope, userId: uuid, blueprintId: uuid, version: ordinal, eligibilityRevision: revision,
  pools: z.array(poolCapture.extend({ totalSeats: z.number().int().min(1).max(10000), usedSeats: count, availableSeats: count, additionalSeats: z.number().int().min(0).max(1) }).strict()
    .refine(value => value.usedSeats + value.availableSeats === value.totalSeats)).max(25), ...resolution }).strict();
const removalPreviewSchema = z.object({ ...envelope, assignment: binding, eligibilityRevision: revision, pools: z.array(poolCapture).max(25) }).strict();
const effectiveSchema = z.object({ ...envelope, userId: uuid, assignments: z.array(binding).max(10000), ...resolution,
  applications: z.array(z.object({ poolId: uuid, sources: companySourcesSchema }).strict()).max(10000) }).strict();
const poolResult = z.object({ poolId: uuid, eventId: uuid, beforeRevision: revision, afterRevision: revision, sourceAdded: z.boolean(), sourceRemoved: z.boolean(),
  seatAllocated: z.boolean(), seatReleased: z.boolean(), effectiveAssignmentRetained: z.boolean() }).strict()
  .refine(value => BigInt(value.afterRevision) === BigInt(value.beforeRevision) + BigInt(1));
const receipt = z.object({ ...envelope, operationId: uuid, assignmentId: uuid, action: z.enum(['assigned', 'removed']), outcome: z.enum(['applied', 'already_applied']),
  revision, deliveryStatus: z.literal('pending'), pools: z.array(poolResult).max(25) }).strict();
export type CompanyBlueprintBinding = Required<z.infer<typeof binding>>;
export type CompanyBlueprintAssignmentPreview = Required<z.infer<typeof previewSchema>>;
export type CompanyBlueprintRemovalPreview = Required<z.infer<typeof removalPreviewSchema>>;
export type CompanyBlueprintEffective = Required<z.infer<typeof effectiveSchema>>;
export type CompanyBlueprintAssignmentReceipt = Required<z.infer<typeof receipt>>;
export interface CompanyBlueprintAssignmentPage { assignments: CompanyBlueprintBinding[]; total: number; page: number; limit: 25 }
export interface CompanyBlueprintAssignmentIntent { operationId: string; assignmentId: string; action: 'assigned' | 'removed'; etag: string | null; body: Record<string, unknown> }
export const companyBlueprintAssignmentEtag = (value: { id?: string; revision?: string }) => `"company-blueprint-assignment-${uuid.parse(value.id)}-${revision.parse(value.revision)}"`;
function validateResolution(value: z.infer<typeof previewSchema> | z.infer<typeof effectiveSchema>) {
  if (value.hasConflicts !== (value.conflicts.length > 0)) companyUnconfirmed();
  const types = new Set<string>(); const sources = new Set<string>();
  const verify = (type: CompanyBlueprintConfigType, variants: z.infer<typeof variant>[]) => {
    if (types.has(type)) companyUnconfirmed(); types.add(type); const payloads = new Set<string>();
    for (const entry of variants) {
      const parsed = companyBlueprintPayload(type, entry.payloadJson);
      const key = JSON.stringify(Object.keys(parsed).sort().map(field => [field, parsed[field]]));
      if (payloads.has(key)) companyUnconfirmed(); payloads.add(key);
      for (const item of entry.sources) {
        const origin = item.blueprintId + ':' + item.configurationId; if (sources.has(origin)) companyUnconfirmed(); sources.add(origin);
      }
    }
  };
  value.effectiveConfigurations.forEach(item => verify(item.configType, [item])); value.conflicts.forEach(item => verify(item.configType, item.variants));
}

export class CompanyBlueprintAssignmentsClient {
  private session: CompanyWorkflowSession<CompanyWorkflowContext>;
  private seatCaptures = new WeakMap<CompanyBlueprintAssignmentIntent, Map<string, number>>();
  constructor(expected: CompanyWorkflowContext) { this.session = new CompanyWorkflowSession(base + '/capabilities', capabilities, expected); }
  access(signal?: AbortSignal) { return this.session.access(signal); }
  invalidate() { this.session.invalidate(); }
  dispose() { this.session.dispose(); }
  canRetry(intent: CompanyBlueprintAssignmentIntent) { return this.session.captured(intent); }
  async users(page = 1, search = '', signal?: AbortSignal): Promise<UserPage | null> {
    companyPage(page); companyText(0, 100).parse(search.trim());
    return this.session.run(async (requestSignal, check) => {
      const context = this.session.require(); const access = await directoryUsers.access(); check();
      if (access.userId !== context.actorUserId || access.demoMode) companyUnconfirmed(true);
      if (!access.permissions.includes('users.read')) { await this.session.fresh(requestSignal, check); return null; }
      if (access.directoryReadProtocol !== 1) companyUnconfirmed();
      const result = await directoryUsers.list(page, search.trim(), 'true', requestSignal); check();
      companyCheckPage(result.users, result.total, page, result.users.map(user => user.id));
      if (result.users.some(user => !user.enabled || !uuid.safeParse(user.id).success)) companyUnconfirmed();
      const current = await directoryUsers.access(); check();
      if (current.userId !== context.actorUserId || current.demoMode || current.directoryReadProtocol !== 1 || !current.permissions.includes('users.read')) companyUnconfirmed(true);
      await this.session.fresh(requestSignal, check); return companyFreeze(result);
    }, signal);
  }
  async list(userId: string, page = 1, signal?: AbortSignal): Promise<CompanyBlueprintAssignmentPage> {
    uuid.parse(userId); companyPage(page);
    return this.session.run(async (requestSignal, check) => {
      this.session.require(); const response = await api.get(base, { params: { userId, page, limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) companyUnconfirmed();
      const value = z.object({ ...envelope, userId: z.literal(userId), assignments: z.array(binding).max(25), page: z.literal(page), limit: z.literal(25), total: count }).strict().parse(response.data);
      this.session.bind(value as CompanyWorkflowContext); companyCheckPage(value.assignments, value.total, page, value.assignments.map(row => row.id));
      if (value.assignments.some(row => row.tenantId !== value.tenantId || row.userId !== userId)) companyUnconfirmed(true);
      await this.session.fresh(requestSignal, check); return companyFreeze(value) as CompanyBlueprintAssignmentPage;
    }, signal);
  }
  async get(id: string, signal?: AbortSignal): Promise<CompanyBlueprintBinding> {
    uuid.parse(id);
    return this.session.run(async (requestSignal, check) => {
      this.session.require(); const response = await api.get(base + '/' + id, { signal: requestSignal }); check();
      if (response.status !== 200) companyUnconfirmed();
      const value = z.object({ ...envelope, assignment: binding }).strict().parse(response.data); this.session.bind(value as CompanyWorkflowContext);
      if (value.assignment.id !== id || value.assignment.tenantId !== value.tenantId || response.headers?.etag !== companyBlueprintAssignmentEtag(value.assignment)) companyUnconfirmed();
      await this.session.fresh(requestSignal, check); return this.session.own(value.assignment) as CompanyBlueprintBinding;
    }, signal);
  }
  async preview(input: { userId: string; blueprintId: string; version: number }, expectedPools: string[], signal?: AbortSignal): Promise<CompanyBlueprintAssignmentPreview> {
    const values = z.object({ userId: uuid, blueprintId: uuid, version: ordinal }).strict().parse(input);
    return this.session.run(async (requestSignal, check) => {
      this.session.require(); const response = await api.post(base + '/preview', values, { signal: requestSignal }); check();
      if (response.status !== 200) companyUnconfirmed(); const value = previewSchema.parse(response.data); this.session.bind(value as CompanyWorkflowContext);
      if (value.userId !== values.userId || value.blueprintId !== values.blueprintId || value.version !== values.version
        || new Set(value.pools.map(pool => pool.poolId)).size !== value.pools.length || value.pools.length !== expectedPools.length
        || value.pools.some(pool => !expectedPools.includes(pool.poolId))) companyUnconfirmed();
      validateResolution(value); await this.session.fresh(requestSignal, check); return this.session.own(value) as CompanyBlueprintAssignmentPreview;
    }, signal);
  }
  async effective(userId: string, signal?: AbortSignal): Promise<CompanyBlueprintEffective> {
    uuid.parse(userId);
    return this.session.run(async (requestSignal, check) => {
      this.session.require(); const response = await api.get(base + '/users/' + userId + '/effective', { signal: requestSignal }); check();
      if (response.status !== 200) companyUnconfirmed(); const value = effectiveSchema.parse(response.data); this.session.bind(value as CompanyWorkflowContext);
      if (value.userId !== userId || new Set(value.assignments.map(row => row.id)).size !== value.assignments.length
        || value.assignments.some(row => row.tenantId !== value.tenantId || row.userId !== userId || row.status !== 'active')
        || new Set(value.applications.map(app => app.poolId)).size !== value.applications.length) companyUnconfirmed();
      validateResolution(value); await this.session.fresh(requestSignal, check); return companyFreeze(value) as CompanyBlueprintEffective;
    }, signal);
  }
  captureAssign(value: CompanyBlueprintAssignmentPreview, reason: string): CompanyBlueprintAssignmentIntent {
    if (!this.session.captured(value) || value.hasConflicts || value.pools.some(pool => pool.additionalSeats > pool.availableSeats)) return companyUnconfirmed();
    const id = uuid.parse(crypto.randomUUID());
    const intent: CompanyBlueprintAssignmentIntent = { operationId: uuid.parse(crypto.randomUUID()), assignmentId: id, action: 'assigned', etag: null, body: {
      id, userId: value.userId, blueprintId: value.blueprintId, version: value.version, eligibilityRevision: value.eligibilityRevision,
      pools: value.pools.map(pool => ({ poolId: pool.poolId, poolRevision: pool.poolRevision })), reason: companyReason(reason), confirm: true,
    } };
    this.seatCaptures.set(intent, new Map(value.pools.map(pool => [pool.poolId, pool.additionalSeats]))); return this.session.own(intent);
  }
  async removalPreview(id: string, signal?: AbortSignal): Promise<CompanyBlueprintRemovalPreview> {
    uuid.parse(id);
    return this.session.run(async (requestSignal, check) => {
      this.session.require(); const response = await api.get(base + '/' + id + '/removal-preview', { signal: requestSignal }); check();
      if (response.status !== 200) companyUnconfirmed(); const value = removalPreviewSchema.parse(response.data); this.session.bind(value as CompanyWorkflowContext);
      if (value.assignment.id !== id || value.assignment.tenantId !== value.tenantId || value.assignment.status !== 'active'
        || response.headers?.etag !== companyBlueprintAssignmentEtag(value.assignment) || new Set(value.pools.map(pool => pool.poolId)).size !== value.pools.length
        || value.pools.length !== value.assignment.appPoolIds.length || value.pools.some(pool => !value.assignment.appPoolIds.includes(pool.poolId))) companyUnconfirmed();
      await this.session.fresh(requestSignal, check); return this.session.own(value) as CompanyBlueprintRemovalPreview;
    }, signal);
  }
  captureRemove(preview: CompanyBlueprintRemovalPreview, reason: string): CompanyBlueprintAssignmentIntent {
    const value = preview.assignment;
    if (!this.session.captured(preview) || value.status !== 'active'
      || value.appPoolIds.length !== preview.pools.length || preview.pools.some(pool => !value.appPoolIds.includes(pool.poolId))) return companyUnconfirmed();
    return this.session.own({ operationId: uuid.parse(crypto.randomUUID()), assignmentId: value.id, action: 'removed', etag: companyBlueprintAssignmentEtag(value), body: {
      userId: value.userId, eligibilityRevision: preview.eligibilityRevision, pools: preview.pools.map(pool => ({ poolId: pool.poolId, poolRevision: pool.poolRevision })),
      reason: companyReason(reason), confirm: true,
    } });
  }
  write(intent: CompanyBlueprintAssignmentIntent, signal?: AbortSignal): Promise<CompanyBlueprintAssignmentReceipt> {
    return this.session.write(intent, async (requestSignal, check) => {
      const response = await api.post(base + (intent.action === 'removed' ? '/' + intent.assignmentId + '/remove' : ''), intent.body,
        { headers: { 'Idempotency-Key': intent.operationId, ...(intent.etag ? { 'If-Match': intent.etag } : {}) }, signal: requestSignal }); check();
      const value = receipt.parse(response.data); this.session.bind(value as CompanyWorkflowContext);
      if (response.status !== (intent.action === 'assigned' && value.outcome === 'applied' ? 201 : 200) || value.operationId !== intent.operationId
        || value.assignmentId !== intent.assignmentId || value.action !== intent.action || value.revision !== (intent.action === 'assigned' ? '1' : '2')) companyUnconfirmed();
      const captures = intent.body.pools as { poolId: string; poolRevision: string }[];
      if (value.pools.length !== captures.length || new Set(value.pools.map(pool => pool.poolId)).size !== value.pools.length || value.pools.some(pool => {
        const captured = captures.find(item => item.poolId === pool.poolId);
        return !captured || captured.poolRevision !== pool.beforeRevision || (intent.action === 'assigned'
          ? !pool.sourceAdded || pool.sourceRemoved || pool.seatReleased || pool.effectiveAssignmentRetained === pool.seatAllocated
            || Number(pool.seatAllocated) !== this.seatCaptures.get(intent)?.get(pool.poolId)
          : pool.sourceAdded || !pool.sourceRemoved || pool.seatAllocated || pool.effectiveAssignmentRetained === pool.seatReleased);
      })) companyUnconfirmed(); return value as CompanyBlueprintAssignmentReceipt;
    }, signal);
  }
}
