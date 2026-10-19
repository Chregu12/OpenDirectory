import { z } from 'zod';
import { api } from './api';
import { CompanyPool, companyPoolEtag } from './companyApplications';
import { directoryUsers, UserPage } from './directoryUsers';
import { companyBindingSchema, companyReturnAssignmentSchema } from './companyOffboardingV2';
import {
  CompanyWorkflowContext, CompanyWorkflowSession, CompanyWire, companyUuid as uuid, companyRevision as revision, companyTimestamp as timestamp,
  companyCount as count, companyV2Context, companyText, companySourcesSchema, companyTargetSchema, companyReason,
  companyCheckPage, companyPage, companyFreeze, companyUnconfirmed,
} from './companyAssignmentProtocol';

const base = '/api/licenses/company/v2';
const capabilities = z.object({ ...companyV2Context, permissions: z.tuple([z.literal('company.apps.read'), z.literal('company.apps.create'), z.literal('company.apps.assign')]),
  allocationMode: z.literal('local-only'), supportedTargets: z.tuple([z.literal('user')]) }).strict();
export const companyAssignmentV2Schema = z.object({ id: uuid, userId: uuid, assignedAt: timestamp, assignedBy: uuid, eligibilityRevision: revision, sources: companySourcesSchema }).strict();
const target = z.object({ id: uuid, revision: revision.nullable(), eligibilityRevision: revision, enabled: z.boolean(), deleted: z.boolean() }).strict()
  .refine(value => value.deleted ? !value.enabled && value.revision === null : value.revision !== null);
const previewSchema = z.object({ ...companyV2Context, poolId: uuid, poolRevision: revision, target, assignment: companyAssignmentV2Schema.nullable() }).strict();
const receiptSchema = z.object({ ...companyV2Context, operationId: uuid, outcome: z.enum(['applied', 'already_applied']), action: z.enum(['manual_assign', 'manual_revoke']),
  poolId: uuid, userId: uuid, assignmentId: uuid.nullable(), sourceAdded: z.boolean(), sourceRemoved: z.boolean(), seatAllocated: z.boolean(), seatReleased: z.boolean(),
  effectiveAssignmentRetained: z.boolean(), eventId: uuid, poolRevision: revision, deliveryStatus: z.literal('pending') }).strict();
const returnsSchema = z.object({ ...companyV2Context, userId: uuid, target: companyTargetSchema, assignments: z.array(companyReturnAssignmentSchema).max(25),
  bindings: z.array(companyBindingSchema).max(10000), totalBindings: count, workflowRequired: z.boolean(), total: count, page: count, limit: z.literal(25) }).strict();
export type CompanyAssignmentV2 = CompanyWire<z.infer<typeof companyAssignmentV2Schema>>;
export type CompanyAssignmentV2Preview = CompanyWire<z.infer<typeof previewSchema>>;
export type CompanyAssignmentV2Receipt = Required<z.infer<typeof receiptSchema>>;
export type CompanyLicenseReturnsV2Preview = Required<z.infer<typeof returnsSchema>>;
export interface CompanyAssignmentsV2Page { poolId: string; poolRevision: string; assignments: CompanyAssignmentV2[]; total: number; page: number; limit: 25 }
export interface CompanyAssignmentV2Intent { operationId: string; poolId: string; userId: string; action: 'manual_assign' | 'manual_revoke'; etag: string; poolRevision: string; body: Record<string, unknown> }

export class CompanyApplicationsV2Client {
  private session: CompanyWorkflowSession<CompanyWorkflowContext>;
  constructor(expected: CompanyWorkflowContext) { this.session = new CompanyWorkflowSession(base + '/capabilities', capabilities, expected); }
  access(signal?: AbortSignal) { return this.session.access(signal); }
  invalidate() { this.session.invalidate(); }
  dispose() { this.session.dispose(); }
  canRetry(intent: CompanyAssignmentV2Intent) { return this.session.captured(intent); }
  async assignments(poolId: string, page = 1, signal?: AbortSignal): Promise<CompanyAssignmentsV2Page> {
    uuid.parse(poolId); companyPage(page);
    return this.session.run(async (requestSignal, check) => {
      this.session.require(); const response = await api.get(base + '/pools/' + poolId + '/assignments', { params: { page, limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) companyUnconfirmed();
      const value = z.object({ ...companyV2Context, poolId: z.literal(poolId), poolRevision: revision, assignments: z.array(companyAssignmentV2Schema).max(25),
        total: count, page: z.literal(page), limit: z.literal(25) }).strict().parse(response.data); this.session.bind(value as CompanyWorkflowContext);
      companyCheckPage(value.assignments, value.total, page, value.assignments.map(row => row.id));
      if (new Set(value.assignments.map(row => row.userId)).size !== value.assignments.length) companyUnconfirmed();
      await this.session.fresh(requestSignal, check); return companyFreeze(value) as CompanyAssignmentsV2Page;
    }, signal);
  }
  async users(page = 1, search = '', signal?: AbortSignal): Promise<UserPage | null> {
    companyPage(page); companyText(0, 100).parse(search.trim());
    return this.session.run(async (requestSignal, check) => {
      const context = this.session.require(); const access = await directoryUsers.access(); check();
      if (access.userId !== context.actorUserId || access.demoMode) companyUnconfirmed(true);
      if (!access.permissions.includes('users.read')) { await this.session.fresh(requestSignal, check); return null; }
      if (access.directoryReadProtocol !== 1) companyUnconfirmed();
      const value = await directoryUsers.list(page, search.trim(), 'true', requestSignal); check();
      companyCheckPage(value.users, value.total, page, value.users.map(user => user.id));
      if (value.users.some(user => !user.enabled || !uuid.safeParse(user.id).success)) companyUnconfirmed();
      const current = await directoryUsers.access(); check();
      if (current.userId !== context.actorUserId || current.demoMode || current.directoryReadProtocol !== 1 || !current.permissions.includes('users.read')) companyUnconfirmed(true);
      await this.session.fresh(requestSignal, check); return companyFreeze(value);
    }, signal);
  }
  async preview(poolId: string, userId: string, signal?: AbortSignal): Promise<CompanyAssignmentV2Preview> {
    uuid.parse(poolId); uuid.parse(userId);
    return this.session.run(async (requestSignal, check) => {
      this.session.require(); const response = await api.post(base + '/pools/' + poolId + '/assignment-preview', { userId }, { signal: requestSignal }); check();
      if (response.status !== 200) companyUnconfirmed(); const value = previewSchema.parse(response.data); this.session.bind(value as CompanyWorkflowContext);
      if (value.poolId !== poolId || value.target.id !== userId || value.assignment && (value.assignment.userId !== userId
        || value.target.enabled && value.assignment.eligibilityRevision !== value.target.eligibilityRevision)) companyUnconfirmed();
      await this.session.fresh(requestSignal, check); return this.session.own(value) as CompanyAssignmentV2Preview;
    }, signal);
  }
  capture(action: 'manual_assign' | 'manual_revoke', value: CompanyAssignmentV2Preview, reason: string): CompanyAssignmentV2Intent {
    if (!this.session.captured(value)) return companyUnconfirmed();
    const hasManual = value.assignment?.sources.some(source => source.sourceType === 'direct');
    if (action === 'manual_assign' ? !value.target.enabled || value.target.deleted || hasManual : !hasManual) return companyUnconfirmed();
    const body = { userId: value.target.id, eligibilityRevision: value.target.eligibilityRevision, sources: value.assignment?.sources || [], reason: companyReason(reason), confirm: true,
      ...(action === 'manual_assign' ? { assignmentId: value.assignment?.id || null } : {}) };
    const intent = { operationId: uuid.parse(crypto.randomUUID()), poolId: value.poolId, userId: value.target.id, action,
      etag: companyPoolEtag({ id: value.poolId, revision: value.poolRevision } as CompanyPool), poolRevision: value.poolRevision, body };
    this.projections.set(intent, value.assignment?.id || null); return this.session.own(intent);
  }
  private projections = new WeakMap<CompanyAssignmentV2Intent, string | null>();
  write(intent: CompanyAssignmentV2Intent, signal?: AbortSignal): Promise<CompanyAssignmentV2Receipt> {
    return this.session.write(intent, async (requestSignal, check) => {
      const projection = this.projections.get(intent);
      const response = await api.post(base + '/pools/' + intent.poolId + '/assignments' + (intent.action === 'manual_revoke' ? '/' + projection + '/revoke' : ''), intent.body,
        { headers: { 'Idempotency-Key': intent.operationId, 'If-Match': intent.etag }, signal: requestSignal }); check();
      const value = receiptSchema.parse(response.data); this.session.bind(value as CompanyWorkflowContext);
      if (response.status !== (intent.action === 'manual_assign' && value.outcome === 'applied' ? 201 : 200) || value.operationId !== intent.operationId
        || value.action !== intent.action || value.poolId !== intent.poolId || value.userId !== intent.userId || BigInt(value.poolRevision) !== BigInt(intent.poolRevision) + BigInt(1)) companyUnconfirmed();
      const sources = intent.body.sources as unknown[];
      if (intent.action === 'manual_assign' ? !value.sourceAdded || value.sourceRemoved || value.seatReleased || !value.assignmentId
        || value.seatAllocated !== !projection || projection && value.assignmentId !== projection
        : value.sourceAdded || !value.sourceRemoved || value.seatAllocated || value.seatReleased !== (sources.length === 1)
        || value.effectiveAssignmentRetained !== (sources.length > 1) || value.assignmentId !== (sources.length > 1 ? projection : null)) companyUnconfirmed();
      return value as CompanyAssignmentV2Receipt;
    }, signal);
  }
  async returnPreview(userId: string, page = 1, signal?: AbortSignal): Promise<CompanyLicenseReturnsV2Preview> {
    uuid.parse(userId); companyPage(page);
    return this.session.run(async (requestSignal, check) => {
      this.session.require(); const response = await api.get(base + '/users/' + userId + '/license-returns', { params: { page, limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) companyUnconfirmed(); const value = returnsSchema.parse(response.data); this.session.bind(value as CompanyWorkflowContext);
      if (value.userId !== userId || value.page !== page || value.totalBindings !== value.bindings.length || value.workflowRequired !== (value.totalBindings > 0)
        || new Set(value.bindings.map(binding => binding.id)).size !== value.bindings.length) companyUnconfirmed();
      companyCheckPage(value.assignments, value.total, page, value.assignments.map(row => row.id));
      if (new Set(value.assignments.map(row => row.poolId)).size !== value.assignments.length) companyUnconfirmed();
      await this.session.fresh(requestSignal, check); return this.session.own(value) as CompanyLicenseReturnsV2Preview;
    }, signal);
  }
}
