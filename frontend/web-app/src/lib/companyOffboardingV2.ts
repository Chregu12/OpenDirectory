import { z } from 'zod';
import { api } from './api';
import {
  CompanyWorkflowContext, CompanyWorkflowSession, CompanyWire, companyV2Context, companyUuid as uuid, companyRevision as revision,
  companyTimestamp as timestamp, companyCount as count, companyText, companySourcesSchema, companyTargetSchema,
  companyReason, companyPage, companyCheckPage, companyFreeze, companyUnconfirmed,
} from './companyAssignmentProtocol';

const base = '/api/licenses/company/v2';
const jobs = base + '/offboarding-workflows';
const phase = z.enum(['pending', 'licenses', 'paused', 'completed_local']);
const failure = z.object({ code: z.number().int().min(400).max(599), step: z.enum(['account', 'capture', 'licenses', 'verify']) }).strict();
const checkpoint = z.object({ schemaVersion: z.literal(1), workflowId: uuid, tenantId: uuid, userId: uuid, actorUserId: uuid, operationId: uuid.nullable(),
  action: z.enum(['disabled', 'already_disabled']), beforeRevision: revision, afterRevision: revision,
  beforeEligibilityRevision: revision, afterEligibilityRevision: revision, createdAt: timestamp, deliveryStatus: z.literal('pending'),
}).strict().refine(value => value.action === 'disabled' ? value.operationId !== null && BigInt(value.afterRevision) > BigInt(value.beforeRevision)
  && BigInt(value.afterEligibilityRevision) > BigInt(value.beforeEligibilityRevision) : value.operationId === null
  && value.beforeRevision === value.afterRevision && value.beforeEligibilityRevision === value.afterEligibilityRevision);
export const companyBindingSchema = z.object({ id: uuid, revision, blueprintId: uuid, version: z.number().int().min(1).max(2147483647), eligibilityRevision: revision,
  poolIds: z.array(uuid).max(25).refine(values => new Set(values).size === values.length) }).strict();
export const companyReturnAssignmentSchema = z.object({ id: uuid, poolId: uuid, poolRevision: revision, name: companyText(1, 160), vendor: companyText(1, 160),
  eligibilityRevision: revision, assignedAt: timestamp, sources: companySourcesSchema }).strict();
const summary = z.object({ id: uuid, userId: uuid, createdBy: uuid, revision, reason: companyText(10, 500), phase, totalLicenses: count.nullable(), completedLicenses: count,
  totalBindings: count.nullable(), completedBindings: count, failure: failure.nullable(), createdAt: timestamp, updatedAt: timestamp }).strict();
const detail = summary.extend({ requestedRevision: revision, checkpoint: checkpoint.nullable(), nextAssignments: z.array(companyReturnAssignmentSchema).max(10000),
  reviewAssignments: z.array(companyReturnAssignmentSchema).max(10000), nextBindings: z.array(companyBindingSchema).max(10000) }).strict();
const preview = z.object({ ...companyV2Context, user: z.object({ id: uuid, name: companyText(1, 320), userRevision: revision, eligibilityRevision: revision, enabled: z.boolean() }).strict(),
  licenseCount: count, bindingCount: count }).strict();
const job = z.object({ ...companyV2Context, workflow: detail, currentTarget: companyTargetSchema }).strict();
const event = z.object({ id: uuid, revision, phase, actorUserId: uuid, createdAt: timestamp, deliveryStatus: z.literal('pending'), failure: failure.nullable(),
  completedLicenses: count, totalLicenses: count.nullable(), completedBindings: count, totalBindings: count.nullable() }).strict();
const capabilities = z.object({ ...companyV2Context, companyOffboardingProtocol: z.literal(2), scope: z.literal('account-local-licenses-and-blueprint-bindings'), requiresFreshMfa: z.literal(true) }).strict();
export type CompanyOffboardingV2Preview = Required<z.infer<typeof preview>>;
export type CompanyOffboardingV2Summary = Required<z.infer<typeof summary>>;
export type CompanyOffboardingV2Job = CompanyWire<z.infer<typeof job>>;
export type CompanyOffboardingV2Event = Required<z.infer<typeof event>>;
export interface CompanyOffboardingV2Intent { operationId: string; workflowId: string; userId: string; etag: string | null; action: 'create' | 'continue'; body: Record<string, unknown> }
export interface CompanyOffboardingV2Page { workflows: CompanyOffboardingV2Summary[]; page: number; limit: 25; total: number }
export const companyOffboardingV2Etag = (value: { id?: string; revision?: string }) => `"company-offboarding-${uuid.parse(value.id)}-${revision.parse(value.revision)}"`;
export const companyOffboardingV2TargetChanged = (value: CompanyOffboardingV2Job) => value.workflow.checkpoint
  ? value.currentTarget.deleted || value.currentTarget.enabled || value.currentTarget.eligibilityRevision !== value.workflow.checkpoint.afterEligibilityRevision
  : value.currentTarget.deleted || value.workflow.failure?.code === 409;
function counts(value: { phase?: string; totalLicenses?: number | null; completedLicenses?: number; totalBindings?: number | null; completedBindings?: number; failure?: unknown }) {
  if ((value.totalLicenses === null ? value.completedLicenses !== 0 : value.completedLicenses > value.totalLicenses)
    || (value.totalBindings === null ? value.completedBindings !== 0 : value.completedBindings > value.totalBindings)
    || (value.totalLicenses === null) !== (value.totalBindings === null)
    || value.totalLicenses > 10000 || value.totalBindings > 10000
    || value.phase === 'pending' && value.totalLicenses !== null || value.phase === 'licenses' && value.totalLicenses === null
    || value.phase === 'completed_local' && (value.totalLicenses === null || value.completedLicenses !== value.totalLicenses || value.completedBindings !== value.totalBindings || value.failure !== null)
    || value.phase === 'paused' && !value.failure || value.phase !== 'paused' && value.failure) companyUnconfirmed();
}

export class CompanyOffboardingV2Client {
  private session: CompanyWorkflowSession<CompanyWorkflowContext>;
  private checkpoints = new WeakMap<CompanyOffboardingV2Intent, string | null>();
  constructor(expected: CompanyWorkflowContext) { this.session = new CompanyWorkflowSession(jobs + '/capabilities', capabilities, expected); }
  dispose() { this.session.dispose(); }
  invalidate() { this.session.invalidate(); }
  access(signal?: AbortSignal) { return this.session.access(signal); }
  canRetry(intent: CompanyOffboardingV2Intent) { return this.session.captured(intent); }
  private parseJob(data: unknown, id: string): CompanyOffboardingV2Job {
    const value = job.parse(data); this.session.bind(value as CompanyWorkflowContext); const workflow = value.workflow;
    counts(workflow);
    if (workflow.id !== id || workflow.userId === value.actorUserId || workflow.createdBy === workflow.userId || Date.parse(workflow.updatedAt) < Date.parse(workflow.createdAt)) companyUnconfirmed();
    if (!workflow.checkpoint && (workflow.totalLicenses !== null || workflow.completedLicenses || workflow.completedBindings || workflow.nextAssignments.length || workflow.reviewAssignments.length || workflow.nextBindings.length)
      || ['licenses', 'completed_local'].includes(workflow.phase) && !workflow.checkpoint) companyUnconfirmed();
    const proof = workflow.checkpoint;
    if (proof && (proof.workflowId !== id || proof.userId !== workflow.userId || proof.tenantId !== value.tenantId || proof.actorUserId === workflow.userId
      || proof.beforeRevision !== workflow.requestedRevision || Date.parse(proof.createdAt) < Date.parse(workflow.createdAt) || Date.parse(proof.createdAt) > Date.parse(workflow.updatedAt))) companyUnconfirmed();
    for (const rows of [workflow.nextAssignments, workflow.reviewAssignments]) {
      if (new Set(rows.map(row => row.poolId)).size !== rows.length || new Set(rows.map(row => row.id)).size !== rows.length
        || rows.length > (workflow.totalLicenses ?? 0) - workflow.completedLicenses) companyUnconfirmed();
    }
    if (new Set(workflow.nextBindings.map(binding => binding.id)).size !== workflow.nextBindings.length
      || workflow.nextBindings.length > (workflow.totalBindings ?? 0) - workflow.completedBindings
      || workflow.totalLicenses !== null && workflow.nextAssignments.length !== workflow.totalLicenses - workflow.completedLicenses
      || workflow.totalBindings !== null && workflow.nextBindings.length !== workflow.totalBindings - workflow.completedBindings
      || workflow.nextAssignments.reduce((total, row) => total + row.sources.length, 0) > 10000
      || workflow.phase === 'completed_local' && (workflow.nextAssignments.length || workflow.reviewAssignments.length || workflow.nextBindings.length)) companyUnconfirmed();
    if (workflow.reviewAssignments.length && (workflow.phase !== 'paused' || workflow.failure?.step !== 'licenses'
      || workflow.reviewAssignments.length !== workflow.nextAssignments.length || workflow.reviewAssignments.some((row, index) => {
        const captured = workflow.nextAssignments[index]; return Object.keys(captured).some(field => field === 'poolRevision'
          ? BigInt(row.poolRevision) < BigInt(captured.poolRevision) : JSON.stringify(row[field]) !== JSON.stringify(captured[field]));
      }))) companyUnconfirmed();
    return companyFreeze(value) as CompanyOffboardingV2Job;
  }
  async preview(userId: string, signal?: AbortSignal): Promise<CompanyOffboardingV2Preview> {
    uuid.parse(userId);
    return this.session.run(async (requestSignal, check) => {
      const context = this.session.require(); if (userId === context.actorUserId) companyUnconfirmed();
      const response = await api.get(base + '/users/' + userId + '/offboarding-preview', { signal: requestSignal }); check();
      if (response.status !== 200) companyUnconfirmed(); const value = preview.parse(response.data); this.session.bind(value as CompanyWorkflowContext);
      if (value.user.id !== userId) companyUnconfirmed(); await this.session.fresh(requestSignal, check); return this.session.own(value) as CompanyOffboardingV2Preview;
    }, signal);
  }
  async list(page = 1, signal?: AbortSignal): Promise<CompanyOffboardingV2Page> {
    companyPage(page);
    return this.session.run(async (requestSignal, check) => {
      this.session.require(); const response = await api.get(jobs, { params: { page, limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) companyUnconfirmed();
      const value = z.object({ ...companyV2Context, workflows: z.array(summary).max(25), total: count, page: z.literal(page), limit: z.literal(25) }).strict().parse(response.data);
      this.session.bind(value as CompanyWorkflowContext); companyCheckPage(value.workflows, value.total, page, value.workflows.map(row => row.id));
      value.workflows.forEach(counts); await this.session.fresh(requestSignal, check); return companyFreeze(value) as CompanyOffboardingV2Page;
    }, signal);
  }
  async get(id: string, signal?: AbortSignal): Promise<CompanyOffboardingV2Job> {
    uuid.parse(id);
    return this.session.run(async (requestSignal, check) => {
      this.session.require(); const response = await api.get(jobs + '/' + id, { signal: requestSignal }); check();
      if (response.status !== 200) companyUnconfirmed(); const value = this.parseJob(response.data, id);
      if (response.headers?.etag !== companyOffboardingV2Etag(value.workflow)) companyUnconfirmed();
      await this.session.fresh(requestSignal, check); return this.session.own(value);
    }, signal);
  }
  async history(id: string, page = 1, signal?: AbortSignal) {
    uuid.parse(id); companyPage(page);
    return this.session.run(async (requestSignal, check) => {
      this.session.require(); const response = await api.get(jobs + '/' + id + '/history', { params: { page, limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) companyUnconfirmed();
      const value = z.object({ ...companyV2Context, workflowId: z.literal(id), events: z.array(event).max(25), total: count, page: z.literal(page), limit: z.literal(25) }).strict().parse(response.data);
      this.session.bind(value as CompanyWorkflowContext); companyCheckPage(value.events, value.total, page, value.events.map(row => row.id)); value.events.forEach(counts);
      await this.session.fresh(requestSignal, check); return companyFreeze(value);
    }, signal);
  }
  captureCreate(value: CompanyOffboardingV2Preview, reason: string): CompanyOffboardingV2Intent {
    if (!this.session.captured(value)) return companyUnconfirmed();
    const workflowId = uuid.parse(crypto.randomUUID());
    return this.session.own({ operationId: workflowId, workflowId, userId: value.user.id, etag: null, action: 'create', body: {
      workflowId, userId: value.user.id, userRevision: value.user.userRevision, eligibilityRevision: value.user.eligibilityRevision, reason: companyReason(reason), confirm: true,
    } });
  }
  captureContinue(value: CompanyOffboardingV2Job, refreshed?: CompanyOffboardingV2Preview): CompanyOffboardingV2Intent {
    if (!this.session.captured(value) || companyOffboardingV2TargetChanged(value) || value.workflow.phase === 'completed_local') return companyUnconfirmed();
    const workflow = value.workflow;
    const requiresPreview = !workflow.checkpoint && workflow.failure?.code === 412 && workflow.failure.step === 'account';
    if (requiresPreview && (!refreshed || !this.session.captured(refreshed) || refreshed.user.id !== workflow.userId
      || refreshed.user.eligibilityRevision !== value.currentTarget.eligibilityRevision || refreshed.user.enabled !== value.currentTarget.enabled)
      || !requiresPreview && refreshed) return companyUnconfirmed();
    const rows = workflow.phase === 'paused' ? workflow.reviewAssignments : workflow.nextAssignments;
    if (workflow.phase === 'paused' && workflow.nextAssignments.length && rows.length !== workflow.nextAssignments.length) return companyUnconfirmed();
    const intent: CompanyOffboardingV2Intent = { operationId: uuid.parse(crypto.randomUUID()), workflowId: workflow.id, userId: workflow.userId, etag: companyOffboardingV2Etag(workflow), action: 'continue', body: {
      confirm: true, reason: workflow.reason, userRevision: refreshed?.user.userRevision || workflow.requestedRevision,
      assignments: rows.map(row => ({ poolId: row.poolId, poolRevision: row.poolRevision, assignmentId: row.id, sources: row.sources })),
      bindings: workflow.nextBindings.map(binding => ({ id: binding.id, revision: binding.revision })),
    } };
    this.checkpoints.set(intent, workflow.checkpoint ? JSON.stringify(workflow.checkpoint) : null); return this.session.own(intent);
  }
  write(intent: CompanyOffboardingV2Intent, signal?: AbortSignal): Promise<CompanyOffboardingV2Job> {
    return this.session.write(intent, async (requestSignal, check) => {
      const response = await api.post(jobs + (intent.action === 'continue' ? '/' + intent.workflowId + '/continue' : ''), intent.body,
        { headers: { 'Idempotency-Key': intent.operationId, ...(intent.etag ? { 'If-Match': intent.etag } : {}) }, signal: requestSignal }); check();
      if (![200, ...(intent.action === 'create' ? [201] : [])].includes(response.status)) companyUnconfirmed();
      const value = this.parseJob(response.data, intent.workflowId);
      if (value.workflow.userId !== intent.userId || value.workflow.reason !== intent.body.reason
        || intent.action === 'create' && value.workflow.createdBy !== this.session.require().actorUserId
        || this.checkpoints.get(intent) && JSON.stringify(value.workflow.checkpoint) !== this.checkpoints.get(intent)) companyUnconfirmed(); return value;
    }, signal);
  }
}
