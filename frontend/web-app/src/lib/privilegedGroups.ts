import { z } from 'zod';
import { api } from './api';
import { privilegedActivation, parsePimEligibility, PIMSelf, PIMCatalogRole, ActivationRequest } from './privilegedActivation';

const id = z.string().uuid(); const role = z.string().regex(/^[a-z][a-z-]{0,63}$/); const date = z.string().refine(value => Number.isFinite(Date.parse(value)));
const seconds = z.number().int().min(60).max(36000); const count = z.number().int().nonnegative();
const groupSchema = z.object({ id, name: z.string().min(2).max(80), description: z.string().max(500), role, maxDurationSeconds: seconds,
  configuredMaxDurationSeconds: seconds, enabled: z.boolean(), protected: z.boolean(), createdAt: date, canManage: z.boolean() }).strict()
  .refine(value => value.maxDurationSeconds <= value.configuredMaxDurationSeconds);
const catalogSchema = z.object({ schemaVersion: z.literal(1), userId: id, groups: z.array(groupSchema).max(100),
  bindings: z.array(z.object({ groupId: id, eligibilityId: id, userId: id }).strict()).max(1000), standingRoles: z.array(role).max(100), canCreate: z.boolean(), canReview: z.boolean(), truncated: z.boolean() }).strict();
export type PIMGroup = z.infer<typeof groupSchema>;
export type PIMGroupCatalog = z.infer<typeof catalogSchema>;
export interface PIMGroupState extends PIMGroupCatalog { self: PIMSelf; roles: PIMCatalogRole[]; queue: ActivationRequest[] }
const memberSchema = z.object({ eligibilityId: id, userId: id, name: z.string().max(255), maxDurationSeconds: seconds, expiresAt: date, revoked: z.boolean() }).strict();
const historySchema = z.object({ id, userId: id.nullable(), actorUserId: id.nullable(), role,
  action: z.enum(['group_created', 'group_disabled', 'eligibility_created', 'eligibility_revoked', 'pending', 'approved', 'denied', 'cancelled', 'active', 'revoked']),
  reason: z.string().min(1).max(500), createdAt: date, durationSeconds: seconds.nullable(), expiresAt: date.nullable() }).strict();
export type PIMGroupMember = z.infer<typeof memberSchema>;
export type PIMGroupEvent = z.infer<typeof historySchema>;
const base = '/api/identity/pim/groups';
function unconfirmed(): never { throw new Error('PIM-Ergebnis nicht bestätigt. Zuerst neu laden; keine automatische Wiederholung.'); }
export const privilegedGroups = {
  async load(signal?: AbortSignal): Promise<PIMGroupState> {
    const [{ data }, self, roles] = await Promise.all([api.get(base, { signal }), privilegedActivation.self(signal), privilegedActivation.catalog(signal)]);
    const result = catalogSchema.parse(data);
    if (result.userId !== self.userId || new Set(result.groups.map(group => group.id)).size !== result.groups.length
      || new Set(result.bindings.map(binding => binding.eligibilityId)).size !== result.bindings.length) unconfirmed();
    for (const binding of result.bindings.filter(binding => binding.userId === self.userId)) {
      const eligibility = self.eligibilities.find(item => item.id === binding.eligibilityId); const group = result.groups.find(item => item.id === binding.groupId);
      if (eligibility && group && eligibility.role !== group.role) unconfirmed();
    }
    const queue = result.canReview ? await privilegedActivation.queue(signal) : [];
    return { ...result, self, roles, queue };
  },
  async create(input: { name: string; description: string; role: string; maxDurationSeconds: number; reason: string; confirm: true }): Promise<PIMGroup> {
    const response = await api.post(base, input); const result = groupSchema.parse(response.data);
    if (response.status !== 201 || !result.enabled || result.name !== input.name || result.role !== input.role || result.configuredMaxDurationSeconds !== input.maxDurationSeconds) unconfirmed(); return result;
  },
  async initialize() {
    const response = await api.post(base + '/initialize', { confirm: true });
    if (response.status !== 200 || !response.data || Object.keys(response.data).length !== 2 || response.data.schemaVersion !== 1 || response.data.initialized !== true) unconfirmed();
  },
  async assign(groupId: string, input: { userId: string; maxDurationSeconds: number; validForSeconds: number; reason: string; confirm: true }) {
    id.parse(groupId); id.parse(input.userId); const response = await api.post(base + '/' + groupId + '/eligibilities', input);
    const data = response.data; const created = parsePimEligibility(data?.eligibility);
    if (response.status !== 201 || !data || Object.keys(data).length !== 3 || data.schemaVersion !== 1 || data.groupId !== groupId
      || created.userId !== input.userId || created.status !== 'eligible'
      || created.maxDurationSeconds !== input.maxDurationSeconds || created.reason !== input.reason.trim()
      || Math.abs((Date.parse(created.expiresAt) - Date.parse(created.createdAt)) / 1000 - input.validForSeconds) > 5) unconfirmed();
  },
  async disable(groupId: string, reason: string) {
    id.parse(groupId); const response = await api.post(base + '/' + groupId + '/disable', { reason, confirm: true });
    if (response.status !== 200 || Object.keys(response.data || {}).length !== 2 || response.data.id !== groupId || response.data.disabled !== true) unconfirmed();
  },
  async members(groupId: string, page = 1, signal?: AbortSignal) {
    id.parse(groupId); const { data } = await api.get(base + '/' + groupId + '/members', { params: { page }, signal });
    return z.object({ schemaVersion: z.literal(1), groupId: z.literal(groupId), page: z.literal(page), limit: z.literal(25), total: count, members: z.array(memberSchema).max(25) }).strict().parse(data);
  },
  async history(groupId: string, page = 1, signal?: AbortSignal) {
    id.parse(groupId); const { data } = await api.get(base + '/' + groupId + '/history', { params: { page }, signal });
    return z.object({ schemaVersion: z.literal(1), groupId: z.literal(groupId), page: z.literal(page), limit: z.literal(25), total: count, events: z.array(historySchema).max(25) }).strict().parse(data);
  },
};
