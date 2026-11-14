import { z } from 'zod';
import { api } from './api';
import { directoryUsers } from './directoryUsers';

const uuid = z.string().regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
const revision = z.string().regex(/^[1-9][0-9]{0,18}$/).refine(value => BigInt(value) <= BigInt('9223372036854775807'));
const timestamp = z.string().refine(value => Number.isFinite(Date.parse(value)));
const group = z.object({ id: uuid, name: z.string().min(1), description: z.string(), createdAt: timestamp, revision,
  membership: z.object({ id: uuid, createdAt: timestamp, effective: z.boolean(), source: z.enum(['manual', 'rule']) }).strict().nullable(),
}).strict();
const pageSchema = z.object({ schemaVersion: z.literal(1), actorUserId: uuid, userId: uuid, membership: z.enum(['member', 'available']),
  groups: z.array(group).max(25), total: z.number().int().nonnegative().safe(), page: z.number().int().positive(), limit: z.literal(25),
}).strict();
export type UserGroup = z.infer<typeof group>;
export type UserGroupPage = z.infer<typeof pageSchema>;

export async function listUserGroups(userId: string, page = 1, search = '', membership: 'member' | 'available' = 'member', signal?: AbortSignal): Promise<UserGroupPage> {
  uuid.parse(userId); z.number().int().min(1).max(1000000).parse(page); z.string().max(255).regex(/^[^\u0000-\u001f\u007f-\u009f]*$/).parse(search); z.enum(['member', 'available']).parse(membership);
  const access = await directoryUsers.access();
  if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
  if (access.directoryUserGroupsProtocol !== 1 || access.demoMode || !access.userId || !['users.read', 'groups.read'].every(permission => access.permissions.includes(permission))) throw new Error('Benutzerbezogene Gruppenverwaltung nicht bestätigt.');
  const response = await api.get(`/api/users/${userId}/groups`, { params: { page, limit: 25, membership, ...(search.trim() ? { search: search.trim() } : {}) }, signal });
  const result = pageSchema.parse(response.data);
  if (response.status !== 200 || result.userId !== userId || result.actorUserId !== access.userId || result.page !== page || result.membership !== membership
    || result.groups.length !== Math.min(25, Math.max(0, result.total - (page - 1) * 25)) || new Set(result.groups.map(item => item.id)).size !== result.groups.length
    || result.groups.some(item => (item.membership !== null) !== (membership === 'member'))) throw new Error('Gruppenmitgliedschaften nicht bestätigt. Bitte neu laden.');
  return result;
}
