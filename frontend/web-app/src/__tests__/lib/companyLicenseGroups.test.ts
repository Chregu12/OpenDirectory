import { api } from '@/lib/api';
import { companyLicenseGroups } from '@/lib/companyLicenseGroups';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
const id = (n: number) => '00000000-0000-4000-8000-' + String(n).padStart(12, '0');
const context = { schemaVersion: 1, companyLicenseGroupsProtocol: 1, actorUserId: id(1), tenantId: id(2), allocationMode: 'local-only' };
const reason = 'Geprüfte Lizenzgruppenänderung';
let rule: any; let mode: string;
const base = '/api/licenses/company/groups';
beforeEach(() => {
  jest.resetAllMocks(); mode = '';
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: () => id(99) });
  rule = { id: id(3), tenantId: id(2), groupId: id(4), poolId: id(5), blueprintId: id(6), status: 'active', revision: '1', createdAt: '2026-10-22T10:00:00.000Z', updatedAt: '2026-10-22T10:00:00.000Z' };
  (api.get as jest.Mock).mockImplementation(async (url: string) => ({ status: 200, data: url.endsWith('/preview') ? { ...context, rule, groupRevision: rule.status === 'active' ? '1' : null,
    groupName: 'Engineering', eligibleMembers: 1, assignedMembers: 0, pendingMembers: 1, removalMembers: 0 } : { ...context, rules: [rule], truncated: false } }));
  (api.post as jest.Mock).mockImplementation(async (url: string, body: any) => {
    if (url.endsWith('/unlink')) { rule = { ...rule, status: 'unlinked', revision: '2' }; return { status: 200, data: { ...context, rule } }; }
    if (url.endsWith('/sync')) {
      const row = { userId: id(body.cursor ? 8 : 7), status: mode === 'blocked' ? 'blocked' : 'assigned', code: mode === 'blocked' ? 409 : null };
      return { status: 200, data: { ...context, actorUserId: mode === 'foreign' ? id(50) : id(1), rule, groupRevision: body.groupRevision,
        results: [row], hasBlocked: mode === 'blocked', nextCursor: mode === 'pages' && !body.cursor ? row.userId : mode === 'cursor' ? id(9) : null } };
    }
    return { status: 201, data: { ...context, rule } };
  });
});
test('ordinary group reads have no allocation side effect', async () => { expect((await companyLicenseGroups.list(id(4), id(1))).rules).toHaveLength(1); expect(api.post).not.toHaveBeenCalled(); });
test('links a pool with explicit confirmation, reason and operation UUID', async () => {
  expect((await companyLicenseGroups.link(id(4), id(5), reason, context)).poolId).toBe(id(5));
  expect(api.post).toHaveBeenCalledWith(base, { groupId: id(4), poolId: id(5), reason, confirm: true }, { headers: { 'Idempotency-Key': id(99) } });
});
test('unlink uses exact linkage ETag and preserves identifiers', async () => {
  const result = await companyLicenseGroups.unlink(rule, reason, context); expect(result.status).toBe('unlinked');
  expect((api.post as jest.Mock).mock.calls[0][2].headers['If-Match']).toBe('"company-license-group-' + id(3) + '-1"');
});
test('sync pins one group revision across cursor pages and reports shortages', async () => {
  mode = 'pages'; expect(await companyLicenseGroups.sync(rule, reason, context)).toHaveLength(2);
  expect((api.post as jest.Mock).mock.calls.map(call => call[1].cursor)).toEqual([null, id(7)]);
  mode = 'blocked'; expect((await companyLicenseGroups.sync(rule, reason, context))[0]).toMatchObject({ status: 'blocked', code: 409 });
});
test.each(['foreign', 'cursor'])('does not confirm %s result or automatically repeat writes', async value => {
  mode = value; await expect(companyLicenseGroups.sync(rule, reason, context)).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});
test('rejects another tenant before linking and stops after session invalidation', async () => {
  await expect(companyLicenseGroups.link(id(4), id(5), reason, { ...context, tenantId: id(88) })).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
  await expect(companyLicenseGroups.sync(rule, reason, context, () => false)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
