import { api } from '@/lib/api';
import { directoryUsers } from '@/lib/directoryUsers';
import { directoryOus, parseOus, ouEtag } from '@/lib/directoryOus';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
jest.mock('@/lib/directoryUsers', () => ({ ...jest.requireActual('@/lib/directoryUsers'), directoryUsers: { access: jest.fn() } }));
const root = { id: '11111111-1111-4111-8111-111111111111', name: 'Engineering', createdAt: '2026-10-19T00:00:00Z' };
const child = { ...root, id: '22222222-2222-4222-8222-222222222222', name: 'Platform', parentId: root.id };
const access = { userId: root.id, permissions: ['ous.read', 'ous.create'], demoMode: false, directoryReadProtocol: 1, directoryCreationProtocol: 1 };
beforeEach(() => { jest.clearAllMocks(); (directoryUsers.access as jest.Mock).mockResolvedValue(access); });
test('only the actual complete own-directory response becomes a hierarchy', async () => {
  (api.get as jest.Mock).mockResolvedValue({ data: { ous: [root, child], total: 2 } }); expect(await directoryOus.list()).toMatchObject([root, child]); expect(api.get).toHaveBeenCalledWith('/api/ous', { signal: undefined });
});
test.each([{ ous: [root, root], total: 2 }, { ous: [child], total: 1 }, { ous: [{ ...root, parentId: child.id }, child], total: 2 }, { ous: [root], total: 2 }])('duplicate, incomplete or cyclic data is not silently displayed: %j', data => { expect(() => parseOus(data)).toThrow(); });
test('a confirmed creation binds the exact parent and profile without sending tenant selectors', async () => {
  (api.post as jest.Mock).mockResolvedValue({ data: child }); const profile = { name: child.name, parentId: root.id, description: null };
  expect(await directoryOus.create(profile)).toMatchObject(child); expect(api.post).toHaveBeenCalledWith('/api/ous', profile);
  (api.post as jest.Mock).mockResolvedValue({ data: root }); await expect(directoryOus.create(profile)).rejects.toThrow('nicht bestätigt');
});
test.each([{ demoMode: true }, { directoryReadProtocol: undefined }, { userId: null }, { permissions: [] }])('unsupported or unauthorized directories never become demo reads: %j', async change => {
  (directoryUsers.access as jest.Mock).mockResolvedValue({ ...access, ...change }); await expect(directoryOus.list()).rejects.toThrow(); expect(api.get).not.toHaveBeenCalled();
});
test('a read-only or down-level service cannot create a unit', async () => {
  for (const change of [{ directoryCreationProtocol: undefined }, { permissions: ['ous.read'] }]) {
    (directoryUsers.access as jest.Mock).mockResolvedValue({ ...access, ...change }); await expect(directoryOus.create({ name: 'No write', description: null, parentId: null })).rejects.toThrow();
  }
  expect(api.post).not.toHaveBeenCalled();
});
const versioned = { ...root, revision: '9007199254740993' }; const mutable = { ...access, directoryOuMutationProtocol: 1, permissions: [...access.permissions, 'ous.update', 'ous.delete'] };
test('OU updates bind the exact BIGINT version and verify the complete returned profile', async () => {
  (directoryUsers.access as jest.Mock).mockResolvedValue(mutable); (api.put as jest.Mock).mockResolvedValue({ data: { ...versioned, name: 'Renamed', revision: '9007199254740994' } });
  expect((await directoryOus.update(versioned, { name: 'Renamed' })).name).toBe('Renamed'); expect(api.put).toHaveBeenCalledWith('/api/ous/' + root.id, { name: 'Renamed' }, { headers: { 'If-Match': ouEtag(versioned) } });
});
test.each([{ revision: versioned.revision }, { revision: '9007199254740994', id: child.id }, { revision: '9007199254740994', parentId: child.id }])('stale or unrelated OU responses cannot confirm an update: %j', async changed => {
  (directoryUsers.access as jest.Mock).mockResolvedValue(mutable); (api.put as jest.Mock).mockResolvedValue({ data: { ...versioned, ...changed } }); await expect(directoryOus.update(versioned, { description: null })).rejects.toThrow('nicht bestätigt');
});
test('only an actual 204 confirms exact-version OU deletion', async () => {
  (directoryUsers.access as jest.Mock).mockResolvedValue(mutable); (api.delete as jest.Mock).mockResolvedValue({ status: 202 }); await expect(directoryOus.remove(versioned)).rejects.toThrow('nicht bestätigt');
  (api.delete as jest.Mock).mockResolvedValue({ status: 204 }); await directoryOus.remove(versioned); expect(api.delete).toHaveBeenCalledWith('/api/ous/' + root.id, { headers: { 'If-Match': ouEtag(versioned) } });
});
test('old servers, missing permissions or missing record versions cannot reach legacy OU writes', async () => {
  for (const changed of [{ directoryOuMutationProtocol: undefined }, { permissions: ['ous.read'] }]) {
    (directoryUsers.access as jest.Mock).mockResolvedValue({ ...mutable, ...changed }); await expect(directoryOus.update(versioned, { name: 'No legacy call' })).rejects.toThrow(); await expect(directoryOus.remove(versioned)).rejects.toThrow();
  }
  await expect(directoryOus.update(root, { name: 'No version' })).rejects.toThrow(); expect(api.put).not.toHaveBeenCalled(); expect(api.delete).not.toHaveBeenCalled();
});
