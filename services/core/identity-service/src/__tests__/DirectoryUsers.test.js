'use strict';

const { DirectoryUsers, userEtag } = require('../DirectoryUsers');
const profile = { username: 'employee', email: 'employee@test.invalid', displayName: 'Employee' };
let store;
beforeEach(() => { store = new DirectoryUsers({ isAvailable: () => false }, { demo: true }); });

test('demo must be explicit and can never replace production storage', async () => {
  await expect(new DirectoryUsers({ isAvailable: () => false }).list()).rejects.toMatchObject({ status: 503 });
  const previous = process.env.NODE_ENV; process.env.NODE_ENV = 'production';
  try { await expect(store.create(profile, 'actor')).rejects.toMatchObject({ status: 503 }); }
  finally { process.env.NODE_ENV = previous; }
});
test('creation starts disabled and does not accept credentials, IDs, roles or an enabled override', async () => {
  const user = await store.create(profile, 'actor'); expect(user.enabled).toBe(false); expect(user.revision).toBe('1');
  for (const override of [{ role: 'admin' }, { password: 'secret' }, { id: user.id }, { enabled: true }, { username: [] }, { email: null }, { department: {} }, { title: 'bad\u0000value' }]) {
    await expect(store.create({ ...profile, ...override }, 'actor')).rejects.toMatchObject({ status: 400 });
  }
  expect(store.memory.size).toBe(1);
});
test.each([undefined, '*', 'W/"version"', '"one","two"', '"user-invalid-1"'])('unsafe or missing preconditions never mutate a row: %s', async expected => {
  const user = await store.create(profile, 'actor');
  await expect(store.update(user.id, { title: 'Changed' }, expected, 'actor')).rejects.toMatchObject({ status: expected === undefined ? 428 : 400 });
  expect(await store.get(user.id)).toEqual(user);
});
test('exact record versions serialize writes and profile-only edits cannot re-enable a disabled account', async () => {
  const user = await store.create(profile, 'actor'); const tag = userEtag(user);
  const results = await Promise.allSettled([store.update(user.id, { title: 'First' }, tag, 'actor'), store.update(user.id, { title: 'Second' }, tag, 'actor')]);
  expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
  expect(results.find(result => result.status === 'rejected').reason.status).toBe(412);
  const current = await store.get(user.id); expect(current.enabled).toBe(false);
  await expect(store.remove(user.id, tag, 'actor')).rejects.toMatchObject({ status: 412 });
  await store.remove(user.id, userEtag(current), 'actor'); await expect(store.get(user.id)).rejects.toMatchObject({ status: 404 });
});
test.each([{ page: '0' }, { page: '-1' }, { limit: '101' }, { page: '1.5' }, { search: [] }, { enabled: 'yes' }, { role: 'admin' }, { page: ['1'] }])('query parsing is bounded and rejects alternate selectors: %j', async query => {
  await expect(store.list(query)).rejects.toMatchObject({ status: 400 });
});
test('a database failure never downgrades into the demo mirror after availability was advertised', async () => {
  const database = { isAvailable: () => true, transaction: async () => { throw new Error('offline'); }, write: async () => { throw new Error('offline'); } };
  const directory = new DirectoryUsers(database, { demo: true, memory: store.memory });
  await store.create(profile, 'actor'); await expect(directory.list()).rejects.toThrow('offline'); await expect(directory.create(profile, 'actor')).rejects.toThrow('offline');
});
