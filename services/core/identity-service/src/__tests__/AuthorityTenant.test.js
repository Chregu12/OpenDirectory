'use strict';

const { authorityTenant, lockAuthorityUsers, requireAuthorityReceiver } = require('../AuthorityTenant');
const tenant = '11111111-1111-4111-8111-111111111111';
const first = '22222222-2222-4222-8222-222222222222';
const second = '33333333-3333-4333-8333-333333333333';
const required = ['identity_role_assignments', 'identity_pim_eligibilities', 'identity_pim_requests', 'identity_role_review_leases'];
test('tenant discovery is derived from the current canonical proof, with a held enabled tenant only for writes', async () => {
  const client = { query: jest.fn(async sql => ({ rows: [sql.includes('actor_home') ? { tenant_id: tenant } : { id: tenant }] })) }; const proof = { issuer: 'https://issuer.test', subject: 'subject', userId: first };
  expect(await authorityTenant(client, proof)).toBe(tenant); expect(client.query).toHaveBeenCalledTimes(1);
  expect(client.query).toHaveBeenCalledWith(expect.stringContaining('identity_authority_actor_home($1::jsonb)'), [JSON.stringify(proof)]);
  expect(await authorityTenant(client, proof, { write: true })).toBe(tenant); expect(client.query).toHaveBeenLastCalledWith(expect.stringContaining('enabled FOR SHARE'), [tenant]);
});
test.each([undefined, null, 'foreign', 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA', 42])('invalid tenant confirmation has no default-owner fallback: %j', async tenantId => {
  await expect(authorityTenant({ query: async () => ({ rows: [{ tenant_id: tenantId }] }) }, {})).rejects.toMatchObject({ status: 503 });
});
test('canonical actor withdrawal and tenant loss fail closed instead of being treated as an empty tenant', async () => {
  await expect(authorityTenant({ query: async () => { throw Object.assign(new Error('withdrawn'), { code: '42501' }); } }, {})).rejects.toMatchObject({ status: 401 });
  const client = { query: jest.fn().mockResolvedValueOnce({ rows: [{ tenant_id: tenant }] }).mockResolvedValueOnce({ rows: [] }) };
  await expect(authorityTenant(client, {}, { write: true })).rejects.toMatchObject({ status: 401 });
});
test('owned-user locks are unique, sorted and tenant-filtered in SQL, before any target row is locked', async () => {
  const rows = [{ id: first }, { id: second }]; const client = { query: jest.fn(async () => ({ rows })) };
  expect(await lockAuthorityUsers(client, [second, first, second, undefined], tenant)).toEqual(rows);
  expect(client.query).toHaveBeenCalledWith(expect.stringContaining("identity_tenant_id('user',id)=$2 ORDER BY id FOR UPDATE"), [[first, second], tenant]);
});
test.each([[], [{ id: first }], [{ id: first }, { id: tenant }]].map(rows => [rows]))('a foreign/missing canonical recipient cannot produce a partial admitted target: %j', async rows => {
  await expect(lockAuthorityUsers({ query: async () => ({ rows }) }, [first, second], tenant)).rejects.toMatchObject({ status: 404 });
});
test('all four exact receiving triggers must be present before any role/PIM mutation', async () => {
  const client = { query: jest.fn(async () => ({ rows: required.map(relname => ({ relname })) })) }; await requireAuthorityReceiver(client);
  expect(client.query).toHaveBeenCalledWith(expect.stringContaining("guard.tgfoid='identity_authority_target_tenant_guard()'::regprocedure"), [required]);
  for (const rows of [[], required.slice(1).map(relname => ({ relname })), required.map(() => ({ relname: required[0] })), [...required.slice(1), 'foreign_table'].map(relname => ({ relname }))])
    await expect(requireAuthorityReceiver({ query: async () => ({ rows }) })).rejects.toMatchObject({ status: 503 });
});
