'use strict';

const { randomUUID } = require('node:crypto');
const { validUuid, validRevision, validContext, sameContext } = require('../../../../packages/identity-authorization-contract');
const { sameTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { createTenantStateClient } = require('../../../../packages/oidc-tenant-state');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { AuthorizationState } = require('./AuthorizationState');
const { requireOuReceiver } = require('./AuthorityTenant');
const { mayUseDirectory, requireDirectoryPermissions } = require('./DirectoryAuthority');
const { DirectoryReader, ouMemberFromRow } = require('./DirectoryReader');
const { groupFields } = require('./GroupMutator');

function reject(status, message) { throw Object.assign(new Error(message), { status }); }
function ouEtag(unit) { return `"ou-${unit.id}-${unit.revision}"`; }
function validateOuEtag(value) {
  if (value === undefined) reject(428, 'An exact If-Match OU version is required');
  const match = typeof value === 'string' && /^"ou-([a-f0-9-]{36})-([1-9][0-9]{0,18})"$/.exec(value);
  if (!match || match[0].length !== value.length || !validUuid(match[1]) || !validRevision(match[2])) reject(400, 'One strong OU ETag is required');
}
function ouFields(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || !Object.keys(body).length || Object.keys(body).some(field => !['name', 'description', 'parentId'].includes(field))) reject(400, 'Exact OU metadata fields required');
  const named = Object.fromEntries(Object.entries(body).filter(([field]) => field !== 'parentId')); const values = Object.keys(named).length ? groupFields(named) : {};
  if (Object.hasOwn(body, 'parentId')) {
    if (body.parentId !== null && !validUuid(body.parentId)) reject(400, 'Canonical own OU parent required');
    values.parentId = body.parentId?.toLowerCase() || null;
  }
  return values;
}
function validateOuTree(rows, targetId, action, parentId) {
  if (rows.length > 10000) reject(503, 'OU collection exceeds the supported mutation boundary');
  const nodes = new Map(rows.map(unit => [unit.id, unit.parent_id]));
  if (!nodes.has(targetId)) reject(404, 'OU not found');
  if (action === 'delete') {
    if (rows.some(unit => unit.parent_id === targetId)) reject(409, 'OU with active children cannot be deleted'); nodes.delete(targetId);
  } else {
    if (parentId && !nodes.has(parentId)) reject(404, 'OU parent not found'); nodes.set(targetId, parentId);
  }
  for (const unitId of nodes.keys()) {
    const seen = new Set(); let current = unitId;
    while (current) {
      if (!nodes.has(current)) reject(503, 'Incoherent OU hierarchy');
      if (seen.has(current) || seen.size >= 256) reject(409, 'OU change would create a cyclic or excessive hierarchy');
      seen.add(current); current = nodes.get(current);
    }
  }
}
class OuMutator {
  constructor(database, { issuer = process.env.OIDC_ISSUER || 'http://localhost:3001', revalidate = createTenantStateClient(), newOperationId = randomUUID } = {}) {
    this.database = database; this.issuer = issuer; this.revalidate = revalidate; this.newOperationId = newOperationId;
  }
  async mutate(action, ouId, changes, expected, user, authorization) {
    if (!validUuid(ouId)) reject(400, 'Canonical OU UUID required'); const targetId = ouId.toLowerCase(); validateOuEtag(expected);
    const permission = { update: 'ous.update', delete: 'ous.delete', 'member-add': 'ous.members.manage', 'member-remove': 'ous.members.manage' }[action];
    const membership = action === 'member-add' || action === 'member-remove';
    if (!this.database.isAvailable()) reject(503, 'Canonical OU storage required');
    if (!permission || user?.actor_type !== 'user' || user.iss !== this.issuer || !validContext(user.identity_authorization) || !mayUseDirectory(user, [permission])) reject(403, 'Canonical OU mutation operator required');
    const tenant = await this.revalidate(authorization, user); const operationId = this.newOperationId(); if (!validUuid(operationId)) reject(503, 'OU operation identifier unavailable');
    return this.database.transaction(async client => {
      const current = (await client.query('SELECT id,version,generation FROM identity_tenants WHERE id=$1 AND enabled FOR SHARE', [tenant.id])).rows[0];
      if (!current || !sameTenantContext(tenant, { id: current.id, version: String(current.version), generation: String(current.generation) })) reject(401, 'Tenant authority changed');
      await requireOuReceiver(client); await client.query('SELECT identity_directory_ou_lock($1)', [tenant.id]);
      let member = null;
      if (membership) {
        const initial = await new AuthorizationState({ transaction: callback => callback(client) }).state(user.iss, user.sub);
        if (!initial.active || !sameContext(initial.context, user.identity_authorization) || !sameTenantContext(initial.tenant, tenant) || !acceptsRoleAuthentication(initial.authentication, user)) reject(401, 'Original OU authority changed');
        await requireDirectoryPermissions(client, user, [permission]);
        const previous = action === 'member-remove' ? (await client.query('SELECT identity_directory_ou_member_state(link) AS state FROM identity_directory_ou_members link WHERE id=$1 AND ou_id=$2 AND tenant_id=$3', [changes.memberId, targetId, tenant.id])).rows[0]?.state : null;
        if (action === 'member-remove' && !previous) reject(404, 'OU membership not found');
        member = { id: previous?.id || randomUUID(), userId: previous?.user_id || changes.userId, before: previous || null };
        const identities = [...new Set([user.identity_authorization.userId.toLowerCase(), member.userId])].sort();
        const locked = (await client.query("SELECT id FROM users WHERE id=ANY($1::uuid[]) AND identity_tenant_id('user',id)=$2 ORDER BY id FOR UPDATE", [identities, tenant.id])).rows;
        if (!locked.some(account => account.id === user.identity_authorization.userId.toLowerCase())) reject(401, 'Original OU operator unavailable');
        if (!locked.some(account => account.id === member.userId)) reject(404, 'OU member not found');
      } else if (!(await client.query("SELECT id FROM users WHERE id=$1 AND identity_tenant_id('user',id)=$2 FOR SHARE", [user.identity_authorization.userId, tenant.id])).rows.length) reject(401, 'Original OU operator unavailable');
      const source = await new AuthorizationState({ transaction: callback => callback(client) }).state(user.iss, user.sub);
      if (!source.active || !sameContext(source.context, user.identity_authorization) || !sameTenantContext(source.tenant, tenant) || !acceptsRoleAuthentication(source.authentication, user)) reject(401, 'Original OU authority changed');
      await requireDirectoryPermissions(client, user, [permission]); await client.query("SET LOCAL statement_timeout = '15s'");
      const rows = (await client.query("SELECT id,parent_id FROM ous WHERE identity_tenant_id('ou',id)=$1 ORDER BY id LIMIT 10001 FOR UPDATE", [tenant.id])).rows;
      if (!rows.some(unit => unit.id === targetId)) reject(404, 'OU not found');
      const before = (await client.query("SELECT identity_directory_ou_state(unit) AS state FROM ous unit WHERE id=$1 AND identity_tenant_id('ou',id)=$2", [targetId, tenant.id])).rows[0]?.state;
      if (!before) reject(404, 'OU not found'); if (ouEtag({ id: targetId, revision: before.revision }) !== expected) reject(412, 'OU changed; reload before retrying');
      const values = action === 'delete' ? null : { name: before.name, description: before.description ?? null, parentId: before.parent_id ?? null, ...(membership ? {} : changes) };
      validateOuTree(rows, targetId, action, values?.parentId);
      if (action === 'delete' && (await client.query('SELECT id FROM identity_directory_ou_members WHERE ou_id=$1 LIMIT 1', [targetId])).rows.length) reject(409, 'OU still has assigned users');
      if (action === 'member-add') {
        if ((await client.query('SELECT id FROM identity_directory_ou_members WHERE ou_id=$1 AND user_id=$2', [targetId, member.userId])).rows.length) reject(409, 'User already belongs to this OU');
        if (Number((await client.query('SELECT count(*) AS count FROM identity_directory_ou_members WHERE ou_id=$1', [targetId])).rows[0].count) >= 10000) reject(409, 'OU membership boundary exceeded');
      }
      if (!sameTenantContext(tenant, await this.revalidate(authorization, user))) reject(401, 'Tenant authority changed');
      const rolesSnapshot = (await client.query('SELECT identity_subject_link_role_state($1) AS state', [user.identity_authorization.userId])).rows[0].state;
      const validUntil = Math.min(user.exp, source.authentication.required ? user.auth_time + source.authentication.maxAgeSeconds : user.exp);
      if (!Number.isFinite(validUntil) || validUntil * 1000 <= Date.now()) reject(401, 'Original OU assurance expired');
      const proof = { operationId: operationId.toLowerCase(), issuer: user.iss, subject: user.sub, context: user.identity_authorization, tenant, rolesSnapshot, validUntil, target: { id: targetId, action, before, expectedValues: values, ...(member ? { member } : {}) } };
      await client.query(membership ? 'SELECT identity_directory_ou_membership_change($1::jsonb)' : 'SELECT identity_directory_ou_change($1::jsonb)', [JSON.stringify(proof)]);
      const receipt = await client.query(`SELECT event.id FROM identity_directory_ou_events event JOIN identity_directory_ou_outbox outbox USING(id)
        WHERE event.id=$1 AND event.tenant_id=$2 AND event.ou_id=$3 AND event.action=$4 AND event.proof=$5::jsonb
        AND event.transaction_id=txid_current() AND outbox.tenant_id=event.tenant_id AND outbox.status='pending'`, [proof.operationId, tenant.id, targetId, action, JSON.stringify(proof)]);
      if (receipt.rows.length !== 1) reject(503, 'Actual tenant-bound OU receipt unavailable');
      const result = action === 'delete' ? null : (await new DirectoryReader(this.database).readOus(client, tenant.id, targetId))[0];
      if (action !== 'delete' && !result) reject(503, 'OU mutation readback unavailable');
      const linked = action === 'member-add' ? (await client.query('SELECT identity_directory_ou_member_state(link) AS state FROM identity_directory_ou_members link WHERE id=$1 AND ou_id=$2 AND tenant_id=$3', [member.id, targetId, tenant.id])).rows[0]?.state : member?.before;
      if (membership && !linked) reject(503, 'Membership readback unavailable');
      if (!sameTenantContext(tenant, await this.revalidate(authorization, user))) reject(401, 'Tenant authority changed'); return membership ? { unit: result, membership: ouMemberFromRow(linked), action } : result;
    }, { actor: user.sub });
  }
  async update(ouId, body, expected, user, authorization) { return this.mutate('update', ouId, ouFields(body), expected, user, authorization); }
  remove(ouId, expected, user, authorization) { return this.mutate('delete', ouId, null, expected, user, authorization); }
  async addMember(ouId, body, expected, user, authorization) {
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length !== 1 || !validUuid(body.userId)) reject(400, 'One canonical member userId required');
    return this.mutate('member-add', ouId, { userId: body.userId.toLowerCase() }, expected, user, authorization);
  }
  async removeMember(ouId, memberId, expected, user, authorization) {
    if (!validUuid(memberId)) reject(400, 'Canonical membership UUID required');
    return this.mutate('member-remove', ouId, { memberId: memberId.toLowerCase() }, expected, user, authorization);
  }
}
module.exports = { OuMutator, ouEtag, validateOuEtag, ouFields, validateOuTree };
