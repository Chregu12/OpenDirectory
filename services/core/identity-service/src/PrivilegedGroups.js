'use strict';

const { PrivilegedActivation, authority, uuid, fields, reason, duration } = require('./PrivilegedActivation');
const { authorityTenant, requireAuthorityReceiver } = require('./AuthorityTenant');
const { getIdentityPermissions } = require('./middleware/identityAccess');
const { readRoleState } = require('./RoleState');
const { ROLES, PROTECTED } = require('../../../../packages/directory-role-contract');
function fail(status, code) { throw Object.assign(new Error(code), { status, code }); }
function text(value, minimum, maximum) { if (typeof value !== 'string' || value !== value.trim() || Array.from(value).length < minimum || Array.from(value).length > maximum || /[\u0000-\u001f\u007f-\u009f]/.test(value)) fail(400, 'bounded_pim_group_text_required'); return value; }
function page(value) { if (value === undefined) return 1; if (typeof value !== 'string' || !/^[1-9][0-9]{0,5}$/.test(value)) fail(400, 'invalid_page'); return Number(value); }
function view(row, user) {
  const permissions = getIdentityPermissions(user);
  return { id: row.id, name: row.name, description: row.description, role: row.role, maxDurationSeconds: Math.min(row.max_duration_seconds, row.policy_max),
    configuredMaxDurationSeconds: row.max_duration_seconds, enabled: row.disabled_at === null, protected: PROTECTED.includes(row.role),
    createdAt: new Date(row.created_at).toISOString(), canManage: permissions.includes('pim.eligibilities.manage') && (!PROTECTED.includes(row.role) || user.roles?.includes('admin') === true) };
}
class PrivilegedGroups {
  constructor(database, options) { this.database = database; this.pim = new PrivilegedActivation(database, options); }
  async group(client, id, tenant, lock = false) {
    const row = (await client.query(`SELECT duty.*,policy.max_duration_seconds AS policy_max FROM identity_pim_groups duty JOIN identity_role_activation_policies policy ON policy.role=duty.role
      WHERE duty.id=$1 AND duty.tenant_id=$2` + (lock ? ' FOR UPDATE OF duty FOR SHARE OF policy' : ''), [id, tenant])).rows[0];
    if (!row) fail(404, 'pim_group_not_found'); return row;
  }
  async catalog(user) {
    const proof = authority(user); const permissions = getIdentityPermissions(user);
    return this.database.transaction(async client => {
      const tenant = await authorityTenant(client, proof);
      const rows = (await client.query(`SELECT duty.*,policy.max_duration_seconds AS policy_max FROM identity_pim_groups duty JOIN identity_role_activation_policies policy ON policy.role=duty.role
        WHERE duty.tenant_id=$1 ORDER BY (duty.disabled_at IS NULL) DESC,CASE WHEN duty.role='admin' THEN 1 ELSE 0 END,duty.name COLLATE "C",duty.id LIMIT 101`, [tenant])).rows;
      const bindings = (await client.query(`SELECT binding.group_id,binding.eligibility_id,binding.user_id FROM identity_pim_group_eligibilities binding JOIN identity_pim_groups duty ON duty.id=binding.group_id
        WHERE duty.tenant_id=$1 AND (binding.user_id=$2 OR $3::boolean) ORDER BY binding.created_at DESC,binding.eligibility_id LIMIT 1001`, [tenant, proof.userId, permissions.includes('pim.requests.read') || permissions.includes('pim.eligibilities.read')])).rows;
      const currentRoles = (await readRoleState(client, proof.userId)).roles;
      const standing = (await client.query(`SELECT DISTINCT assignment.role FROM identity_role_assignments assignment JOIN identity_role_activation_policies policy ON policy.role=assignment.role AND policy.version=assignment.policy_version
        WHERE assignment.user_id=$1 AND assignment.activation_request_id IS NULL AND assignment.revoked_at IS NULL AND NOT policy.activation_required
        AND (assignment.expires_at IS NULL OR assignment.expires_at>clock_timestamp()) ORDER BY assignment.role`, [proof.userId])).rows.map(row => row.role).filter(role => currentRoles.includes(role));
      return { schemaVersion: 1, userId: proof.userId, groups: rows.slice(0, 100).map(row => view(row, user)), bindings: bindings.slice(0, 1000).map(row => ({ groupId: row.group_id, eligibilityId: row.eligibility_id, userId: row.user_id })),
        standingRoles: standing, canCreate: permissions.includes('pim.eligibilities.manage'), canReview: permissions.includes('pim.requests.read'), truncated: rows.length > 100 || bindings.length > 1000 };
    }, { readOnly: true });
  }
  async create(input, user, authorization) {
    fields(input, ['name', 'description', 'role', 'maxDurationSeconds', 'reason', 'confirm']);
    const name = text(input.name, 2, 80); const description = text(input.description, 0, 500); const explanation = reason(input.reason);
    if (input.confirm !== true || !ROLES.includes(input.role) || input.role === 'user') fail(400, 'explicit_pim_group_duty_required'); duration(input.maxDurationSeconds);
    const proof = authority(user);
    return this.pim.commands.run(user, authorization, async client => {
      await requireAuthorityReceiver(client); const tenant = await authorityTenant(client, proof, { write: true });
      const locked = await this.pim.lockUsers(client, [proof.userId], tenant); const roles = await this.pim.verify(client, proof, locked, 'pim.eligibilities.manage'); this.pim.protectedRole(input.role, roles);
      if (Number((await client.query('SELECT count(*) AS count FROM identity_pim_groups WHERE tenant_id=$1 AND disabled_at IS NULL', [tenant])).rows[0].count) >= 100) fail(409, 'pim_group_limit');
      const row = (await client.query('INSERT INTO identity_pim_groups(tenant_id,name,description,role,max_duration_seconds,created_by,reason) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id', [tenant, name, description, input.role, input.maxDurationSeconds, proof.userId, explanation])).rows[0];
      return view(await this.group(client, row.id, tenant), user);
    }, { actor: JSON.stringify(proof) }, { required: true, maxAgeSeconds: 300 });
  }
  async initialize(input, user, authorization) {
    fields(input, ['confirm']); if (input.confirm !== true) fail(400, 'explicit_pim_group_confirmation_required'); const proof = authority(user);
    return this.pim.commands.run(user, authorization, async client => {
      const tenant = await authorityTenant(client, proof, { write: true }); const locked = await this.pim.lockUsers(client, [proof.userId], tenant);
      const roles = await this.pim.verify(client, proof, locked, 'pim.eligibilities.manage'); this.pim.protectedRole('admin', roles);
      await client.query('SELECT identity_pim_seed_groups($1,$2)', [tenant, proof.userId]); return { schemaVersion: 1, initialized: true };
    }, { actor: JSON.stringify(proof) }, { required: true, maxAgeSeconds: 300 });
  }
  async disable(id, input, user, authorization) {
    id = uuid(id); fields(input, ['reason', 'confirm']); const explanation = reason(input.reason); if (input.confirm !== true) fail(400, 'explicit_pim_group_confirmation_required');
    const proof = authority(user);
    return this.pim.commands.run(user, authorization, async client => {
      await requireAuthorityReceiver(client); const tenant = await authorityTenant(client, proof, { write: true }); const group = await this.group(client, id, tenant, true);
      const recipients = (await client.query('SELECT DISTINCT binding.user_id FROM identity_pim_group_eligibilities binding JOIN identity_pim_eligibilities eligibility ON eligibility.id=binding.eligibility_id WHERE binding.group_id=$1 AND eligibility.revoked_at IS NULL AND eligibility.expires_at>clock_timestamp() ORDER BY binding.user_id', [id])).rows.map(row => row.user_id);
      const locked = await this.pim.lockUsers(client, [proof.userId, ...recipients], tenant); const roles = await this.pim.verify(client, proof, locked, 'pim.eligibilities.manage'); this.pim.protectedRole(group.role, roles);
      if (group.disabled_at) fail(409, 'pim_group_disabled');
      await client.query('UPDATE identity_pim_groups SET disabled_at=clock_timestamp(),reason=$2 WHERE id=$1', [id, explanation]);
      return { id, disabled: true };
    }, { actor: JSON.stringify(proof) }, { required: true, maxAgeSeconds: 300 });
  }
  async members(id, query, user) {
    id = uuid(id); fields(query, ['page']); const selected = page(query.page); const proof = authority(user);
    if (!getIdentityPermissions(user).includes('pim.eligibilities.read')) fail(403, 'forbidden');
    return this.database.transaction(async client => {
      const tenant = await authorityTenant(client, proof); await this.group(client, id, tenant);
      const total = Number((await client.query('SELECT count(*) AS count FROM identity_pim_group_eligibilities WHERE group_id=$1', [id])).rows[0].count);
      const rows = (await client.query(`SELECT binding.eligibility_id,binding.user_id,account.username,account.display_name,eligibility.max_duration_seconds,eligibility.expires_at,eligibility.revoked_at
        FROM identity_pim_group_eligibilities binding JOIN identity_pim_eligibilities eligibility ON eligibility.id=binding.eligibility_id LEFT JOIN users account ON account.id=binding.user_id AND identity_tenant_id('user',account.id)=$3
        WHERE binding.group_id=$1 ORDER BY (eligibility.revoked_at IS NULL AND eligibility.expires_at>clock_timestamp()) DESC,eligibility.created_at DESC,eligibility.id LIMIT 25 OFFSET $2`, [id, (selected - 1) * 25, tenant])).rows;
      return { schemaVersion: 1, groupId: id, page: selected, limit: 25, total, members: rows.map(row => ({ eligibilityId: row.eligibility_id, userId: row.user_id, name: row.display_name || row.username || row.user_id,
        maxDurationSeconds: row.max_duration_seconds, expiresAt: new Date(row.expires_at).toISOString(), revoked: row.revoked_at !== null })) };
    }, { readOnly: true });
  }
  async history(id, query, user) {
    id = uuid(id); fields(query, ['page']); const selected = page(query.page); const proof = authority(user); const all = getIdentityPermissions(user).includes('pim.requests.read');
    return this.database.transaction(async client => {
      const tenant = await authorityTenant(client, proof); await this.group(client, id, tenant);
      const records = `WITH records AS (
        SELECT audit.id,audit.user_id,audit.actor,audit.details,audit.created_at,eligibility.role,request.duration_seconds,assignment.expires_at
        FROM identity_pim_audit audit LEFT JOIN identity_pim_requests request ON request.id=audit.entity_id
        JOIN identity_pim_group_eligibilities binding ON binding.eligibility_id=COALESCE(request.eligibility_id,audit.entity_id)
        JOIN identity_pim_eligibilities eligibility ON eligibility.id=binding.eligibility_id
        LEFT JOIN identity_role_assignments assignment ON assignment.activation_request_id=request.id
        WHERE binding.group_id=$1 AND (audit.user_id=$2 OR $3::boolean)
        UNION ALL SELECT audit.id,NULL::uuid,audit.actor::text,audit.details||jsonb_build_object('state','group_'||audit.action),audit.created_at,
          audit.details->>'role',NULL::integer,NULL::timestamptz FROM identity_pim_group_audit audit
        WHERE audit.group_id=$1 AND ($3::boolean OR audit.actor->>'userId'=$2::text))`;
      const args = [id, proof.userId, all]; const total = Number((await client.query(records + ' SELECT count(*) AS count FROM records', args)).rows[0].count);
      const rows = (await client.query(records + ' SELECT * FROM records ORDER BY created_at DESC,id DESC LIMIT 25 OFFSET $4', [...args, (selected - 1) * 25])).rows;
      return { schemaVersion: 1, groupId: id, page: selected, limit: 25, total, events: rows.map(row => {
        let actorId = null; try { actorId = uuid(JSON.parse(row.actor).userId); } catch {}
        const state = row.details.state || (row.details.revoked_at ? 'eligibility_revoked' : 'eligibility_created');
        return { id: row.id, userId: row.user_id, actorUserId: actorId, role: row.role, action: state, reason: row.details.reason,
          createdAt: new Date(row.created_at).toISOString(), durationSeconds: row.duration_seconds || null, expiresAt: row.expires_at ? new Date(row.expires_at).toISOString() : null };
      }) };
    }, { readOnly: true });
  }
}
module.exports = { PrivilegedGroups };
