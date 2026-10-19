'use strict';

const { validUuid, validContext, sameContext } = require('../../../../packages/identity-authorization-contract');
const { sameTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { createTenantStateClient } = require('../../../../packages/oidc-tenant-state');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { AuthorizationState } = require('./AuthorizationState');
const { mayUseDirectory, requireDirectoryPermissions } = require('./DirectoryAuthority');
const { DirectoryRoles } = require('./DirectoryRoles');
const { USER_COLUMNS, userFromRow, userListQuery } = require('./DirectoryUsers');
const { getIdentityPermissions } = require('./middleware/identityAccess');
const { companyDirectoryPermissions } = require('./CompanyOwner');

function reject(status, message) { throw Object.assign(new Error(message), { status }); }
function exactQuery(query = {}) { if (Object.keys(query).length) reject(400, 'No query selectors accepted'); }
function identifier(value) { if (!validUuid(value)) reject(400, 'Canonical directory UUID required'); }
function bounded(rows) { if (rows.length > 10000) reject(503, 'Directory collection exceeds the supported read boundary'); return rows; }
function iso(value) { return value instanceof Date ? value.toISOString() : value || undefined; }
function ouMemberFromRow(row) {
  return { id: row.id, ouId: row.ou_id, userId: row.user_id, createdAt: iso(row.created_at), ...(row.profile ? { profile: { username: row.profile.username, email: row.profile.email, displayName: row.profile.displayName ?? undefined } } : {}) };
}

class DirectoryReader {
  constructor(database, { issuer = process.env.OIDC_ISSUER || 'http://localhost:3001', revalidate = createTenantStateClient() } = {}) {
    this.database = database; this.issuer = issuer; this.revalidate = revalidate;
  }

  async read(permissions, user, authorization, operation) {
    if (!this.database.isAvailable()) reject(503, 'Canonical directory storage required');
    if (user?.actor_type !== 'user' || user.iss !== this.issuer || !validContext(user.identity_authorization)
      || !mayUseDirectory(user, permissions)) reject(403, 'Canonical directory reader required');
    const tenant = await this.revalidate(authorization, user);
    let authentication;
    const result = await this.database.transaction(async client => {
      const source = new AuthorizationState({ transaction: callback => callback(client) });
      const current = await source.state(user.iss, user.sub);
      if (!current.active || !sameContext(current.context, user.identity_authorization) || !sameTenantContext(current.tenant, tenant)
        || !acceptsRoleAuthentication(current.authentication, user)) reject(401, 'Original directory authority changed');
      authentication = current.authentication;
      await requireDirectoryPermissions(client, user, permissions);
      return operation(client, tenant.id);
    }, { readOnly: true });
    if (!sameTenantContext(tenant, await this.revalidate(authorization, user)) || !acceptsRoleAuthentication(authentication, user)
      || !Number.isFinite(user.exp) || user.exp * 1000 <= Date.now()) reject(401, 'Original directory authority changed');
    return result;
  }

  async users(query, user, authorization) {
    const { page, limit, search, enabled } = userListQuery(query);
    return this.read(['users.read'], user, authorization, async (client, tenantId) => {
      const where = "WHERE ($1='' OR strpos(lower(concat_ws(' ',username,email,display_name,department,title)),lower($1))>0) AND ($2::boolean IS NULL OR enabled=$2) AND identity_tenant_id('user',id)=$3";
      const total = Number((await client.query('SELECT COUNT(*) AS count FROM users ' + where, [search,enabled,tenantId])).rows[0].count);
      const result = await client.query(`SELECT ${USER_COLUMNS} FROM users ${where} ORDER BY created_at,id LIMIT $4 OFFSET $5`, [search,enabled,tenantId,limit,(page-1)*limit]);
      return { users: result.rows.map(userFromRow), total, page, limit };
    });
  }

  async user(userId, query, user, authorization) {
    identifier(userId); exactQuery(query);
    return this.read(['users.read'], user, authorization, async (client, tenantId) => {
      const row = (await client.query(`SELECT ${USER_COLUMNS} FROM users WHERE id=$1 AND identity_tenant_id('user',id)=$2`, [userId,tenantId])).rows[0];
      if (!row) reject(404, 'User not found');
      return userFromRow(row);
    });
  }

  async readGroups(client, tenantId, groupId = null) {
    const rows = bounded((await client.query("SELECT id,name,description,created_at,revision FROM groups WHERE identity_tenant_id('group',id)=$1 AND ($2::uuid IS NULL OR id=$2) ORDER BY created_at,id LIMIT 10001", [tenantId,groupId])).rows);
    if (!rows.length) return [];
    const members = (await client.query(`SELECT member.group_id,member.user_id FROM group_members member JOIN users account ON account.id::text=member.user_id
      WHERE member.group_id=ANY($1::uuid[]) AND identity_tenant_id('user',account.id)=$2 ORDER BY member.group_id,member.user_id`, [rows.map(row => row.id),tenantId])).rows;
    const byGroup = new Map();
    for (const member of members) { if (!byGroup.has(member.group_id)) byGroup.set(member.group_id, []); byGroup.get(member.group_id).push(member.user_id); }
    return rows.map(row => ({ id:row.id,name:row.name,description:row.description ?? undefined,members:byGroup.get(row.id) || [],createdAt:iso(row.created_at),revision:String(row.revision) }));
  }

  async groups(query, user, authorization) {
    exactQuery(query);
    return this.read(['groups.read'], user, authorization, async (client, tenantId) => {
      const groups = await this.readGroups(client, tenantId); return { groups,total:groups.length };
    });
  }

  async group(groupId, query, user, authorization) {
    identifier(groupId); exactQuery(query);
    return this.read(['groups.read'], user, authorization, async (client, tenantId) => {
      const group = (await this.readGroups(client, tenantId, groupId))[0]; if (!group) reject(404, 'Group not found'); return group;
    });
  }

  async readOus(client, tenantId, ouId = null) {
    const rows = bounded((await client.query(`SELECT id,name,description,parent_id,created_at,updated_at,revision,
      (SELECT count(*)::int FROM identity_directory_ou_members link WHERE link.ou_id=ous.id) AS member_count,
      NOT EXISTS(SELECT 1 FROM identity_directory_ou_members link WHERE link.ou_id=ous.id AND (link.tenant_id<>$1 OR identity_tenant_id('user',link.user_id) IS DISTINCT FROM $1)) AS coherent_members,
      parent_id IS NULL OR EXISTS(SELECT 1 FROM ous parent WHERE parent.id=ous.parent_id AND identity_tenant_id('ou',parent.id)=$1) AS coherent_parent
      FROM ous WHERE identity_tenant_id('ou',id)=$1 AND ($2::uuid IS NULL OR id=$2) ORDER BY created_at,id LIMIT 10001`, [tenantId,ouId])).rows);
    if (rows.some(row => row.coherent_parent !== true)) reject(503, 'Incoherent directory hierarchy');
    if (rows.some(row => row.coherent_members !== true || !Number.isSafeInteger(row.member_count) || row.member_count < 0 || row.member_count > 10000)) reject(503, 'Incoherent directory memberships');
    return rows.map(row => ({ id:row.id,name:row.name,description:row.description ?? undefined,parentId:row.parent_id ?? undefined,createdAt:iso(row.created_at),updatedAt:iso(row.updated_at),revision:String(row.revision),memberCount:row.member_count }));
  }

  async ous(query, user, authorization) {
    exactQuery(query);
    return this.read(['ous.read'], user, authorization, async (client, tenantId) => {
      const ous = await this.readOus(client, tenantId); const nodes = new Map(ous.map(ou => [ou.id,{ ...ou,children:[] }]));
      for (const ou of ous) {
        const seen = new Set(); let parent = ou;
        while (parent) {
          if (seen.has(parent.id) || seen.size >= 256) reject(503, 'Unsupported or cyclic directory hierarchy');
          seen.add(parent.id); parent = parent.parentId ? nodes.get(parent.parentId) : undefined;
        }
      }
      const tree = [];
      for (const node of nodes.values()) { if (node.parentId) nodes.get(node.parentId).children.push(node); else tree.push(node); }
      return { ous,total:ous.length,tree };
    });
  }

  async ou(ouId, query, user, authorization) {
    identifier(ouId); exactQuery(query);
    return this.read(['ous.read'], user, authorization, async (client, tenantId) => {
      const ou = (await this.readOus(client, tenantId, ouId))[0]; if (!ou) reject(404, 'OU not found'); return ou;
    });
  }

  async ouMembers(ouId, query, user, authorization) {
    identifier(ouId); if (Object.keys(query).some(field => !['page', 'limit'].includes(field))) reject(400, 'Only membership pagination selectors accepted'); const { page, limit } = userListQuery(query);
    return this.read(['ous.read'], user, authorization, async (client, tenantId) => {
      const unit = (await this.readOus(client, tenantId, ouId))[0]; if (!unit) reject(404, 'OU not found');
      const profileAccess = getIdentityPermissions(user).includes('users.read') || (await companyDirectoryPermissions(client, user)).includes('users.read');
      if ((await client.query('SELECT id FROM identity_directory_ou_members WHERE ou_id=$1 AND tenant_id<>$2 LIMIT 1', [ouId, tenantId])).rows.length) reject(503, 'Incoherent membership tenant');
      const total = Number((await client.query('SELECT count(*) AS count FROM identity_directory_ou_members WHERE ou_id=$1 AND tenant_id=$2', [ouId, tenantId])).rows[0].count);
      if (total > 10000) reject(503, 'OU membership collection exceeds the supported boundary');
      const rows = (await client.query(`SELECT link.id,link.ou_id,link.user_id,link.created_at,account.id IS NOT NULL AND identity_tenant_id('user',link.user_id)=$2 AS coherent_user,
        CASE WHEN $5::boolean THEN jsonb_build_object('username',account.username,'email',account.email,'displayName',account.display_name) END AS profile
        FROM identity_directory_ou_members link LEFT JOIN users account ON account.id=link.user_id
        WHERE link.ou_id=$1 AND link.tenant_id=$2 ORDER BY link.created_at,link.id LIMIT $3 OFFSET $4`, [ouId, tenantId, limit, (page - 1) * limit, profileAccess])).rows;
      if (rows.some(link => link.coherent_user !== true)) reject(503, 'Incoherent membership user');
      return { schemaVersion: 1, actorUserId: user.identity_authorization.userId, unit, members: rows.map(ouMemberFromRow), total, page, limit, profileAccess };
    });
  }

  async search(query, user, authorization) {
    exactQuery(query);
    return this.read(['users.read','groups.read'], user, authorization, async (client, tenantId) => {
      const users = bounded((await client.query(`SELECT ${USER_COLUMNS} FROM users WHERE identity_tenant_id('user',id)=$1 ORDER BY created_at,id LIMIT 10001`, [tenantId])).rows).map(userFromRow);
      const groups = await this.readGroups(client, tenantId); return { entries:[...users,...groups],total:users.length+groups.length };
    });
  }

  async roles(userId, query, user, authorization) {
    identifier(userId); exactQuery(query);
    return this.read(['identities.roles.read'], user, authorization, async (client, tenantId) => {
      if (!(await client.query("SELECT id FROM users WHERE id=$1 AND identity_tenant_id('user',id)=$2", [userId,tenantId])).rows.length) reject(404, 'User not found');
      return new DirectoryRoles({ transaction: callback => callback(client) }).list(userId);
    });
  }
}

module.exports = { DirectoryReader, ouMemberFromRow };
