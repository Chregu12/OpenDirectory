'use strict';

const { provenMfa } = require('../../../../../packages/mfa-authorization-contract');
const { validContext } = require('../../../../../packages/identity-authorization-contract');
const { createAccessStateClient } = require('../../../../../packages/oidc-access-state');
const { getLicensePermissions } = require('../middleware/licenseAccess');
const { LicenseError } = require('./LicenseError');
const { requirePrincipal, UUID } = require('./LicensePrincipal');
const { withdrawSource } = require('./LicenseSourceMutation');
const { scopedPermission, scopeContext } = require('./LicenseScopeContext');

const SELECT = `SELECT grants.*,event.version,event.state,event.expires_at,
  CASE WHEN grants.kind='direct' THEN EXISTS(SELECT 1 FROM license_assignment_sources WHERE grant_id=grants.id)
    ELSE EXISTS(SELECT 1 FROM license_group_rules WHERE grant_id=grants.id AND enabled) END AS present,
  license_source_expiry(grants.id,event.expires_at)<=license_now() AS expired,
  (SELECT COUNT(*)::int FROM license_assignment_sources WHERE grant_id=grants.id AND (license_member_source_expiry(grant_id,user_id,expires_at) IS NULL OR license_member_source_expiry(grant_id,user_id,expires_at)>license_now())) AS source_users
  FROM license_grants grants JOIN license_catalog catalog ON catalog.id=grants.license_id AND catalog.business_tenant_id IS NULL
  JOIN LATERAL(SELECT * FROM license_grant_events WHERE grant_id=grants.id ORDER BY version DESC LIMIT 1) event ON true`;

function fail(status, message) { throw new LicenseError(status, message); }
function uuid(value) { if (typeof value !== 'string' || !UUID.test(value)) fail(400, 'canonical_uuid_required'); }
function etag(grant) { return `"od-license-grant:${grant.id}:${grant.version}"`; }
function view(row) {
  if (!row) fail(404, 'license_grant_not_found');
  return { id: row.id, licenseId: row.license_id, kind: row.kind, recipientId: row.recipient_id, version: String(row.version),
    origin: row.origin, createdAt: row.created_at.toISOString(), expiresAt: row.expires_at?.toISOString() || null,
    state: row.state !== 'active' ? row.state : !row.present ? 'revoked' : row.expired ? 'expired' : 'active', sourceUsers: row.source_users };
}

class LicenseGrants {
  constructor(allocator, { revalidate } = {}) {
    this.allocator = allocator;
    this.database = allocator.database;
    this.revalidate = revalidate || createAccessStateClient();
  }

  actor(user, principal, licenseId) {
    requirePrincipal(principal);
    if (user?.actor_type !== 'user' || user.iss !== principal.issuer || user.sub !== principal.subject
      || !validContext(user.identity_authorization) || user.identity_authorization.userId !== principal.userId
      || !(scopeContext.getStore() ? scopedPermission(user, principal, licenseId, 'assignments.manage') : getLicensePermissions(user).includes('licenses.assignments.manage'))) fail(403, 'license_grant_authority_required');
    const now = Math.floor(Date.now() / 1000);
    if (!provenMfa(user) || user.auth_time > now + 5 || now - user.auth_time > 300) fail(428, 'fresh_mfa_required');
    return principal.userId;
  }

  async get(licenseId, grantId, client = this.database) {
    uuid(licenseId); uuid(grantId);
    await this.allocator.assertPoolAccess(licenseId, client, { legacyOnly: true });
    return view((await client.query(`${SELECT} WHERE grants.license_id=$1 AND grants.id=$2`, [licenseId, grantId])).rows[0]);
  }

  async list(licenseId, after, client = this.database) {
    uuid(licenseId); if (after !== undefined) uuid(after);
    await this.allocator.assertPoolAccess(licenseId, client, { legacyOnly: true });
    const rows = (await client.query(`${SELECT} WHERE grants.license_id=$1 AND ($2::uuid IS NULL OR grants.id>$2) ORDER BY grants.id LIMIT 101`, [licenseId, after || null])).rows;
    return { grants: rows.slice(0, 100).map(view), hasMore: rows.length > 100, nextAfter: rows.length > 100 ? rows[99].id : null };
  }

  async revoke(licenseId, grantId, expected, body, user, principal, authorization) {
    const actor = this.actor(user, principal, licenseId);
    uuid(licenseId); uuid(grantId);
    if (!expected) fail(428, 'license_grant_version_required');
    if (typeof expected !== 'string' || !/^"od-license-grant:[0-9a-f-]{36}:[1-9]\d{0,18}"$/.test(expected)) fail(400, 'invalid_license_grant_version');
    if (!body || Array.isArray(body) || Object.keys(body).length !== 2 || body.confirm !== true || typeof body.reason !== 'string'
      || body.reason.trim().length < 10 || body.reason.length > 500 || /[\u0000-\u001f\u007f]/.test(body.reason)) fail(400, 'confirmed_reason_required');
    await this.get(licenseId, grantId);
    const previous = await this.database.query('SELECT user_id FROM license_assignment_sources WHERE grant_id=$1', [grantId]);
    const identifiers = [...new Set([actor, ...previous.rows.map(row => row.user_id)])].sort();
    for (const identifier of identifiers) await this.allocator.assertLegacySubject(identifier);
    return this.allocator.transaction(async client => {
      await this.allocator.assertPoolAccess(licenseId, client, { legacyOnly: true });
      for (const identifier of identifiers) {
        await this.allocator.assertLegacySubject(identifier, client);
        await client.query('INSERT INTO license_subjects(user_id) VALUES($1) ON CONFLICT DO NOTHING', [identifier]);
        const state = (await client.query('SELECT * FROM license_subjects WHERE user_id=$1 AND business_tenant_id IS NULL FOR UPDATE', [identifier])).rows[0];
        if (!state) fail(404, 'legacy_license_subject_not_found');
        if (identifier === actor && (state.disabled || state.directory_enabled === false)) fail(403, 'license_actor_disabled');
      }
      await this.allocator.lockLicense(client, licenseId);
      await this.allocator.authorizeOperation(client,licenseId,'assignments.manage');
      const current = await this.get(licenseId, grantId, client);
      if (expected !== etag(current)) fail(412, 'license_grant_changed');
      if (current.state !== 'active') fail(409, 'license_grant_not_active');
      const sources = (await client.query('SELECT user_id FROM license_assignment_sources WHERE grant_id=$1', [grantId])).rows;
      if (sources.some(row => !identifiers.includes(row.user_id))) fail(409, 'license_grant_members_changed');
      await this.revalidate(authorization, user);
      this.actor(user, principal, licenseId);
      await client.query("SELECT set_config('opendirectory.license_actor_user',$1,true),set_config('opendirectory.license_actor_issuer',$2,true),set_config('opendirectory.license_actor_subject',$3,true)", [actor, principal.issuer, principal.subject]);
      const { usersRetainingAssignment } = await withdrawSource(this.allocator, client, current, actor);
      const grant = await this.get(licenseId, grantId, client);
      await this.allocator.audit(client, licenseId, 'grant-revoked', actor, { grantId, version: grant.version, previousVersion: current.version,
        kind: grant.kind, recipientId: grant.recipientId, reason: body.reason.trim(), sourcesRemoved: sources.length, usersRetainingAssignment });
      await this.revalidate(authorization, user);
      this.actor(user, principal, licenseId);
      return { grant, localOnly: true, sourcesRemoved: sources.length, usersRetainingAssignment };
    });
  }
}

module.exports = { LicenseGrants, etag };
