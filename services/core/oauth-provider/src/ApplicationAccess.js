'use strict';

const { createHash, randomUUID } = require('node:crypto');
const { validUuid, validRevision, validContext, validMemberships } = require('../../../../packages/identity-authorization-contract');
const { mapRow, protectedClient, administrator, permissionsOf } = require('./ClientRegistry');
const ID = /^[A-Za-z0-9._~-]{1,255}$/;
const INTERACTIVE = ['authorization_code','urn:ietf:params:oauth:grant-type:device_code'];
class ApplicationAccessError extends Error { constructor(status, code) { super(code); this.status = status; this.code = code; } }
function fail(status, code) { throw new ApplicationAccessError(status, code); }
function actorRecord(actor) { return { issuer: actor.iss, subject: actor.sub, userId: actor.identity_authorization?.userId || null, type: actor.actor_type }; }
function sameActor(first, second) { return ['issuer','subject','userId','type'].every(key => first?.[key] === second?.[key]); }
function fields(value, names) { if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !names.includes(key))) fail(400, 'invalid_application_assignment'); }
function validApplicationContext(value) {
  return !!value && typeof value === 'object' && Object.keys(value).length === 4 && value.schemaVersion === 1
    && typeof value.clientId === 'string' && ID.test(value.clientId) && validUuid(value.userId)
    && typeof value.revision === 'string' && value.revision.length === 64 && /^[a-f0-9]{64}$/.test(value.revision);
}
function assignment(row) {
  return { id: row.id, clientId: row.client_id, targetType: row.target_type, targetId: row.target_id, targetRevision: row.target_revision,
    reason: row.reason, durationSeconds: row.duration_seconds, createdAt: new Date(row.created_at).toISOString(), expiresAt: new Date(row.expires_at).toISOString(),
    revokedAt: row.revoked_at ? new Date(row.revoked_at).toISOString() : null, status: row.status };
}
const SELECT = "SELECT *,CASE WHEN revoked_at IS NOT NULL THEN 'revoked' WHEN expires_at<=clock_timestamp() THEN 'expired' ELSE 'active' END AS status FROM oauth_application_assignments";
function source(connection) {
  return {
    client: async id => mapRow((await connection.query('SELECT * FROM oauth_clients WHERE id=$1 FOR UPDATE', [id])).rows[0]),
    get: async id => (await connection.query(SELECT + ' WHERE id=$1', [id])).rows[0],
    list: async id => (await connection.query(SELECT + ' WHERE client_id=$1 ORDER BY (revoked_at IS NULL AND expires_at>clock_timestamp()) DESC,created_at DESC,id LIMIT 101', [id])).rows,
    effective: async (id, userId, groupIds) => (await connection.query(`SELECT id,target_type,target_id FROM oauth_application_assignments WHERE client_id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp()
      AND ((target_type='user' AND target_id=$2) OR (target_type='group' AND target_id=ANY($3::uuid[]))) ORDER BY id LIMIT 101`, [id, userId, groupIds])).rows,
    duplicate: async (id, type, target) => (await connection.query("SELECT id FROM oauth_application_assignments WHERE client_id=$1 AND target_type=$2 AND target_id=$3 AND revoked_at IS NULL AND expires_at>clock_timestamp() LIMIT 1", [id,type,target])).rows.length > 0,
    insert: async (id, input, proof) => connection.query(`INSERT INTO oauth_application_assignments(id,client_id,target_type,target_id,target_revision,reason,duration_seconds)
      VALUES($1,$2,$3,$4,$5,$6,$7)`, [input.requestId,id,input.targetType,input.targetId,proof.revision,input.reason,input.durationSeconds]),
    revoke: async id => connection.query('UPDATE oauth_application_assignments SET revoked_at=clock_timestamp() WHERE id=$1 AND revoked_at IS NULL', [id]),
  };
}
class ApplicationAccess {
  constructor(database, { identity, demo = false, production = process.env.NODE_ENV === 'production', companyConsoleClientId = process.env.COMPANY_CONSOLE_CLIENT_ID || '' } = {}) {
    if (demo && production) throw new Error('Application assignment bypass is forbidden in production');
    this.database = database; this.identity = identity; this.demo = demo; this.companyConsoleClientId = companyConsoleClientId;
  }
  async transaction(operation, actor) {
    let connection;
    try {
      if (!this.database.isAvailable()) fail(503, 'application_access_unavailable');
      connection = await this.database.pool.connect(); await connection.query('BEGIN');
      await connection.query("SET LOCAL statement_timeout='1500ms'"); await connection.query("SET LOCAL lock_timeout='1000ms'");
      if (actor) await connection.query("SELECT set_config('opendirectory.actor',$1,true)", [JSON.stringify(actorRecord(actor))]);
      const result = await operation(source(connection)); await connection.query('COMMIT'); return result;
    } catch (error) {
      if (connection) await connection.query('ROLLBACK').catch(() => {});
      if (error instanceof ApplicationAccessError) throw error;
      throw new ApplicationAccessError(['23505','40001'].includes(error.code) ? 409 : 503, ['23505','40001'].includes(error.code) ? 'application_assignment_conflict' : 'application_access_unavailable');
    } finally { connection?.release(); }
  }
  authority(actor, permission) {
    if (!permissionsOf(actor).includes(permission) || !validContext(actor.identity_authorization)) fail(403, 'forbidden');
  }
  async client(repository, clientId, actor, manage = false) {
    if (typeof clientId !== 'string' || !ID.test(clientId)) fail(400, 'invalid_client');
    const client = await repository.client(clientId); if (!client || client.deletedAt) fail(404, 'client_not_found');
    if (!client.grantTypes.some(grant => INTERACTIVE.includes(grant))) fail(400, 'human_assignments_not_supported');
    if (manage && protectedClient(client) && !administrator(actor)) fail(403, 'protected_client');
    return client;
  }
  async context(clientId, state) {
    if (this.demo) return undefined;
    if (!validContext(state?.context) || !validMemberships(state.memberships)) fail(503, 'invalid_identity_assignment_source');
    const membership = new Map(state.memberships.map(member => [member.groupId,member.membershipId]));
    const grants = await this.transaction(repository => repository.effective(clientId, state.context.userId, [...membership.keys()]));
    if (grants.length > 100) fail(503, 'application_assignment_limit');
    if (!grants.length && this.companyConsoleClientId && clientId === this.companyConsoleClientId) {
      const source = await this.identity.companyConsole(clientId, state.context.userId);
      if (source.active) return { schemaVersion: 1, clientId, userId: state.context.userId, revision: source.revision };
    }
    if (!grants.length) fail(403, 'application_not_assigned');
    const revision = createHash('sha256').update(JSON.stringify([clientId,state.context.userId,grants.map(grant => [grant.id,grant.target_type === 'group' ? membership.get(grant.target_id) : null])])).digest('hex');
    return { schemaVersion: 1, clientId, userId: state.context.userId, revision };
  }
  async matches(clientId, state, expected) {
    if (this.demo) return true;
    if (!validApplicationContext(expected) || expected.clientId !== clientId || expected.userId !== state?.context?.userId) return false;
    try { const current = await this.context(clientId,state); return current.revision === expected.revision; }
    catch (error) { if (error.status === 403) return false; throw error; }
  }
  async list(clientId, actor) {
    this.authority(actor,'applications.assignments.read');
    return this.transaction(async repository => {
      const client = await this.client(repository,clientId,actor); const rows = await repository.list(clientId);
      return { clientId, name: client.name, protected: protectedClient(client), assignmentRequired: true,
        canManage: permissionsOf(actor).includes('applications.assignments.manage') && (!protectedClient(client) || administrator(actor)),
        assignments: rows.slice(0,100).map(assignment), truncated: rows.length > 100 };
    });
  }
  input(body, bootstrap = false) {
    fields(body,['requestId','targetType','targetId','durationSeconds','reason']);
    if (!validUuid(body.requestId) || !['user','group'].includes(body.targetType) || !validUuid(body.targetId)
      || !Number.isInteger(body.durationSeconds) || body.durationSeconds < 60 || body.durationSeconds > (bootstrap ? 28800 : 2592000)
      || typeof body.reason !== 'string' || body.reason.trim().length < 10 || body.reason.length > 500 || /[\u0000-\u001f\u007f]/.test(body.reason)
      || (bootstrap && body.targetType !== 'user')) fail(400, 'invalid_application_assignment');
    return { ...body, requestId: body.requestId.toLowerCase(), targetId: body.targetId.toLowerCase(), reason: body.reason.trim() };
  }
  async grant(clientId, body, actor, bootstrap = false) {
    if (!bootstrap) this.authority(actor,'applications.assignments.manage');
    else if (actor.actor_type !== 'bootstrap') fail(403,'forbidden');
    const input = this.input(body,bootstrap);
    await this.transaction(repository => this.client(repository,clientId,actor,!bootstrap));
    const actorUserId = bootstrap ? input.targetId : actor.identity_authorization.userId;
    const proof = await this.identity.target(input.targetType,input.targetId,actorUserId);
    if (!bootstrap && proof.actorIsMember) fail(403,'self_application_administration');
    return this.transaction(async repository => {
      await this.client(repository,clientId,actor,!bootstrap);
      const existing = await repository.get(input.requestId);
      if (existing) {
        if (existing.client_id !== clientId || existing.target_type !== input.targetType || existing.target_id !== input.targetId
          || existing.reason !== input.reason || existing.duration_seconds !== input.durationSeconds || !sameActor(existing.created_actor,actorRecord(actor)) || existing.status !== 'active') fail(409,'application_assignment_conflict');
        return { assignment: assignment(existing), reused: true };
      }
      if (await repository.duplicate(clientId,input.targetType,input.targetId)) fail(409,'application_assignment_exists');
      await repository.insert(clientId,input,proof); return { assignment: assignment(await repository.get(input.requestId)), reused: false };
    },actor);
  }
  async revoke(clientId, assignmentId, actor) {
    this.authority(actor,'applications.assignments.manage'); if (!validUuid(assignmentId)) fail(400,'invalid_assignment');
    const row = await this.transaction(async repository => { await this.client(repository,clientId,actor,true); return repository.get(assignmentId); });
    if (!row || row.client_id !== clientId) fail(404,'application_assignment_not_found');
    const proof = await this.identity.target(row.target_type,row.target_id,actor.identity_authorization.userId).catch(error => { if (error.code === 'application_target_ineligible') return { actorIsMember: row.target_type === 'user' && row.target_id === actor.identity_authorization.userId }; throw error; });
    if (proof.actorIsMember) fail(403,'self_application_administration');
    return this.transaction(async repository => {
      await this.client(repository,clientId,actor,true); const current = await repository.get(assignmentId);
      if (!current || current.client_id !== clientId) fail(404,'application_assignment_not_found');
      if (!current.revoked_at) await repository.revoke(assignmentId);
      return { assignment: assignment(await repository.get(assignmentId)) };
    },actor);
  }
  async bootstrap(clientId, userId, durationSeconds, reason, issuer) {
    return this.grant(clientId,{ requestId: randomUUID(), targetType: 'user', targetId: userId, durationSeconds, reason },
      { iss: issuer, sub: 'offline-application-bootstrap', actor_type: 'bootstrap' },true);
  }
}
module.exports = { ApplicationAccess, ApplicationAccessError, validApplicationContext };
