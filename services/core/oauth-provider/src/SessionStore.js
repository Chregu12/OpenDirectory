'use strict';

const { sameContext } = require('../../../../packages/identity-authorization-contract');

const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;

class SessionError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}

function mapSession(row) {
  return row && { id: row.id, issuer: row.issuer, subject: row.subject, principalType: row.principal_type, clientId: row.client_id,
    authTime: Number(row.auth_time), createdAt: new Date(row.created_at).getTime(), expiresAt: new Date(row.expires_at).getTime(),
    revokedAt: row.revoked_at ? new Date(row.revoked_at).getTime() : null, revocationReason: row.revocation_reason };
}

function sqlRepository(client) {
  return {
    now: async () => Number((await client.query('SELECT EXTRACT(EPOCH FROM clock_timestamp())*1000 AS now')).rows[0].now),
    session: async (id, lock = false) => mapSession((await client.query('SELECT * FROM oauth_sessions WHERE id=$1' + (lock ? ' FOR UPDATE' : ''), [id])).rows[0]),
    refresh: async hash => {
      const row = (await client.query('SELECT * FROM oauth_session_refresh WHERE token_hash=$1 FOR UPDATE', [hash])).rows[0];
      return row && { hash: row.token_hash, sessionId: row.session_id, scope: row.scope, authorization: row.claims_snapshot,
        expiresAt: new Date(row.expires_at).getTime(), consumedAt: row.consumed_at ? new Date(row.consumed_at).getTime() : null };
    },
    insertSession: async session => client.query(`INSERT INTO oauth_sessions(id,issuer,subject,principal_type,client_id,auth_time,expires_at)
      VALUES($1,$2,$3,$4,$5,$6,$7)`, [session.id, session.issuer, session.subject, session.principalType, session.clientId, session.authTime, new Date(session.expiresAt)]),
    insertRefresh: async refresh => client.query(`INSERT INTO oauth_session_refresh(token_hash,session_id,scope,claims_snapshot,expires_at)
      VALUES($1,$2,$3,$4,$5)`, [refresh.hash, refresh.sessionId, refresh.scope, JSON.stringify(refresh.authorization), new Date(refresh.expiresAt)]),
    consume: async (hash, replacement) => client.query('UPDATE oauth_session_refresh SET consumed_at=clock_timestamp(),replaced_by=$2 WHERE token_hash=$1', [hash, replacement]),
    revoke: async (id, reason) => client.query('UPDATE oauth_sessions SET revoked_at=clock_timestamp(),revocation_reason=$2 WHERE id=$1 AND revoked_at IS NULL', [id, reason]),
    audit: async (id, action, actor) => client.query('INSERT INTO oauth_session_audit(session_id,action,actor_subject,actor_type,actor_client_id) VALUES($1,$2,$3,$4,$5)',
      [id, action, actor.subject, actor.principalType, actor.clientId]),
    owned: async (owner, lock = false) => (await client.query(`SELECT * FROM oauth_sessions WHERE issuer=$1 AND subject=$2 AND principal_type=$3
      ` + (lock ? 'ORDER BY id FOR UPDATE' : 'ORDER BY created_at DESC,id LIMIT 100'), [owner.issuer, owner.subject, owner.principalType])).rows.map(mapSession),
    revokeOwned: async (owner, actor) => {
      const result = await client.query(`WITH targets AS (
        SELECT id FROM oauth_sessions WHERE issuer=$1 AND subject=$2 AND principal_type=$3 AND revoked_at IS NULL AND expires_at>clock_timestamp() ORDER BY id FOR UPDATE
      ), revoked AS (
        UPDATE oauth_sessions SET revoked_at=clock_timestamp(),revocation_reason=$4 WHERE id IN (SELECT id FROM targets) RETURNING id
      ), audited AS (
        INSERT INTO oauth_session_audit(session_id,action,actor_subject,actor_type,actor_client_id)
          SELECT id,'revoked_all',$5,$6,$7 FROM revoked RETURNING id
      ) SELECT COUNT(*)::int AS revoked FROM audited`, [owner.issuer, owner.subject, owner.principalType,
        owns(owner, actor) ? 'owner_revoked' : 'administrator_revoked', actor.subject, actor.principalType, actor.clientId]);
      return result.rows[0];
    },
  };
}

function memoryRepository(state) {
  return {
    now: async () => Date.now(),
    session: async id => state.sessions.get(id),
    refresh: async hash => state.refresh.get(hash),
    insertSession: async session => { if (state.sessions.has(session.id)) throw new SessionError(503, 'duplicate_session'); state.sessions.set(session.id, { ...session, createdAt: Date.now(), revokedAt: null }); },
    insertRefresh: async refresh => { if (state.refresh.has(refresh.hash)) throw new SessionError(503, 'duplicate_refresh'); state.refresh.set(refresh.hash, { ...refresh, consumedAt: null }); },
    consume: async (hash, replacement) => { Object.assign(state.refresh.get(hash), { consumedAt: Date.now(), replacement }); },
    revoke: async (id, reason) => { Object.assign(state.sessions.get(id), { revokedAt: Date.now(), revocationReason: reason }); },
    audit: async (id, action, actor) => { state.audit.push({ id, action, ...actor }); },
    owned: async owner => [...state.sessions.values()].filter(session => owns(session, owner)).sort((first, second) => first.id.localeCompare(second.id)),
  };
}

function owns(session, actor) {
  return session.issuer === actor.issuer && session.subject === actor.subject && session.principalType === actor.principalType;
}

function viewer(payload) {
  return { issuer: payload.iss, subject: payload.sub, principalType: payload.actor_type, clientId: payload.client_id };
}

function validateRefresh(refresh) {
  if (!HASH.test(refresh.hash) || typeof refresh.scope !== 'string' || refresh.scope.length > 4096 || !Number.isFinite(refresh.expiresAt)
    || !refresh.authorization || typeof refresh.authorization !== 'object' || Array.isArray(refresh.authorization)
    || Buffer.byteLength(JSON.stringify(refresh.authorization)) > 65536) throw new SessionError(503, 'invalid_session_record');
}

function validateBinding(authorization, session) {
  if (authorization.sid !== session.id || authorization.iss !== session.issuer || authorization.sub !== session.subject
    || authorization.aud !== session.clientId || authorization.actor_type !== session.principalType || authorization.auth_time !== session.authTime) throw new SessionError(503, 'invalid_session_binding');
}

class SessionStore {
  constructor(database, { demo = false, production = process.env.NODE_ENV === 'production', limit = 10000 } = {}) {
    if (demo && production) throw new Error('In-memory sessions are forbidden in production');
    this.database = database;
    this.demo = demo;
    this.limit = limit;
    this.memory = { sessions: new Map(), refresh: new Map(), audit: [] };
    this.queue = Promise.resolve();
  }

  async ready() {
    if (this.demo) return;
    try { await this.database.query('SELECT id FROM oauth_sessions LIMIT 0'); await this.database.query('SELECT token_hash FROM oauth_session_refresh LIMIT 0'); await this.database.query('SELECT id FROM oauth_session_audit LIMIT 0'); }
    catch { throw new SessionError(503, 'session_authority_unavailable'); }
  }

  async transaction(operation) {
    if (this.demo) {
      const run = async () => {
        const state = structuredClone(this.memory);
        const result = await operation(memoryRepository(state));
        if (state.sessions.size > this.limit || state.refresh.size > this.limit) throw new SessionError(503, 'session_authority_full');
        this.memory = state;
        return result;
      };
      const next = this.queue.then(run, run);
      this.queue = next.catch(() => {});
      return next;
    }
    let client;
    try {
      client = await this.database.pool.connect();
      await client.query('BEGIN');
      await client.query("SET LOCAL lock_timeout = '2500ms'");
      await client.query("SET LOCAL statement_timeout = '5000ms'");
      const result = await operation(sqlRepository(client));
      await client.query('COMMIT');
      return result;
    } catch (error) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      if (error instanceof SessionError) throw error;
      throw new SessionError(503, 'session_authority_unavailable');
    } finally { client?.release(); }
  }

  async create(session, refresh) {
    if (!UUID.test(session.id) || typeof session.issuer !== 'string' || !session.issuer || typeof session.subject !== 'string' || !session.subject
      || session.subject.length > 255 || !['user', 'application'].includes(session.principalType) || typeof session.clientId !== 'string' || !session.clientId
      || session.clientId.length > 255 || !Number.isInteger(session.authTime) || !Number.isFinite(session.expiresAt)) throw new SessionError(503, 'invalid_session_record');
    if (refresh) { validateRefresh(refresh); validateBinding(refresh.authorization, session); }
    return this.transaction(async repository => {
      if (session.expiresAt <= await repository.now()) throw new SessionError(400, 'invalid_grant');
      await repository.insertSession(session);
      if (refresh) await repository.insertRefresh({ ...refresh, sessionId: session.id });
      await repository.audit(session.id, 'created', session);
    });
  }

  async active(payload) {
    if (!UUID.test(payload?.sid || '') || typeof payload.client_id !== 'string' || !['user', 'application'].includes(payload.actor_type) || !Number.isInteger(payload.auth_time)) return false;
    try {
      const repository = this.demo ? memoryRepository(this.memory) : sqlRepository(this.database);
      const session = await repository.session(payload.sid);
      return !!session && owns(session, viewer(payload)) && session.clientId === payload.client_id && session.authTime === payload.auth_time
        && session.revokedAt === null && session.expiresAt > await repository.now();
    } catch { throw new SessionError(503, 'session_authority_unavailable'); }
  }

  async rotate(hash, clientId, issue) {
    if (!HASH.test(hash)) throw new SessionError(400, 'invalid_grant');
    return this.transaction(async repository => {
      const refresh = await repository.refresh(hash);
      if (!refresh) return { error: 'invalid_grant' };
      const session = await repository.session(refresh.sessionId, true);
      const now = await repository.now();
      if (!session || session.clientId !== clientId || refresh.expiresAt <= now || session.expiresAt <= now || session.revokedAt !== null) return { error: 'invalid_grant' };
      if (refresh.consumedAt !== null) {
        await repository.revoke(session.id, 'refresh_reuse');
        await repository.audit(session.id, 'refresh_reuse', { ...session, subject: clientId, principalType: 'application' });
        return { error: 'invalid_grant' };
      }
      const issued = await issue(refresh, session);
      if (issued.error) return issued;
      validateRefresh(issued.refresh);
      validateBinding(issued.refresh.authorization, session);
      if ((refresh.authorization.identity_authorization || issued.refresh.authorization.identity_authorization)
        && !sameContext(refresh.authorization.identity_authorization, issued.refresh.authorization.identity_authorization)) throw new SessionError(503, 'invalid_session_binding');
      await repository.consume(hash, issued.refresh.hash);
      await repository.insertRefresh({ ...issued.refresh, sessionId: session.id, expiresAt: Math.min(refresh.expiresAt, session.expiresAt) });
      await repository.audit(session.id, 'refreshed', { ...session, subject: clientId, principalType: 'application' });
      return issued.response;
    });
  }

  async revokeRefresh(hash, clientId) {
    return this.transaction(async repository => {
      const refresh = await repository.refresh(hash);
      if (!refresh) return false;
      const session = await repository.session(refresh.sessionId, true);
      if (!session || session.clientId !== clientId) return false;
      if (session.revokedAt === null) {
        await repository.revoke(session.id, 'refresh_revoked');
        await repository.audit(session.id, 'refresh_revoked', { ...session, subject: clientId, principalType: 'application' });
      }
      return true;
    });
  }

  async list(owner) {
    try {
      const repository = this.demo ? memoryRepository(this.memory) : sqlRepository(this.database);
      const rows = await repository.owned(owner);
      return rows.sort((first, second) => second.createdAt - first.createdAt).slice(0, 100).map(session => ({ id: session.id, clientId: session.clientId,
        principalType: session.principalType, createdAt: new Date(session.createdAt).toISOString(), expiresAt: new Date(session.expiresAt).toISOString(),
        revokedAt: session.revokedAt !== null ? new Date(session.revokedAt).toISOString() : null, revocationReason: session.revocationReason || null }));
    } catch { throw new SessionError(503, 'session_authority_unavailable'); }
  }

  async revokeSession(id, actor, administrator = false) {
    if (!UUID.test(id)) throw new SessionError(404, 'session_not_found');
    return this.transaction(async repository => {
      const session = await repository.session(id, true);
      if (!session || session.issuer !== actor.issuer || (!administrator && !owns(session, actor))) throw new SessionError(404, 'session_not_found');
      if (session.revokedAt === null) {
        await repository.revoke(id, administrator && !owns(session, actor) ? 'administrator_revoked' : 'owner_revoked');
        await repository.audit(id, 'revoked', actor);
      }
      return { id, revoked: true };
    });
  }

  async revokeAll(owner, actor) {
    return this.transaction(async repository => {
      if (repository.revokeOwned) return repository.revokeOwned(owner, actor);
      const sessions = await repository.owned(owner, true);
      const now = await repository.now();
      let revoked = 0;
      for (const session of sessions) {
        if (session.revokedAt !== null || session.expiresAt <= now) continue;
        await repository.revoke(session.id, owns(session, actor) ? 'owner_revoked' : 'administrator_revoked');
        await repository.audit(session.id, 'revoked_all', actor);
        revoked++;
      }
      return { revoked };
    });
  }
}

module.exports = { SessionStore, SessionError, viewer };
