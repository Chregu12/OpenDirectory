'use strict';

const { randomUUID, randomBytes } = require('node:crypto');
const { hashSecret, secretMatches } = require('./clientSecrets');
const { validRevision, validContext } = require('../../../../packages/identity-authorization-contract');
const { freshMfa, acceptsAuthentication } = require('./applicationAuthentication');
const GRANTS = Object.freeze(['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code']);
const SAFE_SCOPES = Object.freeze(['openid', 'profile', 'email', 'groups', 'offline_access', 'sessions.self.read', 'sessions.self.revoke']);
const PERMISSIONS = Object.freeze(['applications.read', 'applications.create', 'applications.update', 'applications.delete', 'applications.credentials.rotate']);
const ASSIGNMENT_PERMISSIONS = Object.freeze(['applications.assignments.read','applications.assignments.manage']);
const AUTHENTICATION_PERMISSIONS = Object.freeze(['applications.authentication.read','applications.authentication.manage']);
const ID = /^[A-Za-z0-9._~-]{1,255}$/;
class ClientError extends Error { constructor(status, code) { super(code); this.status = status; this.code = code; } }
function fail(status, code) { throw new ClientError(status, code); }
function listOf(value, limit, valid) { return Array.isArray(value) && value.length <= limit && new Set(value).size === value.length && value.every(valid); }
function validClient(client) {
  return typeof client.clientId === 'string' && ID.test(client.clientId) && client.clientId.trim() === client.clientId && typeof client.name === 'string' && !!client.name.trim() && client.name.length <= 255
    && typeof client.publicClient === 'boolean' && typeof client.enabled === 'boolean' && validRevision(client.version)
    && typeof client.mfaRequired === 'boolean' && Number.isInteger(client.mfaMaxAgeSeconds) && client.mfaMaxAgeSeconds >= 300 && client.mfaMaxAgeSeconds <= 86400
    && (client.publicClient ? client.clientSecretHash === null : typeof client.clientSecretHash === 'string' && client.clientSecretHash.length === 64 && /^[a-f0-9]{64}$/.test(client.clientSecretHash))
    && listOf(client.grantTypes, 4, grant => GRANTS.includes(grant)) && client.grantTypes.length > 0
    && !(client.publicClient && client.grantTypes.includes('client_credentials'))
    && listOf(client.redirectUris, 8, uri => {
      if (typeof uri !== 'string' || uri.length > 2048 || /[\u0000-\u0020\u007f]/.test(uri)) return false;
      try { const url = new URL(uri); return !url.hash && !url.username && !url.password
        && (url.protocol === 'https:' || (url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname))); } catch { return false; }
    }) && (!client.grantTypes.includes('authorization_code') || client.redirectUris.length > 0)
    && listOf(client.scopes, 64, scope => typeof scope === 'string' && scope.length <= 128 && !/\s/.test(scope) && /^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope));
}
function protectedClient(client) { return client.scopes.some(scope => !SAFE_SCOPES.includes(scope)); }
function administrator(actor) { return actor?.actor_type === 'user' && Array.isArray(actor.roles) && actor.roles.includes('admin'); }
function permissionsOf(actor) {
  if (actor?.actor_type !== 'user') return [];
  if (administrator(actor)) return [...PERMISSIONS, 'applications.permissions.assign', ...ASSIGNMENT_PERMISSIONS, ...AUTHENTICATION_PERMISSIONS,'applications.licensesources.discover'];
  const roles = Array.isArray(actor.roles) ? actor.roles : [];
  return PERMISSIONS.filter(permission => (roles.includes('application-administrator')) || (permission === 'applications.read' && roles.includes('application-reader'))
    || (Array.isArray(actor.permissions) && actor.permissions.includes(permission)))
    .concat(ASSIGNMENT_PERMISSIONS.filter(permission => roles.includes('application-access-administrator')
      || (permission === 'applications.assignments.read' && roles.includes('application-access-reader'))
      || (Array.isArray(actor.permissions) && actor.permissions.includes(permission))))
    .concat(AUTHENTICATION_PERMISSIONS.filter(permission => roles.includes('application-authentication-administrator')
      || (permission === 'applications.authentication.read' && roles.includes('application-authentication-reader'))
      || (Array.isArray(actor.permissions) && actor.permissions.includes(permission))))
    .concat(roles.some(role=>['license-scope-administrator','license-scope-reader'].includes(role))?['applications.licensesources.discover']:[]);
}
function etag(client) { return `"od-client:${client.clientId}:${client.version}"`; }
function publicClient(client) {
  return { clientId: client.clientId, name: client.name, publicClient: client.publicClient, enabled: client.enabled, version: client.version,
    redirectUris: client.redirectUris, grantTypes: client.grantTypes, scopes: client.scopes, createdAt: client.createdAt, updatedAt: client.updatedAt, protected: protectedClient(client) };
}
function mapRow(row) {
  if (!row) return null;
  const client = { clientId: row.id, name: row.name, clientSecretHash: row.secret_hash, publicClient: row.token_endpoint_auth_method === 'none',
    redirectUris: row.redirect_uris, grantTypes: row.grants, scopes: row.scopes, version: String(row.revision), enabled: row.enabled,
    mfaRequired: row.mfa_required, mfaMaxAgeSeconds: row.mfa_max_age_seconds,
    deletedAt: row.deleted_at ? new Date(row.deleted_at).toISOString() : null, createdAt: new Date(row.created_at).toISOString(), updatedAt: new Date(row.updated_at).toISOString() };
  if (!validClient(client) || !['none', 'client_secret_post'].includes(row.token_endpoint_auth_method)) fail(503, 'invalid_client_record');
  return client;
}
function repository(connection) {
  return {
    get: async (id, lock = false) => mapRow((await connection.query('SELECT * FROM oauth_clients WHERE id=$1' + (lock ? ' FOR UPDATE' : ''), [id])).rows[0]),
    list: async (limit = 101) => (await connection.query('SELECT * FROM oauth_clients WHERE deleted_at IS NULL ORDER BY created_at,id LIMIT $1', [limit])).rows.map(mapRow),
    insert: client => connection.query(`INSERT INTO oauth_clients(id,name,secret_hash,redirect_uris,grants,scopes,token_endpoint_auth_method,enabled,mfa_required,mfa_max_age_seconds)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [client.clientId, client.name, client.clientSecretHash, JSON.stringify(client.redirectUris), JSON.stringify(client.grantTypes), JSON.stringify(client.scopes), client.publicClient ? 'none' : 'client_secret_post', client.enabled, client.mfaRequired, client.mfaMaxAgeSeconds]),
    update: client => connection.query(`UPDATE oauth_clients SET name=$2,secret_hash=$3,redirect_uris=$4,grants=$5,scopes=$6,enabled=$7,revision=$8,deleted_at=$9,mfa_required=$10,mfa_max_age_seconds=$11 WHERE id=$1`,
      [client.clientId, client.name, client.clientSecretHash, JSON.stringify(client.redirectUris), JSON.stringify(client.grantTypes), JSON.stringify(client.scopes), client.enabled, client.version, client.deletedAt, client.mfaRequired, client.mfaMaxAgeSeconds]),
    initialized: async () => (await connection.query('SELECT initialized FROM oauth_client_registry WHERE singleton=TRUE FOR UPDATE')).rows[0]?.initialized,
    initialize: () => connection.query('UPDATE oauth_client_registry SET initialized=TRUE WHERE singleton=TRUE AND NOT initialized'),
    audit: (client, action, actor, details = {}) => connection.query(`INSERT INTO oauth_client_audit(client_id,revision,action,actor_issuer,actor_subject,actor_user_id,actor_type,details)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, [client.clientId, client.version, action, actor.iss, actor.sub, actor.identity_authorization?.userId || null, actor.actor_type, JSON.stringify({ ...publicClient(client), ...details })]),
  };
}
function memoryRepository(state) {
  return {
    get: async id => structuredClone(state.clients.get(id) || null),
    list: async (limit = 101) => [...state.clients.values()].filter(client => !client.deletedAt).slice(0, limit).map(client => structuredClone(client)),
    insert: async client => { if (state.clients.has(client.clientId)) fail(409, 'client_exists'); state.clients.set(client.clientId, structuredClone(client)); },
    update: async client => { state.clients.set(client.clientId, structuredClone(client)); },
    initialized: async () => state.initialized,
    initialize: async () => { state.initialized = true; },
    audit: async (client, action, actor, details = {}) => { state.audit.push({ clientId: client.clientId, version: client.version, action, subject: actor.sub, ...details }); },
  };
}
class ClientRegistry {
  constructor(database, { demo = false, production = process.env.NODE_ENV === 'production', seeds = [] } = {}) {
    if (demo && production) throw new Error('In-memory clients are forbidden in production');
    this.database = database; this.demo = demo; this.queue = Promise.resolve(); this.memory = { clients: new Map(), initialized: false, audit: [] };
    if (demo) for (const seed of seeds) { const client = this.seed(seed); this.memory.clients.set(client.clientId, client); }
  }
  seed(seed) {
    if (!seed || Object.keys(seed).some(key => !['clientId','name','clientSecretHash','publicClient','enabled','redirectUris','grantTypes','scopes'].includes(key))) fail(503, 'invalid_client_record');
    const now = new Date().toISOString();
    const client = { ...seed, publicClient: seed.publicClient ?? !seed.clientSecretHash, enabled: seed.enabled ?? true, version: '1', mfaRequired: false, mfaMaxAgeSeconds: 3600, deletedAt: null, createdAt: now, updatedAt: now };
    if (!validClient(client)) fail(503, 'invalid_client_record'); return client;
  }
  async transaction(operation) {
    if (this.demo) {
      const run = async () => { const state = structuredClone(this.memory); const result = await operation(memoryRepository(state)); this.memory = state; return result; };
      const pending = this.queue.then(run, run); this.queue = pending.catch(() => {}); return pending;
    }
    let connection;
    try {
      if (!this.database.isAvailable()) fail(503, 'client_authority_unavailable');
      connection = await this.database.pool.connect(); await connection.query('BEGIN');
      await connection.query("SET LOCAL statement_timeout='1500ms'"); await connection.query("SET LOCAL lock_timeout='1000ms'");
      const result = await operation(repository(connection)); await connection.query('COMMIT'); return result;
    } catch (error) {
      if (connection) await connection.query('ROLLBACK').catch(() => {});
      if (error instanceof ClientError) throw error;
      throw new ClientError(error.code === '23505' ? 409 : 503, error.code === '23505' ? 'client_exists' : 'client_authority_unavailable');
    } finally { connection?.release(); }
  }
  async initialize(seeds, configured, assertConfigured) {
    return this.transaction(async source => {
      const initialized = await source.initialized();
      if (typeof initialized !== 'boolean') fail(503, 'client_authority_unavailable');
      if (!initialized) {
        for (const seed of seeds) {
          const client = this.seed(seed);
          if (!await source.get(client.clientId)) { await source.insert(client); await source.audit(client, 'bootstrap', { iss: 'urn:opendirectory:bootstrap', sub: 'issuer-bootstrap', actor_type: 'bootstrap' }); }
        }
        await source.initialize();
      }
      for (const client of await source.list(10001)) if (!validClient(client)) fail(503, 'invalid_client_record');
      if (configured) assertConfigured(await source.get(configured.clientId), configured);
    });
  }
  async get(id) {
    if (typeof id !== 'string' || !ID.test(id)) return null;
    const client = await this.transaction(source => source.get(id));
    return client && !client.deletedAt ? client : null;
  }
  async licenseSource(id,actor){
    this.actor(actor,'applications.licensesources.discover');if(id==='.'||id==='..')fail(400,'source_client_id_required');const client=await this.get(id);if(!client)fail(404,'source_client_not_found');
    return{schemaVersion:1,clientId:client.clientId,revision:client.version,enabled:client.enabled,
      canReadGroupSources:client.enabled&&!client.publicClient&&JSON.stringify(client.grantTypes)===JSON.stringify(['client_credentials'])&&JSON.stringify(client.scopes)===JSON.stringify(['licenses.groups.derive'])};
  }
  async current(client) { const latest = await this.get(client.clientId); return !!latest?.enabled && latest.version === client.version; }
  async active(payload) {
    if (typeof payload?.client_id !== 'string' || !validRevision(payload.client_revision)) return false;
    const client = await this.get(payload.client_id); return !!client?.enabled && client.version === payload.client_revision && acceptsAuthentication(client, payload);
  }
  authenticated(client, secret, confidential = false) {
    return !!client?.enabled && (client.publicClient ? !confidential && secret === undefined : secretMatches(client.clientSecretHash, secret));
  }
  actor(actor, permission) {
    if (!permissionsOf(actor).includes(permission) || (!this.demo && !validContext(actor.identity_authorization))) fail(403, 'forbidden');
  }
  async list(actor) { this.actor(actor, 'applications.read'); const clients = await this.transaction(source => source.list()); return { clients: clients.slice(0, 100).map(publicClient), truncated: clients.length > 100 }; }
  allowed(actor, before, after) {
    if (!administrator(actor) && (protectedClient(after) || (before && protectedClient(before)))) fail(403, 'protected_client');
  }
  metadata(input, before) {
    if (!input || Array.isArray(input) || typeof input !== 'object' || Object.keys(input).some(key => !['name','redirectUris','scopes','grantTypes','publicClient','enabled'].includes(key))) fail(400, 'invalid_client_metadata');
    if (before && input.publicClient !== undefined && input.publicClient !== before.publicClient) fail(400, 'client_authentication_immutable');
    const client = { ...(before || { clientId: randomUUID(), name: '', publicClient: false, enabled: false, mfaRequired: false, mfaMaxAgeSeconds: 3600, redirectUris: [], scopes: ['openid','profile','email'], grantTypes: ['authorization_code'], version: '1', deletedAt: null }), ...input };
    if (!before) { const now = new Date().toISOString(); client.createdAt = now; client.updatedAt = now; client.clientSecretHash = client.publicClient ? null : hashSecret(randomBytes(32).toString('base64url')); }
    if (!validClient(client)) fail(400, 'invalid_client_metadata'); return client;
  }
  async create(input, actor) {
    this.actor(actor, 'applications.create'); const client = this.metadata(input); this.allowed(actor, null, client);
    if (client.enabled) this.actor(actor, 'applications.update');
    const secret = client.publicClient ? null : randomBytes(32).toString('base64url'); client.clientSecretHash = secret ? hashSecret(secret) : null;
    const stored = await this.transaction(async source => { await source.insert(client); await source.audit(client, 'created', actor); return source.get(client.clientId); });
    return { ...publicClient(stored), clientSecret: secret };
  }
  async mutate(id, match, input, actor, action = 'updated') {
    if (!['updated','rotated','deleted'].includes(action)) fail(400, 'invalid_client_action');
    this.actor(actor, action === 'rotated' ? 'applications.credentials.rotate' : action === 'deleted' ? 'applications.delete' : 'applications.update');
    if (id === actor.client_id) fail(409, 'separate_client_required');
    if (!match) fail(428, 'client_version_required');
    let secret;
    const stored = await this.transaction(async source => {
      const before = await source.get(id, true); if (!before || before.deletedAt) fail(404, 'client_not_found');
      if (match !== etag(before)) fail(412, 'client_version_conflict');
      const client = action === 'updated' ? this.metadata(input, before) : { ...before };
      this.allowed(actor, before, client);
      if (action === 'rotated') { if (client.publicClient) fail(400, 'public_client_has_no_secret'); secret = randomBytes(32).toString('base64url'); client.clientSecretHash = hashSecret(secret); }
      if (action === 'deleted') { client.enabled = false; client.deletedAt = new Date().toISOString(); }
      client.version = (BigInt(before.version) + 1n).toString(); client.updatedAt = new Date().toISOString();
      if (!validRevision(client.version)) fail(409, 'client_generation_exhausted');
      await source.update(client); await source.audit(client, action, actor); return source.get(id);
    });
    return { ...publicClient(stored), ...(secret ? { clientSecret: secret } : {}) };
  }
  authenticationView(client, actor) {
    const allowed = permissionsOf(actor).includes('applications.authentication.manage') && client.clientId !== actor.client_id && (administrator(actor) || !protectedClient(client));
    return { clientId: client.clientId, name: client.name, version: client.version, required: client.mfaRequired, maxAgeSeconds: client.mfaMaxAgeSeconds,
      protected: protectedClient(client), canManage: allowed && freshMfa(actor), requiresFreshMfa: allowed && !freshMfa(actor) };
  }
  async authentication(id, actor) {
    this.actor(actor, 'applications.authentication.read'); const client = await this.get(id);
    if (!client) fail(404, 'client_not_found'); return this.authenticationView(client, actor);
  }
  async setAuthentication(id, match, input, actor) {
    this.actor(actor, 'applications.authentication.manage');
    if (id === actor.client_id) fail(409, 'separate_client_required');
    if (!match) fail(428, 'client_version_required');
    if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== 3
      || Object.keys(input).some(field => !['required','maxAgeSeconds','reason'].includes(field)) || typeof input.required !== 'boolean'
      || !Number.isInteger(input.maxAgeSeconds) || input.maxAgeSeconds < 300 || input.maxAgeSeconds > 86400
      || typeof input.reason !== 'string' || input.reason.trim().length < 10 || input.reason.trim().length > 500 || /[\u0000-\u001f\u007f]/.test(input.reason)) fail(400, 'invalid_authentication_policy');
    return this.transaction(async source => {
      const before = await source.get(id, true); if (!before || before.deletedAt) fail(404, 'client_not_found');
      if (match !== etag(before)) fail(412, 'client_version_conflict'); this.allowed(actor, before, before);
      if (!freshMfa(actor)) fail(428, 'fresh_mfa_required');
      const client = { ...before, mfaRequired: input.required, mfaMaxAgeSeconds: input.maxAgeSeconds, version: String(BigInt(before.version) + 1n), updatedAt: new Date().toISOString() };
      if (!validRevision(client.version)) fail(409, 'client_generation_exhausted');
      await source.update(client); await source.audit(client, 'authentication_changed', actor, { reason: input.reason.trim(), authentication: { required: client.mfaRequired, maxAgeSeconds: client.mfaMaxAgeSeconds } });
      return this.authenticationView(await source.get(id), actor);
    });
  }
}
module.exports = { ClientRegistry, ClientError, validClient, publicClient, protectedClient, mapRow, permissionsOf, administrator, etag, GRANTS, SAFE_SCOPES };
