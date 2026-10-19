'use strict';

const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { CompanyBlueprintAuthority } = require('./CompanyBlueprintAuthority');
const { CompanyLicenseAuthority } = require('./licenses/CompanyLicenseAuthority');
const { resolveConfigurations } = require('./BlueprintPreview');
const { COMPANY_BLUEPRINT_PERMISSIONS, identifier, versionNumber, writeValues, commandValues, expectedRevision, pagination } = require('../../../../packages/company-blueprint-contract');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function storageError(error) {
  if (error.status) return error;
  const status = ({ P0002: 404, '40001': 412, '23505': 409, '23514': 409, '22003': 409, '22P02': 400, '55P03': 409 }[error.code]) || 503;
  return Object.assign(new Error(status >= 500 ? 'Company blueprint storage or receiving evidence unavailable' : error.message, { cause: error }), { status });
}
function envelope(source) { return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id }; }
function summary(row) {
  return { id: row.id, tenantId: row.tenant_id, name: row.draft.name, platform: row.draft.platform, revision: String(row.revision), publishedVersion: row.published_version,
    draftChanged: row.draft_changed, configurationCount: row.draft.configurations.length, appCount: row.draft.appPoolIds.length, createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString() };
}
function release(row) {
  return { version: row.version, sourceRevision: String(row.source_revision), publishedRevision: String(row.published_revision), actorUserId: row.actor_user_id, operationId: row.operation_id, createdAt: row.created_at.toISOString() };
}
const HEAD = `SELECT head.*,head.published_version IS NULL OR head.draft IS DISTINCT FROM (SELECT draft FROM company_blueprint_versions WHERE blueprint_id=head.id AND version=head.published_version) AS draft_changed FROM company_blueprints head`;
class CompanyBlueprints {
  constructor(database, { authority = new CompanyBlueprintAuthority(), applicationAuthority = new CompanyLicenseAuthority() } = {}) { this.database = database; this.authority = authority; this.applicationAuthority = applicationAuthority; }
  async unchanged(source, user, authorization, applicationSource = null) {
    const current = await this.authority.read(authorization, user);
    if (!isDeepStrictEqual(current, source) || source.validUntil * 1000 <= Date.now()) fail(401, 'Original company blueprint authority changed');
    if (applicationSource) {
      const application = await this.applicationAuthority.read(authorization, user);
      if (!isDeepStrictEqual(application, applicationSource) || application.validUntil * 1000 <= Date.now()) fail(401, 'Original company app authority changed');
    }
  }
  async observe(user, authorization, operation) {
    const source = await this.authority.read(authorization, user); const client = await this.database.getClient();
    try {
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'); await client.query("SET LOCAL statement_timeout='5s'");
      await client.query('SELECT company_blueprint_receiving()');
      const result = await operation(client, source); await this.unchanged(source, user, authorization); await client.query('COMMIT'); await this.unchanged(source, user, authorization); return result;
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw storageError(error); } finally { client.release(); }
  }
  async capabilities(user, authorization) {
    return this.observe(user, authorization, async (_client, source) => ({ ...envelope(source), companyBlueprintProtocol: 1, permissions: [...COMPANY_BLUEPRINT_PERMISSIONS], configurationMode: 'local-only', maxConfigurations: 25, maxApplications: 25 }));
  }
  async own(client, id, source) {
    const row = (await client.query(HEAD + ' WHERE head.id=$1 AND head.tenant_id=$2', [id, source.tenant.id])).rows[0];
    if (!row) fail(404, 'Own company blueprint not found'); return row;
  }
  async list(query, user, authorization) {
    const { page, limit, search } = pagination(query, true);
    return this.observe(user, authorization, async (client, source) => {
      const where = " WHERE head.tenant_id=$1 AND ($2='' OR strpos(lower(head.draft->>'name'),lower($2))>0)"; const parameters = [source.tenant.id, search];
      const total = (await client.query('SELECT count(*)::integer AS total FROM company_blueprints head' + where, parameters)).rows[0].total;
      const rows = (await client.query(HEAD + where + ' ORDER BY head.draft->>\'name\',head.id LIMIT $3 OFFSET $4', [...parameters, limit, (page - 1) * limit])).rows;
      return { ...envelope(source), blueprints: rows.map(summary), total, page, limit };
    });
  }
  async get(id, user, authorization) {
    identifier(id);
    return this.observe(user, authorization, async (client, source) => {
      const row = await this.own(client, id, source);
      const configurations = (await client.query(`SELECT configuration->>'id' AS id,$2::text AS blueprint_id,configuration->>'type' AS config_type,
        ((configuration->>'payloadJson')::jsonb)::text AS payload_json,dense_rank() OVER(PARTITION BY configuration->>'type' ORDER BY (configuration->>'payloadJson')::jsonb)::text AS payload_rank
        FROM company_blueprints head CROSS JOIN LATERAL jsonb_array_elements(head.draft->'configurations') configuration WHERE head.id=$1 AND head.tenant_id=$3 ORDER BY configuration->>'id'`, [id, id, source.tenant.id])).rows;
      return { ...envelope(source), blueprint: { id: row.id, tenantId: row.tenant_id, revision: String(row.revision), publishedVersion: row.published_version, draftChanged: row.draft_changed,
        draft: row.draft, createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString(), preview: resolveConfigurations(configurations) } };
    });
  }
  async versions(id, query, user, authorization) {
    identifier(id); const { page, limit } = pagination(query);
    return this.observe(user, authorization, async (client, source) => {
      await this.own(client, id, source);
      const total = (await client.query('SELECT count(*)::integer AS total FROM company_blueprint_versions WHERE blueprint_id=$1 AND tenant_id=$2', [id, source.tenant.id])).rows[0].total;
      const rows = (await client.query('SELECT * FROM company_blueprint_versions WHERE blueprint_id=$1 AND tenant_id=$2 ORDER BY version DESC LIMIT $3 OFFSET $4', [id, source.tenant.id, limit, (page - 1) * limit])).rows;
      return { ...envelope(source), blueprintId: id, versions: rows.map(release), total, page, limit };
    });
  }
  async version(id, ordinal, user, authorization) {
    identifier(id); ordinal = versionNumber(ordinal);
    return this.observe(user, authorization, async (client, source) => {
      await this.own(client, id, source);
      const row = (await client.query('SELECT * FROM company_blueprint_versions WHERE blueprint_id=$1 AND tenant_id=$2 AND version=$3', [id, source.tenant.id, ordinal])).rows[0];
      if (!row) fail(404, 'Own company blueprint version not found');
      return { ...envelope(source), blueprintId: id, version: { ...release(row), draft: row.draft, apps: row.apps } };
    });
  }
  async history(id, query, user, authorization) {
    identifier(id); const { page, limit } = pagination(query);
    return this.observe(user, authorization, async (client, source) => {
      await this.own(client, id, source);
      const total = (await client.query('SELECT count(*)::integer AS total FROM company_blueprint_events WHERE blueprint_id=$1 AND tenant_id=$2', [id, source.tenant.id])).rows[0].total;
      const rows = (await client.query('SELECT * FROM company_blueprint_events WHERE blueprint_id=$1 AND tenant_id=$2 ORDER BY after_revision DESC LIMIT $3 OFFSET $4', [id, source.tenant.id, limit, (page - 1) * limit])).rows;
      return { ...envelope(source), blueprintId: id, events: rows.map(row => ({ id: row.id, tenantId: row.tenant_id, type: row.type, version: 1, blueprintId: row.blueprint_id,
        actorUserId: row.actor_user_id, correlationId: row.correlation_id, createdAt: row.created_at.toISOString(), beforeRevision: row.before_revision === null ? null : String(row.before_revision),
        afterRevision: String(row.after_revision), releasedVersion: row.released_version, restoredFrom: row.restored_from, reason: row.reason, deliveryStatus: 'pending' })), total, page, limit };
    });
  }
  async change(action, id, input, tag, operationId, user, authorization, correlationId = randomUUID()) {
    const values = writeValues(action, input); id = action === 'created' ? values.id : identifier(id); identifier(operationId); identifier(correlationId);
    const command = { id: operationId, correlationId, blueprintId: id, action, expectedRevision: action === 'created' ? '0' : expectedRevision(id, tag), reason: values.reason,
      draft: values.draft || null, version: values.version || null }; commandValues(command);
    const source = await this.authority.read(authorization, user); const client = await this.database.getClient(); let applicationSource = null;
    try {
      await client.query('BEGIN'); await client.query("SET LOCAL statement_timeout='5s';SET LOCAL lock_timeout='4s'"); await client.query('SELECT company_blueprint_receiving()');
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [operationId]);
      const prior = (await client.query('SELECT id FROM company_blueprint_operations WHERE id=$1', [operationId])).rows[0];
      if (!prior) {
        let document = command.draft;
        if (!document) {
          const head = await this.own(client, id, source); document = head.draft;
          if (action === 'restored') {
            const row = (await client.query('SELECT draft FROM company_blueprint_versions WHERE blueprint_id=$1 AND tenant_id=$2 AND version=$3', [id, source.tenant.id, command.version])).rows[0];
            if (!row) fail(404, 'Own company blueprint version not found'); document = row.draft;
          }
        }
        if (document.appPoolIds.length) {
          applicationSource = await this.applicationAuthority.read(authorization, user);
          if (!isDeepStrictEqual(Object.fromEntries(['issuer', 'subject', 'tokenId', 'expiresAt', 'context', 'tenant', 'actorUserId', 'schemaVersion'].map(field => [field, applicationSource[field]])),
              Object.fromEntries(['issuer', 'subject', 'tokenId', 'expiresAt', 'context', 'tenant', 'actorUserId', 'schemaVersion'].map(field => [field, source[field]])))) fail(401, 'Independent app authority does not match the original actor');
          if (applicationSource.target !== null) fail(401, 'Untargeted original app authority required');
        }
      }
      await this.unchanged(source, user, authorization, applicationSource);
      const result = (await client.query('SELECT company_blueprint_change($1::jsonb,$2::jsonb,$3::jsonb) AS result', [source, applicationSource, command])).rows[0].result;
      await this.unchanged(source, user, authorization, applicationSource); await client.query('COMMIT'); await this.unchanged(source, user, authorization, applicationSource); return result;
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw storageError(error); } finally { client.release(); }
  }
}
module.exports = { CompanyBlueprints };
