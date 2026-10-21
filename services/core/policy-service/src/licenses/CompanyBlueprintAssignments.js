'use strict';

const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { CompanyBlueprintAssignmentAuthority } = require('./CompanyBlueprintAssignmentAuthority');
const { CompanyLicenseAuthority } = require('./CompanyLicenseAuthority');
const { LicenseAllocator } = require('./LicenseAllocator');
const { companyLicenseContext } = require('./CompanyLicenseContext');
const { principalContext } = require('./LicensePrincipal');
const { COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS, validSource, exact, identifier, revision, text, versionNumber, pagination } = require('../../../../../packages/company-blueprint-assignment-contract');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function storageError(error) {
  if (error.status) return error;
  return Object.assign(new Error(error.code === '42501' ? 'Purpose-bound company assignment evidence unavailable' : error.message), { status: ({ P0002: 404, '40001': 412, '23505': 409, '23514': 409, '55P03': 409, '22P02': 400, '22003': 409 }[error.code]) || 503, cause: error });
}
function envelope(source) { return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id }; }
function validApplicationSource(source, user, userId) {
  try {
    exact(source, ['schemaVersion', 'issuer', 'subject', 'tokenId', 'expiresAt', 'context', 'tenant', 'actorUserId', 'permissions', 'validUntil', 'target']);
    return JSON.stringify(source.permissions) === JSON.stringify(['company.apps.read', 'company.apps.create', 'company.apps.assign'])
      && validSource({ ...source, companyBlueprintAssignmentsProtocol: 1, permissions: [...COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS] }, user, userId);
  } catch { return false; }
}
function captures(values, maximum = 25) {
  if (!Array.isArray(values) || values.length > maximum) fail(400, 'Bounded complete pool captures required');
  const seen = new Set();
  return values.map(item => { exact(item, ['poolId', 'poolRevision']); identifier(item.poolId); revision(item.poolRevision); if (seen.has(item.poolId)) fail(400, 'Duplicate pool capture'); seen.add(item.poolId); return { ...item }; });
}
function ownConfigurations(rows) {
  if (rows.length > 1000) fail(409, 'Own effective configuration limit reached');
  const identities = new Set(); const groups = new Map(); let bytes = 0;
  for (const row of rows) {
    const identity = `${row.blueprint_id}:${row.id}`;
    if (identities.has(identity)) fail(503, 'Duplicate own configuration provenance'); identities.add(identity);
    bytes += Buffer.byteLength(row.payload_json); if (bytes > 1048576) fail(409, 'Own effective payload limit reached');
    if (!groups.has(row.config_type)) groups.set(row.config_type, new Map());
    const variants = groups.get(row.config_type); const rank = String(row.payload_rank);
    if (!variants.has(rank)) variants.set(rank, { payloadJson: row.payload_json, sources: [] });
    variants.get(rank).sources.push({ blueprintId: row.blueprint_id, configurationId: row.id });
  }
  const effectiveConfigurations = []; const conflicts = [];
  for (const configType of [...groups.keys()].sort()) {
    const variants = [...groups.get(configType)].sort(([left], [right]) => Number(left) - Number(right)).map(([, variant]) => variant);
    if (variants.length > 1) conflicts.push({ configType, variants }); else effectiveConfigurations.push({ configType, ...variants[0] });
  }
  return { effectiveConfigurations, conflicts, hasConflicts: conflicts.length > 0 };
}
class CompanyBlueprintAssignments {
  constructor(database, { allocator = new LicenseAllocator(database), authority = new CompanyBlueprintAssignmentAuthority(), applicationAuthority = new CompanyLicenseAuthority() } = {}) {
    this.database = database; this.allocator = allocator; this.authority = authority; this.applicationAuthority = applicationAuthority;
    if (allocator.database !== database) fail(503, 'Original allocator database required');
  }
  async source(user, authorization, userId = null) {
    if (typeof authorization !== 'string' || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization) || authorization.length > 16384) fail(401, 'Original assignment bearer required');
    const source = await this.authority.read(authorization, user, userId);
    if (!validSource(source, user, userId)) fail(503, 'Invalid original assignment source'); return source;
  }
  async unchanged(source, applicationSource, user, authorization) {
    if (source && !isDeepStrictEqual(source, await this.source(user, authorization, source.target?.id || null))) fail(401, 'Original assignment authority changed');
    if (applicationSource && (!validApplicationSource(applicationSource, user, applicationSource.target.id) || !isDeepStrictEqual(applicationSource, await this.applicationAuthority.read(authorization, user, applicationSource.target.id)))) fail(401, 'Original application authority changed');
  }
  async appSource(source, user, authorization, userId) {
    const application = await this.applicationAuthority.read(authorization, user, userId);
    if (!validApplicationSource(application, user, userId)) fail(503, 'Invalid original application source');
    const { companyBlueprintAssignmentsProtocol, permissions, validUntil, ...base } = source;
    if (!isDeepStrictEqual(base, Object.fromEntries(Object.entries(application).filter(([field]) => !['permissions', 'validUntil'].includes(field))))) fail(401, 'Independent application actor does not match');
    return application;
  }
  async observe(user, authorization, userId, operation) {
    const source = await this.source(user, authorization, userId); const client = await this.database.getClient(); let applicationSource = null;
    try {
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'); await client.query("SET LOCAL statement_timeout='5s'"); await client.query('SELECT company_blueprint_assignment_receiving()');
      const applications = async () => { applicationSource ||= await this.appSource(source, user, authorization, userId); return applicationSource; };
      const result = await operation(client, source, applications);
      if (Buffer.byteLength(JSON.stringify(result)) > 2097152) fail(409, 'Own assignment response limit reached');
      await this.unchanged(source, applicationSource, user, authorization); await client.query('COMMIT'); await this.unchanged(source, applicationSource, user, authorization); return result;
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw storageError(error); } finally { client.release(); }
  }
  async capabilities(user, authorization) {
    return this.observe(user, authorization, null, async (_client, source) => ({ ...envelope(source), companyBlueprintAssignmentsProtocol: 1, permissions: [...COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS], configurationMode: 'local-only', allocationMode: 'local-only', supportedTargets: ['user'], maxApplications: 25 }));
  }
  async own(client, id, source) {
    const row = (await client.query('SELECT binding.*,company_blueprint_assignment_view(binding) AS value,company_blueprint_assignment_binding_valid(binding) AS valid FROM company_blueprint_user_assignments binding WHERE id=$1 AND tenant_id=$2', [id, source.tenant.id])).rows[0];
    if (!row) fail(404, 'Own blueprint user assignment not found'); if (!row.valid) fail(503, 'Original binding evidence unavailable'); return row;
  }
  async list(query, user, authorization) {
    exact(Object.fromEntries(Object.entries(query).filter(([field]) => !['page', 'limit'].includes(field))), ['userId']); identifier(query.userId);
    const { page, limit } = pagination(Object.fromEntries(Object.entries(query).filter(([field]) => field !== 'userId')));
    return this.observe(user, authorization, query.userId, async (client, source) => {
      const total = (await client.query('SELECT count(*)::integer AS total FROM company_blueprint_user_assignments WHERE tenant_id=$1 AND user_id=$2', [source.tenant.id, query.userId])).rows[0].total;
      const rows = (await client.query('SELECT company_blueprint_assignment_view(binding) AS value,company_blueprint_assignment_binding_valid(binding) AS valid FROM company_blueprint_user_assignments binding WHERE tenant_id=$1 AND user_id=$2 ORDER BY created_at DESC,id LIMIT $3 OFFSET $4', [source.tenant.id, query.userId, limit, (page - 1) * limit])).rows;
      if (rows.some(row => !row.valid)) fail(503, 'Original binding evidence unavailable');
      return { ...envelope(source), userId: query.userId, assignments: rows.map(row => row.value), page, limit, total };
    });
  }
  async get(id, user, authorization) { identifier(id); return this.observe(user, authorization, null, async (client, source) => ({ ...envelope(source), assignment: (await this.own(client, id, source)).value })); }
  async active(client, source, userId, excluded = null) {
    const rows = (await client.query("SELECT binding.*,company_blueprint_assignment_view(binding) AS value,company_blueprint_assignment_binding_valid(binding) AS valid FROM company_blueprint_user_assignments binding WHERE tenant_id=$1 AND user_id=$2 AND status='active' AND ($3::uuid IS NULL OR id<>$3) ORDER BY blueprint_id LIMIT 1001", [source.tenant.id, userId, excluded])).rows;
    if (rows.length > 1000) fail(409, 'Own effective binding limit reached'); if (rows.some(row => !row.valid)) fail(503, 'Original binding evidence unavailable'); return rows;
  }
  async configuration(client, bindings, candidate = null) {
    const selected = bindings.map(binding => ({ blueprintId: binding.blueprint_id, version: binding.version })); if (candidate) selected.push(candidate);
    const rows = (await client.query(`SELECT configuration->>'id' AS id,release.blueprint_id::text AS blueprint_id,configuration->>'type' AS config_type,((configuration->>'payloadJson')::jsonb)::text AS payload_json,
      dense_rank() OVER(PARTITION BY configuration->>'type' ORDER BY (configuration->>'payloadJson')::jsonb)::text AS payload_rank
      FROM jsonb_to_recordset($1::jsonb) selection("blueprintId" uuid,version integer) JOIN company_blueprint_versions release ON release.blueprint_id=selection."blueprintId" AND release.version=selection.version
      CROSS JOIN LATERAL jsonb_array_elements(release.draft->'configurations') configuration ORDER BY release.blueprint_id,configuration->>'id' LIMIT 1001`, [JSON.stringify(selected)])).rows;
    return ownConfigurations(rows);
  }
  async pools(client, source, poolIds) {
    const result = [];
    for (const poolId of [...poolIds].sort()) {
      const row = (await client.query('SELECT catalog.*,license_company_pool_valid(id) AS valid FROM license_catalog catalog WHERE id=$1 AND business_tenant_id=$2', [poolId, source.tenant.id])).rows[0];
      if (!row) fail(404, 'Own app pool not found'); if (!row.valid) fail(503, 'Canonical pool evidence unavailable');
      const existing = (await client.query("SELECT eligibility_revision FROM license_assignments WHERE license_id=$1 AND assignee_type='user' AND assignee_id=$2", [poolId, source.target.id])).rows[0];
      result.push({ poolId, poolRevision: String(row.business_revision), totalSeats: row.total_seats, usedSeats: row.used_seats, availableSeats: row.total_seats - row.used_seats, additionalSeats: existing ? 0 : 1 });
    }
    return result;
  }
  async preview(input, user, authorization) {
    exact(input, ['userId', 'blueprintId', 'version']); identifier(input.userId); identifier(input.blueprintId); const version = versionNumber(input.version);
    return this.observe(user, authorization, input.userId, async (client, source, applications) => {
      if (!source.target.enabled || source.target.deleted) fail(403, 'Enabled original employee required');
      const bindings = await this.active(client, source, input.userId); if (bindings.some(binding => binding.blueprint_id === input.blueprintId)) fail(409, 'Blueprint already assigned; remove the original binding first');
      if (bindings.some(binding => String(binding.eligibility_revision) !== source.target.eligibilityRevision)) fail(409, 'Original binding generation requires explicit cleanup');
      const release = (await client.query('SELECT * FROM company_blueprint_versions WHERE blueprint_id=$1 AND tenant_id=$2 AND version=$3', [input.blueprintId, source.tenant.id, version])).rows[0];
      if (!release) fail(404, 'Own immutable blueprint version not found');
      if (release.draft.appPoolIds.length) await applications(); const pools = await this.pools(client, source, release.draft.appPoolIds);
      return { ...envelope(source), userId: input.userId, blueprintId: input.blueprintId, version, eligibilityRevision: source.target.eligibilityRevision, pools, ...await this.configuration(client, bindings, { blueprintId: input.blueprintId, version }) };
    });
  }
  async removalPreview(id, user, authorization) {
    identifier(id); const base = await this.source(user, authorization); const metadata = await this.observe(user, authorization, null, async (client, source) => (await this.own(client, id, source)).value);
    return this.observe(user, authorization, metadata.userId, async (client, source, applications) => {
      if (base.actorUserId !== source.actorUserId || base.tenant.id !== source.tenant.id) fail(401, 'Original removal actor changed'); const binding = (await this.own(client, id, source)).value;
      if (binding.status !== 'active') fail(409, 'Original active binding required'); if (binding.appPoolIds.length) await applications();
      return { ...envelope(source), assignment: binding, eligibilityRevision: source.target.eligibilityRevision, pools: (await this.pools(client, source, binding.appPoolIds)).map(({ poolId, poolRevision }) => ({ poolId, poolRevision })) };
    });
  }
  async effective(userId, user, authorization) {
    identifier(userId);
    return this.observe(user, authorization, userId, async (client, source, applications) => {
      const all = await this.active(client, source, userId); const bindings = source.target.enabled && !source.target.deleted ? all.filter(binding => String(binding.eligibility_revision) === source.target.eligibilityRevision) : [];
      const poolIds = [...new Set(bindings.flatMap(binding => binding.value.appPoolIds))].sort();
      if (poolIds.length) { await applications(); await this.pools(client, source, poolIds); } const apps = [];
      for (const poolId of poolIds) apps.push({ poolId, sources: (await client.query('SELECT license_company_sources($1,$2) AS sources', [poolId, userId])).rows[0].sources });
      return { ...envelope(source), userId, assignments: bindings.map(binding => binding.value), ...await this.configuration(client, bindings), applications: apps };
    });
  }
  async change(action, id, input, tag, operationId, user, authorization, correlationId = randomUUID(), checks = {}) {
    identifier(operationId); identifier(correlationId); if (!['assigned', 'removed'].includes(action)) fail(400, 'Unsupported own assignment action');
    exact(input, action === 'assigned' ? ['id', 'userId', 'blueprintId', 'version', 'eligibilityRevision', 'pools', 'reason', 'confirm'] : ['userId', 'eligibilityRevision', 'pools', 'reason', 'confirm']);
    if (input.confirm !== true) fail(400, 'Explicit assignment confirmation required'); identifier(input.userId); revision(input.eligibilityRevision); text(input.reason, 10, 500);
    id = identifier(action === 'assigned' ? input.id : id); let expectedRevision = '0';
    if (action === 'removed') { if (tag === undefined) fail(428, 'Original assignment If-Match required'); const match = typeof tag === 'string' && /^"company-blueprint-assignment-([a-f0-9-]{36})-([1-9][0-9]{0,18})"$/.exec(tag); if (!match || match[1] !== id) fail(412, 'Original assignment version changed'); expectedRevision = revision(match[2]); }
    const command = { id: operationId, correlationId, action, assignmentId: id, expectedRevision, userId: input.userId, eligibilityRevision: input.eligibilityRevision,
      blueprintId: action === 'assigned' ? identifier(input.blueprintId) : null, version: action === 'assigned' ? versionNumber(input.version) : null, pools: captures(input.pools), reason: input.reason, values: null };
    return this.execute(command, user, authorization, checks);
  }
  async execute(command, user, authorization, supplied = {}) {
    identifier(command.id); identifier(command.userId); const applicationNeeded = command.pools.length > 0;
    const sourceNeeded = ['assigned', 'removed'].includes(command.action) || command.action === 'retire_sources' && command.values.bindings.length > 0;
    const source = sourceNeeded ? supplied.source || await this.source(user, authorization, command.userId) : null;
    if (source && !validSource(source, user, command.userId)) fail(503, 'Original assignment source invalid');
    const applicationSource = applicationNeeded ? supplied.applicationSource || await this.applicationAuthority.read(authorization, user, command.userId) : null;
    if (applicationSource && !validApplicationSource(applicationSource, user, command.userId)) fail(503, 'Invalid original application source');
    if (source && applicationSource) await this.appSource(source, user, authorization, command.userId);
    const actor = source || applicationSource; if (!actor) fail(403, 'Original assignment authority required');
    const principal = { issuer: actor.issuer, subject: actor.subject, userId: actor.actorUserId, enabled: true }; let result;
    const scope = { database: this.database, tenantId: actor.tenant.id, licenseId: null, actorUserId: actor.actorUserId, targetUserId: command.userId,
      verify: async (client, after) => {
        await this.unchanged(source, applicationSource, user, authorization);
        if (!after) await client.query('SELECT company_blueprint_assignment_begin($1::jsonb,$2::jsonb,$3::jsonb)', [source, applicationSource, command]);
        if (supplied.verify) await supplied.verify(client, after, command);
      },
      complete: async client => { result = (await client.query('SELECT company_blueprint_assignment_finish($1) AS result', [command.id])).rows[0].result; },
      eligibility: async userId => { if (userId !== command.userId) fail(403, 'Recipient outside original assignment'); return { schemaVersion: 1, userId, revision: actor.target.eligibilityRevision, enabled: actor.target.enabled, deleted: actor.target.deleted }; },
    };
    try {
      await principalContext.run(principal, () => companyLicenseContext.run(scope, () => this.allocator.transaction(async client => {
        if ((await client.query('SELECT id FROM company_blueprint_assignment_events WHERE id=$1', [command.id])).rows.length) return;
        if (command.action === 'assigned') {
          const other = await this.active(client, actor, command.userId, command.assignmentId);
          if ((await this.configuration(client, other, { blueprintId: command.blueprintId, version: command.version })).hasConflicts) fail(409, 'Own assigned configuration conflict');
        }
        for (const capture of [...command.pools].sort((left, right) => left.poolId.localeCompare(right.poolId))) {
          const child = (await client.query('SELECT license_company_p2_begin($1,$2) AS id', [command.id, capture.poolId])).rows[0].id;
          await companyLicenseContext.run({ ...scope, licenseId: capture.poolId }, async () => {
            const positive = ['assigned', 'manual_assign'].includes(command.action);
            const snapshots = positive ? await this.allocator.users.active([command.userId], { authorization }) : [];
            await this.allocator.lockSubjects(client, actor.actorUserId, positive ? [command.userId] : [], snapshots); const license = await this.allocator.lockLicense(client, capture.poolId); await this.allocator.authorizeOperation(client, license.id, 'assignments.manage');
            const current = await this.allocator.findAssignment(client, license.id, { assignee_type: 'user', assignee_id: command.userId });
            if (positive && current && String(current.eligibility_revision) !== command.eligibilityRevision) fail(409, 'Existing grant incarnation requires explicit withdrawal');
            if (positive) {
              if (!current && await this.allocator.count(client, license.id) >= license.total_seats) fail(409, 'No seats available for complete blueprint');
              await client.query('INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by) VALUES($1,$2,$3,$4,$5)', [license.id, command.userId, command.action === 'assigned' ? 'blueprint' : 'direct', command.action === 'assigned' ? command.assignmentId : 'direct', actor.actorUserId]);
            } else if (command.action === 'retire_sources') {
              await client.query('DELETE FROM license_assignment_sources WHERE license_id=$1 AND user_id=$2', [license.id, command.userId]);
            } else {
              const removed = await client.query('DELETE FROM license_assignment_sources WHERE license_id=$1 AND user_id=$2 AND source_type=$3 AND source_id=$4 RETURNING grant_id', [license.id, command.userId, command.action === 'removed' ? 'blueprint' : 'direct', command.action === 'removed' ? command.assignmentId : 'direct']);
              if (removed.rows.length !== 1) fail(409, 'Original source incarnation changed');
            }
            await this.allocator.syncUser(client, license.id, command.userId, actor.actorUserId); await this.allocator.syncCounter(client, license.id);
            const details = command.action === 'retire_sources' ? (await client.query("SELECT jsonb_build_object('userId',target_user_id,'assignmentId',before_state#>'{assignment,id}','sources',before_state->'sources') AS value FROM license_company_commands WHERE id=$1", [child])).rows[0].value : (await client.query('SELECT license_company_p2_result($1) AS value', [child])).rows[0].value;
            await this.allocator.audit(client, license.id, command.action === 'retire_sources' ? 'company-sources-retired' : 'company-source-change', actor.actorUserId, details); await client.query('SELECT license_company_p2_finish($1)', [child]);
          });
        }
      })));
      await this.unchanged(source, applicationSource, user, authorization); return result;
    } catch (error) { throw storageError(error); }
  }
}
module.exports = { CompanyBlueprintAssignments, ownConfigurations };
