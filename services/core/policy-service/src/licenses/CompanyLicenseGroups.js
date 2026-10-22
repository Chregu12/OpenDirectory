'use strict';
const { randomUUID, createHash } = require('node:crypto');
const { v5 } = require('uuid');
const { identifier, exact } = require('../../../../../packages/company-license-contract');
const { linkValues, syncValues, unlinkValues } = require('../../../../../packages/company-license-group-contract');
const { CompanyBlueprints } = require('../CompanyBlueprints');
const { CompanyBlueprintAssignments } = require('./CompanyBlueprintAssignments');
const { GroupSnapshotClient } = require('./GroupSnapshotClient');
function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function envelope(source) { return { schemaVersion: 1, companyLicenseGroupsProtocol: 1, actorUserId: source.kind === 'application' ? null : source.actorUserId, tenantId: source.tenant.id, allocationMode: 'local-only',
  ...(source.kind === 'application' ? { actor: { kind: 'application', id: source.grantId, clientId: source.subject, clientRevision: source.clientRevision } } : {}) }; }
function view(row) { return { id: row.id, tenantId: row.tenant_id, groupId: row.group_id, poolId: row.pool_id, blueprintId: row.blueprint_id,
  status: row.status, revision: String(row.revision), createdAt: new Date(row.created_at).toISOString(), updatedAt: new Date(row.updated_at).toISOString() }; }
class CompanyLicenseGroups {
  constructor(companies, { blueprints = new CompanyBlueprints(companies.database), assignments = new CompanyBlueprintAssignments(companies.database, { allocator: companies.allocator }), groups = new GroupSnapshotClient(), correlationId = null } = {}) {
    this.companies = companies; this.database = companies.database; this.blueprints = blueprints; this.assignments = assignments; this.groups = groups; this.correlationId = correlationId;
  }
  async rule(client, id, source) {
    identifier(id); await client.query('SELECT company_license_group_receiving()');
    const row = (await client.query(`SELECT rule.* FROM company_license_groups rule WHERE id=$1 AND tenant_id=$2
      AND EXISTS(SELECT 1 FROM company_license_group_events event JOIN company_license_group_outbox box ON box.id=event.id
        WHERE event.rule_id=rule.id AND event.result-'created_at'-'updated_at'=to_jsonb(rule)-'created_at'-'updated_at'
          AND (event.result->>'created_at')::timestamptz=rule.created_at AND (event.result->>'updated_at')::timestamptz=rule.updated_at AND box.status='pending')`, [id, source.tenant.id])).rows[0];
    if (!row) fail(404, 'Own license group not found'); return row;
  }
  async snapshot(rule, source, authorization) {
    if (rule.status === 'unlinked') return null;
    if (source.kind === 'application') {
      if (typeof this.groups.machineSnapshot !== 'function') fail(403, 'Purpose-bound app group source required');
      const proof = await this.groups.machineSnapshot(authorization);
      if (proof.kind !== 'application' || proof.grantId !== source.grantId || proof.jobId !== source.jobId || proof.ruleId !== rule.id || proof.tenant.id !== rule.tenant_id || proof.group?.groupId !== rule.group_id || proof.group.unresolvedMemberIds.length) fail(503, 'Complete own app group source required');
      return { ...proof.group, hash: createHash('sha256').update(JSON.stringify(proof.group)).digest('hex'), validUntil: new Date(proof.validUntil * 1000).toISOString() };
    }
    const group = await this.groups.snapshot(rule.group_id, authorization, true);
    if (group.viewerUserId !== source.actorUserId || group.viewerEnabled !== true || group.sourceAuthorization !== null) fail(403, 'Original company license group viewer required');
    return group;
  }
  async bindings(client, rule) {
    const rows = (await client.query(`SELECT binding.*,company_blueprint_assignment_binding_valid(binding) AS valid FROM company_blueprint_user_assignments binding
      WHERE tenant_id=$1 AND blueprint_id=$2 AND status='active' ORDER BY user_id`, [rule.tenant_id, rule.blueprint_id])).rows;
    if (rows.some(row => row.valid !== true) || rows.length > 10000) fail(503, 'Complete license group bindings unavailable'); return rows;
  }
  async list(query, user, authorization) {
    if (Object.keys(query).some(key => key !== 'groupId')) fail(400, 'Unsupported license group selector'); if (query.groupId !== undefined) identifier(query.groupId);
    return this.companies.read(user, authorization, async (client, source) => {
      await client.query('SELECT company_license_group_receiving()');
      const rows = (await client.query('SELECT * FROM company_license_groups WHERE tenant_id=$1 AND ($2::uuid IS NULL OR group_id=$2::uuid) ORDER BY created_at,id LIMIT 101', [source.tenant.id, query.groupId || null])).rows;
      for (const row of rows) await this.rule(client, row.id, source);
      return { ...envelope(source), rules: rows.slice(0, 100).map(view), truncated: rows.length > 100 };
    });
  }
  async write(source, operationId, id, values, blueprintId, user, authorization) {
    const client = await this.database.getClient();
    try {
      await client.query('BEGIN'); await client.query("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'");
      await this.companies.unchanged(source, user, authorization);
      const result = (await client.query('SELECT company_license_group_write($1::jsonb,$2::uuid,$3::uuid,$4::jsonb,$5::uuid) AS result', [source, operationId, id, values, blueprintId])).rows[0].result;
      await this.companies.unchanged(source, user, authorization); await client.query('COMMIT');
      await this.companies.unchanged(source, user, authorization); return { ...envelope(source), rule: view(result) };
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; } finally { client.release(); }
  }
  async link(input, operationId, user, authorization) {
    const values = linkValues(input); identifier(operationId); const id = v5('license-group', operationId); const blueprintId = v5('license-blueprint', operationId);
    const source = await this.companies.authority.read(authorization, user);
    await this.database.query('SELECT company_license_group_receiving()');
    const prior = (await this.database.query('SELECT * FROM company_license_group_events WHERE id=$1 AND tenant_id=$2', [operationId, source.tenant.id])).rows[0];
    if (prior) return this.write(source, operationId, id, values, blueprintId, user, authorization);
    const candidate = { group_id: values.groupId, status: 'active' };
    const group = await this.snapshot(candidate, source, authorization); if (group.deleted) fail(404, 'Current directory group required');
    await this.companies.ownPool(this.database, values.poolId, source.tenant.id);
    if ((await this.database.query("SELECT id FROM company_license_groups WHERE tenant_id=$1 AND group_id=$2 AND pool_id=$3 AND status='active'", [source.tenant.id, values.groupId, values.poolId])).rows.length) fail(409, 'Group is already linked to this pool');
    const draft = { name: 'Lizenzgruppe ' + values.groupId, description: 'Lizenzpool ' + values.poolId, platform: 'all', configurations: [], appPoolIds: [values.poolId] };
    await this.blueprints.change('created', blueprintId, { id: blueprintId, draft, reason: values.reason, confirm: true }, undefined, v5('create-blueprint', operationId), user, authorization);
    await this.blueprints.change('published', blueprintId, { reason: values.reason, confirm: true }, `"company-blueprint-${blueprintId}-1"`, v5('publish-blueprint', operationId), user, authorization);
    const current = await this.snapshot(candidate, source, authorization);
    if (current.revision !== group.revision || current.hash !== group.hash) fail(412, 'Group changed while linking; inspect state before retrying');
    return this.write(source, operationId, id, values, blueprintId, user, authorization);
  }
  async preview(id, user, authorization) {
    return this.companies.read(user, authorization, async (client, source) => {
      const rule = await this.rule(client, id, source); const group = await this.snapshot(rule, source, authorization); const bindings = await this.bindings(client, rule);
      const wanted = new Set(group?.deleted ? [] : group?.memberIds || []);
      return { ...envelope(source), rule: view(rule), groupRevision: group?.revision || null, groupName: group?.name || null,
        eligibleMembers: wanted.size, assignedMembers: bindings.length, pendingMembers: [...wanted].filter(id => !bindings.some(binding => binding.user_id === id)).length,
        removalMembers: bindings.filter(binding => !wanted.has(binding.user_id)).length };
    });
  }
  async unlink(id, input, expected, operationId, user, authorization) {
    identifier(id); identifier(operationId); const values = unlinkValues(input); const source = await this.companies.authority.read(authorization, user);
    const rule = await this.rule(this.database, id, source);
    if (!expected) fail(428, 'License group If-Match required');
    const match = /^"company-license-group-([a-f0-9-]{36})-([12])"$/.exec(expected);
    if (!match || match[1] !== id) fail(412, 'License group version changed');
    const prior = (await this.database.query('SELECT id FROM company_license_group_events WHERE id=$1 AND tenant_id=$2', [operationId, source.tenant.id])).rows[0];
    if (!prior && match[2] !== String(rule.revision)) fail(412, 'License group version changed');
    return this.write(source, operationId, id, { ...values, revision: match[2] }, null, user, authorization);
  }
  async sync(id, input, user, authorization, selectedUsers = null) {
    const values = syncValues(input); const source = await this.companies.authority.read(authorization, user); const rule = await this.rule(this.database, id, source);
    const group = await this.snapshot(rule, source, authorization);
    if ((group?.revision || null) !== values.groupRevision) fail(412, 'Group changed; capture a fresh preview');
    const bindings = await this.bindings(this.database, rule); const desired = new Set(group?.deleted ? [] : group?.memberIds || []);
    const members = new Map((group?.memberships || []).map(member => [member.userId, member]));
    const all = [...new Set([...desired, ...bindings.map(binding => binding.user_id)])].sort();
    if (selectedUsers !== null && (source.kind !== 'application' || !Array.isArray(selectedUsers) || !selectedUsers.length || selectedUsers.length > 25 || new Set(selectedUsers).size !== selectedUsers.length)) fail(400, 'Bounded captured app targets required');
    if (selectedUsers) selectedUsers.forEach(identifier);
    const selected = selectedUsers || all.filter(userId => !values.cursor || userId > values.cursor).slice(0, 25); const results = [];
    const verify = async (client, after, command) => {
      await client.query('SELECT id FROM company_license_groups WHERE id=$1 FOR SHARE', [rule.id]);
      const currentRule = await this.rule(client, rule.id, source);
      if (currentRule.status !== rule.status || currentRule.revision !== rule.revision) fail(412, 'License group linkage changed');
      const current = await this.snapshot(currentRule, source, authorization);
      if ((current?.revision || null) !== (group?.revision || null) || (current?.hash || null) !== (group?.hash || null)) fail(412, 'Original group membership changed');
      if (after) {
        const snapshot = group || { groupId: rule.group_id, deleted: true, memberIds: [], memberships: [] };
        const deadline = Math.min(Date.now() + 60000, group ? Date.parse(group.validUntil) : Infinity,
          members.get(command.userId)?.reviewDeadlineAt ? Date.parse(members.get(command.userId).reviewDeadlineAt) : Infinity);
        await client.query(`INSERT INTO company_license_group_effects(id,rule_id,user_id,action,snapshot,valid_until,transaction_id)
          VALUES($1,$2,$3,$4,$5,LEAST(clock_timestamp()+interval '60 seconds',$6::timestamptz),txid_current())`,
        [command.id, rule.id, command.userId, command.action, snapshot, new Date(deadline).toISOString()]);
      }
    };
    for (const userId of selected) {
      let binding = bindings.find(binding => binding.user_id === userId);
      try {
        if (binding && (!desired.has(userId) || String(binding.eligibility_revision) !== members.get(userId)?.eligibilityRevision)) {
          const preview = await this.assignments.removalPreview(binding.id, user, authorization);
          await this.assignments.change('removed', binding.id, { userId, eligibilityRevision: preview.eligibilityRevision,
            pools: preview.pools.map(({ poolId, poolRevision }) => ({ poolId, poolRevision })), reason: values.reason, confirm: true },
          `"company-blueprint-assignment-${binding.id}-${binding.revision}"`, randomUUID(), user, authorization, this.correlationId || randomUUID(), { verify });
          binding = null;
        }
        if (desired.has(userId) && !binding) {
          const preview = await this.assignments.preview({ userId, blueprintId: rule.blueprint_id, version: 1 }, user, authorization);
          if (preview.eligibilityRevision !== members.get(userId).eligibilityRevision) fail(412, 'Current group recipient generation changed');
          await this.assignments.change('assigned', undefined, { id: randomUUID(), userId, blueprintId: rule.blueprint_id, version: 1,
            eligibilityRevision: preview.eligibilityRevision, pools: preview.pools.map(({ poolId, poolRevision }) => ({ poolId, poolRevision })), reason: values.reason, confirm: true },
          undefined, randomUUID(), user, authorization, this.correlationId || randomUUID(), { verify });
          results.push({ userId, status: 'assigned', code: null });
        } else results.push({ userId, status: desired.has(userId) ? 'retained' : 'removed', code: null });
      } catch (error) {
        if ([401, 412, 428].includes(error.status) || error.status === 403 && (source.kind !== 'application' || error.authorityDenied) || !error.status || error.status >= 500) throw error;
        results.push({ userId, status: 'blocked', code: error.status });
      }
    }
    await this.companies.unchanged(source, user, authorization);
    const last = selected.at(-1); const nextCursor = last && all.some(userId => userId > last) ? last : null;
    return { ...envelope(source), rule: view(rule), groupRevision: group?.revision || null, results, nextCursor, hasBlocked: results.some(result => result.status === 'blocked') };
  }
}
module.exports = { CompanyLicenseGroups, view };
