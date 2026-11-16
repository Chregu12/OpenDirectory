'use strict';

const { createHash, randomBytes } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { v5 } = require('uuid');
const { identifier, exact } = require('../../../../../packages/company-license-contract');
const { CompanyLicenseGroups } = require('./CompanyLicenseGroups');
const { ProviderError } = require('./fulfillment/transport');
const { envelope, bindingView, confirmation } = require('./CompanyMicrosoftBridge');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function eligible(raw) { return raw.target.enabled && !raw.target.deleted && raw.assignment?.eligibilityRevision === raw.target.eligibilityRevision; }
function liveOrigin(origin, raw) { return eligible(raw) && origin.live && origin.bindingValid && origin.eligibilityRevision === raw.target.eligibilityRevision; }
function targetView(row) {
  return row ? { id: identifier(row.id), revision: String(row.revision), status: row.status, owned: row.owned,
    lastOperationId: row.last_operation_id, pendingOperationId: row.pending_operation_id, uncertainOperationId: row.uncertain_operation_id, errorCode: row.error_code,
    retryAt: row.retry_at ? new Date(row.retry_at).toISOString() : null, checkedAt: row.checked_at ? new Date(row.checked_at).toISOString() : null } : null;
}
function observation(value) {
  const fields = ['present', 'direct', 'active', 'plansMatch', 'inherited', 'accountEnabled']; exact(value, fields);
  if (fields.some(field => typeof value[field] !== 'boolean') || value.direct && !value.present || value.active && !value.direct || value.plansMatch && !value.direct || value.inherited && !value.present) fail(503, 'Complete Microsoft license observation required');
  return Object.fromEntries(fields.map(field => [field, value[field]]));
}
function plan(projected, observed, target) {
  if (target?.status === 'processing') return 'recover';
  if (target?.uncertain_operation_id || target?.status === 'unknown') return 'review';
  if (target?.pending_operation_id || target?.status === 'verifying') return 'verify';
  if (projected.desired) {
    if (!observed.accountEnabled) return 'conflict';
    if (!observed.present) return 'assign';
    return target?.owned && observed.direct && observed.plansMatch ? observed.active ? 'confirmed' : 'verify' : 'conflict';
  }
  if (!observed.direct) return observed.present ? 'external_retained' : 'confirmed';
  return target?.owned && observed.plansMatch ? 'remove' : 'external_retained';
}

class CompanyMicrosoftDelivery {
  constructor(bridge, { groups = new CompanyLicenseGroups(bridge.companies) } = {}) { this.bridge = bridge; this.companies = bridge.companies; this.database = bridge.database; this.groups = groups; }
  async bindings(client, poolId, source, config) {
    await client.query('SELECT company_microsoft_delivery_receiving()'); await this.companies.ownPool(client, poolId, source.tenant.id);
    const connection = await this.bridge.connection(client, source); this.bridge.matchingConnection(source, connection, config);
    const product = (await client.query("SELECT * FROM company_microsoft_pools WHERE pool_id=$1 AND tenant_id=$2 AND connection_id=$3 AND status='active'", [poolId, source.tenant.id, connection.id])).rows[0];
    const person = (await client.query("SELECT * FROM company_microsoft_users WHERE user_id=$1 AND tenant_id=$2 AND connection_id=$3 AND status='active'", [source.target.id, source.tenant.id, connection.id])).rows[0];
    if (!product || !person) fail(409, 'Current own Microsoft pool and user mappings required');
    const id = v5(person.id, product.id);
    const target = (await client.query(`SELECT target.*,attempt.outcome->>'retryAt' AS retry_at FROM company_microsoft_targets target
      LEFT JOIN company_microsoft_operations attempt ON attempt.id=target.last_operation_id AND attempt.tenant_id=target.tenant_id
      WHERE target.id=$1 AND target.tenant_id=$2`, [id, source.tenant.id])).rows[0] || null;
    if (target && (target.pool_binding_id !== product.id || target.user_binding_id !== person.id || target.connection_id !== connection.id)) fail(503, 'Exact Microsoft delivery target binding required');
    return { id, connection, product, person, target };
  }
  async projection(client, poolId, source, authorization) {
    const raw = (await client.query('SELECT company_microsoft_local($1::uuid,$2::jsonb) AS value', [poolId, source])).rows[0]?.value;
    if (!raw || raw.poolId !== poolId || raw.target.id !== source.target.id || !Array.isArray(raw.origins) || raw.origins.length > 10000) fail(503, 'Complete local license projection unavailable');
    if (raw.origins.some(origin => origin.bindingValid !== true)) fail(503, 'Original blueprint binding evidence unavailable');
    const rules = new Map();
    for (const ruleId of [...new Set(raw.origins.filter(origin => origin.rule).map(origin => origin.rule.id))].sort()) {
      const retained = raw.origins.find(origin => origin.rule?.id === ruleId).rule; const rule = await this.groups.rule(client, ruleId, source);
      if (rule.group_id !== retained.groupId || String(rule.revision) !== retained.revision || rule.status !== retained.status) fail(412, 'License group linkage changed');
      rules.set(ruleId, rule);
    }
    const proofs = [];
    for (const ruleId of [...new Set(raw.origins.filter(origin => liveOrigin(origin, raw) && origin.rule?.status === 'active').map(origin => origin.rule.id))].sort()) {
      const rule = rules.get(ruleId);
      const group = await this.groups.snapshot(rule, source, authorization);
      if (!group || Date.parse(group.validUntil) <= Date.now()) fail(503, 'Current company group snapshot required');
      const member = group.memberships.find(row => row.userId === source.target.id) || null;
      const active = !group.deleted && group.memberIds.includes(source.target.id) && member?.eligibilityRevision === source.target.eligibilityRevision
        && (member.reviewDeadlineAt === null || Date.parse(member.reviewDeadlineAt) > Date.now());
      proofs.push({ ruleId, groupId: group.groupId, revision: group.revision, hash: group.hash, active: !!active,
        membershipId: member?.membershipId || null, eligibilityRevision: member?.eligibilityRevision || null,
        reviewDeadlineAt: member?.reviewDeadlineAt || null, validUntil: group.validUntil });
    }
    const desired = raw.origins.some(origin => liveOrigin(origin, raw) && (!origin.rule || origin.rule.status === 'active' && proofs.some(proof => proof.ruleId === origin.rule.id && proof.active)));
    return { raw, groups: proofs, desired };
  }
  stableProjection(value) { return { ...value, groups: value.groups.map(({ validUntil, ...proof }) => proof) }; }
  async inspect(graph, bindings) {
    if (graph.tenantId !== bindings.connection.microsoft_tenant_id) fail(503, 'Bound Microsoft Graph tenant required');
    graph.assignmentError = null;
    try { return observation(await graph.inspect(bindings.person.object_id, bindings.product.sku_id, bindings.product.disabled_plans)); }
    catch (error) { if (error instanceof ProviderError && error.code === 'graph_assignment_error' && error.observation) { graph.assignmentError = error.code; return observation(error.observation); } throw error; }
  }
  capture(source, bindings, projection, remote, stock = null) {
    return { ...envelope(source), poolId: bindings.product.pool_id, userId: bindings.person.user_id,
      connection: bindingView('connection', bindings.connection), pool: bindingView('pool', bindings.product), user: bindingView('user', bindings.person),
      target: targetView(bindings.target), local: this.stableProjection(projection), remote, stock };
  }
  async preview(poolId, userId, user, authorization) {
    identifier(poolId); identifier(userId);
    return this.companies.read(user, authorization, async (client, source) => {
      const config = this.bridge.requireConfiguration(source); const bindings = await this.bindings(client, poolId, source, config);
      const projection = await this.projection(client, poolId, source, authorization);
      const remote = await this.inspect(this.bridge.createGraph(config.write), bindings);
      let action = plan(projection, remote, bindings.target), stock = null;
      if (action === 'assign') {
        stock = (await this.bridge.createReader(config.read).inspect()).find(row => row.skuId === bindings.product.sku_id) || null;
        if (!stock || stock.appliesTo !== 'User' || stock.capabilityStatus !== 'Enabled' || stock.prepaidUnits.enabled <= stock.consumedUnits) action = 'conflict';
      }
      const current = await this.projection(client, poolId, source, authorization);
      if (!isDeepStrictEqual(this.stableProjection(current), this.stableProjection(projection))) fail(412, 'Local entitlement or group membership changed during the preview');
      this.bridge.unchangedConfiguration(source, config);
      const value = this.capture(source, bindings, projection, remote, stock);
      if (Buffer.byteLength(JSON.stringify(value)) > 2097152) fail(409, 'Microsoft preview exceeds response limit');
      return { ...value, fingerprint: digest(value), action, checkedAt: new Date().toISOString() };
    }, userId);
  }
  async transaction(client, operation) {
    try {
      await client.query('BEGIN'); await client.query("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'");
      const result = await operation(); await client.query('COMMIT'); return result;
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
  }
  async recorded(source, operation, request, client = this.database) {
    const row = (await client.query('SELECT * FROM company_microsoft_operations WHERE id=$1 AND tenant_id=$2', [operation, source.tenant.id])).rows[0];
    if (!row) return null;
    await client.query('SELECT company_microsoft_delivery_receiving()');
    if (row.action !== 'sync' || row.source.actorUserId !== source.actorUserId || !isDeepStrictEqual(row.request, request)) fail(409, 'Microsoft operation key belongs to another original request');
    if (row.phase !== 'finished') fail(409, 'Original Microsoft operation requires recovery; no repeat dispatch');
    return row.outcome;
  }
  async sync(poolId, userId, input, operation, user, authorization) {
    identifier(poolId); identifier(userId); identifier(operation); const reason = confirmation(input, ['fingerprint', 'action']);
    if (typeof input.fingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(input.fingerprint)) fail(400, 'Exact reviewed Microsoft preview required');
    if (!['assign', 'remove', 'confirmed', 'conflict', 'review', 'verify', 'external_retained'].includes(input.action)) fail(400, 'Explicit reviewed Microsoft action required');
    const source = await this.companies.authority.read(authorization, user, userId);
    const request = { poolId, userId, fingerprint: input.fingerprint, action: input.action, reason, confirm: true };
    const prior = await this.recorded(source, operation, request);
    if (prior) { await this.companies.unchanged(source, user, authorization); return { ...envelope(source), historical: true, result: prior }; }
    const config = this.bridge.requireConfiguration(source); const client = await this.database.getClient(); let locked = false, lockKey = null, prepared = false, dispatched = false, finished = false;
    const nonce = randomBytes(32).toString('hex'); let bindings, graph;
    const settle = async (kind, errorCode = null, retryAfter = null) => {
      const result = await this.transaction(client, async () => (await client.query('SELECT company_microsoft_finish($1::uuid,$2::text,$3::jsonb) AS result', [operation, nonce, { kind, errorCode, retryAfter }])).rows[0].result);
      finished = true; return result;
    };
    try {
      bindings = await this.bindings(client, poolId, source, config);
      lockKey = 'company-microsoft:' + bindings.id;
      locked = (await client.query('SELECT pg_try_advisory_lock(hashtextextended($1,0)) AS locked', [lockKey])).rows[0].locked;
      if (!locked) fail(409, 'Microsoft target is already being inspected');
      const existing = await this.recorded(source, operation, request, client);
      if (existing) { await this.companies.unchanged(source, user, authorization); return { ...envelope(source), historical: true, result: existing }; }
      bindings = await this.bindings(client, poolId, source, config);
      if ('company-microsoft:' + bindings.id !== lockKey) fail(412, 'Microsoft mapping pair changed before the target lock');
      if (bindings.target?.status === 'processing') fail(409, 'Interrupted Microsoft operation requires explicit recovery');
      if (bindings.target?.retry_at && Date.parse(bindings.target.retry_at) > Date.now()) fail(429, 'Microsoft retry window is still active');
      const projection = await this.projection(client, poolId, source, authorization); graph = this.bridge.createGraph(config.write);
      const remote = await this.inspect(graph, bindings); let action = plan(projection, remote, bindings.target), stock = null;
      if (action === 'assign') {
        stock = (await this.bridge.createReader(config.read).inspect()).find(row => row.skuId === bindings.product.sku_id) || null;
        if (!stock || stock.appliesTo !== 'User' || stock.capabilityStatus !== 'Enabled' || stock.prepaidUnits.enabled <= stock.consumedUnits) action = 'conflict';
      }
      const capture = this.capture(source, bindings, projection, remote, stock);
      if (digest(capture) !== input.fingerprint || action !== input.action) fail(412, 'Microsoft preview, reviewed action, local entitlement or provider observation changed');
      const mutation = action === 'assign' || action === 'remove'; let token;
      if (mutation) token = await graph.tokens.get();
      await this.transaction(client, async () => {
        await this.companies.unchanged(source, user, authorization); this.bridge.unchangedConfiguration(source, config);
        await client.query('SELECT company_microsoft_prepare($1::jsonb,$2::uuid,$3::text,$4::uuid,$5::jsonb,$6::jsonb,$7::jsonb)', [source, operation, nonce, bindings.id, request, projection, capture]);
        await this.companies.unchanged(source, user, authorization); this.bridge.unchangedConfiguration(source, config);
      });
      prepared = true;
      if (!mutation) {
        const result = await settle('observed', graph.assignmentError); await this.companies.unchanged(source, user, authorization); return { ...envelope(source), historical: false, result };
      }
      const current = await this.projection(client, poolId, source, authorization);
      const maps = await this.bindings(client, poolId, source, config);
      if (!isDeepStrictEqual(this.stableProjection(current), this.stableProjection(projection))
        || !isDeepStrictEqual(bindingView('connection', maps.connection), bindingView('connection', bindings.connection))
        || !isDeepStrictEqual(bindingView('pool', maps.product), bindingView('pool', bindings.product))
        || !isDeepStrictEqual(bindingView('user', maps.person), bindingView('user', bindings.person))
        || !isDeepStrictEqual(await this.inspect(graph, maps), remote)) fail(412, 'Original Microsoft dispatch proof changed');
      if (action === 'assign') {
        const latest = (await this.bridge.createReader(config.read).inspect()).find(row => row.skuId === bindings.product.sku_id) || null;
        if (!isDeepStrictEqual(latest, stock)) fail(412, 'Microsoft stock changed before dispatch');
      }
      token = await graph.tokens.get();
      await this.companies.unchanged(source, user, authorization); this.bridge.unchangedConfiguration(source, config);
      const deadline = await this.transaction(client, async () => {
        const value = (await client.query('SELECT company_microsoft_dispatch($1::uuid,$2::text) AS deadline', [operation, nonce])).rows[0].deadline;
        await this.companies.unchanged(source, user, authorization); this.bridge.unchangedConfiguration(source, config); return value;
      });
      dispatched = true;
      if (!Number.isFinite(new Date(deadline).getTime()) || Date.now() >= new Date(deadline).getTime()) fail(503, 'Microsoft dispatch window elapsed');
      let kind = 'acknowledged', errorCode = null, retryAfter = null;
      try { await graph.mutate(bindings.person.object_id, bindings.product.sku_id, bindings.product.disabled_plans, projection.desired, token, operation); }
      catch (error) {
        const certainRejection = error instanceof ProviderError && error.uncertain === false && /^graph_write_(?:invalid_request|http_(?:400|401|403|404|405|410|412|415|422|429))$/.test(error.code);
        kind = certainRejection ? 'rejected' : 'unknown';
        errorCode = error instanceof ProviderError && /^[a-z0-9_]{1,120}$/.test(error.code) ? error.code : 'provider_write_uncertain';
        retryAfter = Number.isInteger(error.retryAfter) && error.retryAfter >= 1 && error.retryAfter <= 3600 ? error.retryAfter : null;
      }
      const result = await settle(kind, errorCode, retryAfter); await this.companies.unchanged(source, user, authorization);
      return { ...envelope(source), historical: false, result };
    } catch (error) {
      if (prepared && !finished) {
        try { await settle(dispatched ? 'unknown' : 'not_sent', dispatched ? 'dispatch_result_unconfirmed' : 'dispatch_precheck_failed'); }
        catch { /* Retain processing/dispatch evidence for explicit recovery. */ }
      }
      if (!error.status && source.validUntil * 1000 <= Date.now()) error.status = 428;
      throw error;
    } finally {
      graph?.tokens?.clear?.();
      let destroyed = false;
      if (locked) {
        try { await client.query('SELECT pg_advisory_unlock(hashtextextended($1,0))', [lockKey]); }
        catch { client.release(true); destroyed = true; }
      }
      if (!destroyed) client.release();
    }
  }
}

module.exports = { CompanyMicrosoftDelivery, eligible, liveOrigin, observation, plan, digest, targetView };
