'use strict';

const { createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { v5 } = require('uuid');
const { identifier, exact } = require('../../../../../packages/company-license-contract');
const { CompanyLicenseGroups } = require('./CompanyLicenseGroups');
const { ProviderError } = require('./fulfillment/transport');
const { envelope, bindingView } = require('./CompanyMicrosoftBridge');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function eligible(raw) { return raw.target.enabled && !raw.target.deleted && raw.assignment?.eligibilityRevision === raw.target.eligibilityRevision; }
function liveOrigin(origin, raw) { return eligible(raw) && origin.live && origin.bindingValid && origin.eligibilityRevision === raw.target.eligibilityRevision; }
function targetView(row) {
  return row ? { id: identifier(row.id), revision: String(row.revision), status: row.status, owned: row.owned,
    lastOperationId: row.last_operation_id, uncertainOperationId: row.uncertain_operation_id, errorCode: row.error_code,
    checkedAt: row.checked_at ? new Date(row.checked_at).toISOString() : null } : null;
}
function observation(value) {
  const fields = ['present', 'direct', 'active', 'plansMatch', 'inherited', 'accountEnabled']; exact(value, fields);
  if (fields.some(field => typeof value[field] !== 'boolean') || value.direct && !value.present || value.active && !value.direct || value.plansMatch && !value.direct || value.inherited && !value.present) fail(503, 'Complete Microsoft license observation required');
  return Object.fromEntries(fields.map(field => [field, value[field]]));
}
function plan(projected, observed, target) {
  if (target?.status === 'processing') return 'recover';
  if (target?.uncertain_operation_id || target?.status === 'unknown') return 'review';
  if (target?.status === 'verifying') return 'verify';
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
    const target = (await client.query('SELECT * FROM company_microsoft_targets WHERE id=$1 AND tenant_id=$2', [id, source.tenant.id])).rows[0] || null;
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
    try { return observation(await graph.inspect(bindings.person.object_id, bindings.product.sku_id, bindings.product.disabled_plans)); }
    catch (error) { if (error instanceof ProviderError && error.code === 'graph_assignment_error' && error.observation) return observation(error.observation); throw error; }
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
}

module.exports = { CompanyMicrosoftDelivery, eligible, liveOrigin, observation, plan, digest, targetView };
