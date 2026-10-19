'use strict';

const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { COMPANY_LICENSE_PERMISSIONS, exact, identifier, pagination } = require('../../../../../packages/company-license-contract');
const { validRevision } = require('../../../../../packages/identity-authorization-contract');
const { sources, manualCommand, retirementValues, operationKey } = require('./CompanyLicenseSourcesContract');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function envelope(source) { return { schemaVersion: 2, companyLicenseProtocol: 2, actorUserId: source.actorUserId, tenantId: source.tenant.id }; }
function assignmentView(row) {
  if (!row || !validRevision(String(row.eligibility_revision))) fail(503, 'Original company allocation eligibility unavailable');
  const captured = sources(row.sources); if (!captured.length) fail(503, 'Complete company allocation source evidence unavailable');
  return { id: identifier(row.id), userId: identifier(row.assignee_id), assignedAt: row.assigned_at.toISOString(), assignedBy: identifier(row.assigned_by), eligibilityRevision: String(row.eligibility_revision), sources: captured };
}
const ASSIGNMENTS = `SELECT assignment.*,license_company_sources(assignment.license_id,assignment.assignee_id::uuid) AS sources FROM license_assignments assignment`;

class CompanyLicenseSources {
  constructor(companies, options = {}) { this.companies = companies; this.database = companies.database; this.options = options; }
  executor() {
    if (!this.instance) this.instance = this.options.executor || new (require('./CompanyBlueprintAssignments').CompanyBlueprintAssignments)(this.database,
      { allocator: this.companies.allocator, applicationAuthority: this.companies.authority, ...(this.options.assignmentAuthority ? { authority: this.options.assignmentAuthority } : {}) });
    return this.instance;
  }
  async observe(user, authorization, operation, target = null) {
    let assignmentSource = null;
    const result = await this.companies.read(user, authorization, async (client, source) => {
      await client.query('SELECT company_blueprint_assignment_retirement_receiving()');
      const assignments = async userId => {
        assignmentSource = await this.executor().source(user, authorization, userId);
        const { companyBlueprintAssignmentsProtocol, permissions, validUntil, ...original } = assignmentSource;
        if (!isDeepStrictEqual(original, Object.fromEntries(Object.entries(source).filter(([field]) => !['permissions', 'validUntil'].includes(field))))) fail(401, 'Independent assignment read authority does not match');
      };
      const value = await operation(client, source, assignments);
      if (assignmentSource) await this.executor().unchanged(assignmentSource, null, user, authorization);
      return value;
    }, target);
    if (assignmentSource) await this.executor().unchanged(assignmentSource, null, user, authorization); return result;
  }
  async bindings(client, source, userId) {
    const result = (await client.query('SELECT company_blueprint_user_binding_manifest($1::uuid,$2::uuid) AS bindings', [source.tenant.id, userId])).rows[0]?.bindings;
    if (!Array.isArray(result) || result.length > 10000) fail(503, 'Complete company blueprint binding manifest unavailable');
    return result;
  }
  async capabilities(user, authorization) {
    return this.observe(user, authorization, async (_client, source) => ({ ...envelope(source), permissions: [...COMPANY_LICENSE_PERMISSIONS], allocationMode: 'local-only', supportedTargets: ['user'] }));
  }
  async assignments(id, query, user, authorization) {
    identifier(id); const { page, limit } = pagination(query);
    return this.observe(user, authorization, async (client, source) => {
      const pool = await this.companies.ownPool(client, id, source.tenant.id);
      const total = (await client.query("SELECT count(*)::integer AS total FROM license_assignments WHERE license_id=$1 AND assignee_type='user'", [id])).rows[0].total;
      const rows = (await client.query(ASSIGNMENTS + " WHERE assignment.license_id=$1 AND assignment.assignee_type='user' ORDER BY assignment.assigned_at,assignment.id LIMIT $2 OFFSET $3", [id, limit, (page - 1) * limit])).rows;
      if (rows.length !== Math.min(limit, Math.max(0, total - (page - 1) * limit))) fail(503, 'Complete source-aware assignments unavailable');
      return { ...envelope(source), poolId: id, poolRevision: String(pool.business_revision), assignments: rows.map(assignmentView), total, page, limit };
    });
  }
  async assignmentPreview(id, input, user, authorization) {
    identifier(id); exact(input, ['userId']); identifier(input.userId);
    return this.observe(user, authorization, async (client, source) => {
      const pool = await this.companies.ownPool(client, id, source.tenant.id);
      const rows = (await client.query(ASSIGNMENTS + " WHERE assignment.license_id=$1 AND assignment.assignee_type='user' AND assignment.assignee_id=$2", [id, input.userId])).rows;
      if (rows.length > 1) fail(503, 'Exact company allocation unavailable');
      return { ...envelope(source), poolId: id, poolRevision: String(pool.business_revision), target: source.target, assignment: rows.length ? assignmentView(rows[0]) : null };
    }, input.userId);
  }
  async manual(action, id, projectionId, input, expected, key, user, authorization, correlationId) {
    const command = manualCommand(action, id, projectionId, input, expected, key, correlationId || randomUUID());
    const applicationSource = await this.companies.authority.read(authorization, user, command.userId);
    const receipt = await this.executor().execute(command, user, authorization, { source: null, applicationSource });
    if (receipt.operationId !== key || receipt.action !== action || receipt.actorUserId !== applicationSource.actorUserId || receipt.tenantId !== applicationSource.tenant.id
      || !['applied', 'already_applied'].includes(receipt.outcome) || receipt.pools?.length !== 1) fail(503, 'Original company source receipt unavailable');
    const child = receipt.pools[0];
    if (child.poolId !== id || !validRevision(child.afterRevision)
      || ['sourceAdded', 'sourceRemoved', 'seatAllocated', 'seatReleased', 'effectiveAssignmentRetained'].some(field => typeof child[field] !== 'boolean')
      || action === 'manual_assign' && (!child.sourceAdded || child.sourceRemoved || child.seatReleased)
      || action === 'manual_revoke' && (!child.sourceRemoved || child.sourceAdded || child.seatAllocated)) fail(503, 'Original source and seat effects unavailable');
    const rows = (await this.database.query('SELECT event.after_state,license_company_event_valid(event) AS valid FROM license_company_events event WHERE id=$1 AND tenant_id=$2 AND license_id=$3 AND target_user_id=$4', [child.eventId, applicationSource.tenant.id, id, command.userId])).rows;
    if (rows.length !== 1 || rows[0].valid !== true || (rows[0].after_state.assignment === null) !== (action === 'manual_revoke' && child.seatReleased)) fail(503, 'Historical company source result unavailable');
    await this.companies.unchanged(applicationSource, user, authorization);
    return { ...envelope(applicationSource), operationId: key, outcome: receipt.outcome, action, poolId: id, userId: command.userId,
      assignmentId: rows[0].after_state.assignment?.id || null, sourceAdded: child.sourceAdded, sourceRemoved: child.sourceRemoved,
      seatAllocated: child.seatAllocated, seatReleased: child.seatReleased, effectiveAssignmentRetained: child.effectiveAssignmentRetained,
      eventId: child.eventId, poolRevision: child.afterRevision, deliveryStatus: 'pending' };
  }
  assign(id, input, expected, key, user, authorization, correlationId) { return this.manual('manual_assign', id, null, input, expected, key, user, authorization, correlationId); }
  revoke(id, projectionId, input, expected, key, user, authorization, correlationId) { return this.manual('manual_revoke', id, projectionId, input, expected, key, user, authorization, correlationId); }
  async returnPreview(userId, query, user, authorization) {
    identifier(userId); const { page, limit } = pagination(query); if (limit > 25) fail(400, 'Company return preview pages are limited to 25 pools');
    return this.observe(user, authorization, async (client, source, assignmentAuthority) => {
      const from = " FROM license_assignments assignment JOIN license_catalog catalog ON catalog.id=assignment.license_id WHERE catalog.business_tenant_id=$1 AND assignment.assignee_type='user' AND assignment.assignee_id=$2::text";
      const total = (await client.query('SELECT count(*)::integer AS total' + from, [source.tenant.id, userId])).rows[0].total;
      const rows = (await client.query('SELECT assignment.*,catalog.name,catalog.vendor,catalog.business_revision,license_company_sources(catalog.id,$2::uuid) AS sources' + from + ' ORDER BY catalog.name,catalog.id LIMIT $3 OFFSET $4', [source.tenant.id, userId, limit, (page - 1) * limit])).rows;
      const bindings = await this.bindings(client, source, userId);
      if (bindings.length) await assignmentAuthority(userId);
      const assignments = [];
      for (const row of rows) {
        await this.companies.ownPool(client, row.license_id, source.tenant.id);
        const assignment = assignmentView(row);
        assignments.push({ id: assignment.id, poolId: row.license_id, poolRevision: String(row.business_revision), name: row.name, vendor: row.vendor,
          eligibilityRevision: assignment.eligibilityRevision, assignedAt: assignment.assignedAt, sources: assignment.sources });
      }
      return { ...envelope(source), userId, target: { enabled: source.target.enabled, deleted: source.target.deleted, eligibilityRevision: source.target.eligibilityRevision },
        assignments, bindings, totalBindings: bindings.length, workflowRequired: bindings.length > 0, total, page, limit };
    }, userId);
  }
  async retire(userId, values, key, user, authorization, correlationId, checkpoint = null) {
    let source = null;
    if (values.bindings.length) {
      const authority = this.options.assignmentAuthority || this.executor().authority;
      if (!authority) fail(503, 'Independent blueprint assignment authority unavailable');
      source = await authority.read(authorization, user, userId);
    }
    const applicationSource = values.assignments.length ? await this.companies.authority.read(authorization, user, userId) : null;
    const original = source || applicationSource; if (!original) fail(400, 'Capture actual sources or blueprint bindings');
    const command = { id: operationKey(key), correlationId, action: 'retire_sources', assignmentId: null, expectedRevision: '0', userId, eligibilityRevision: values.eligibilityRevision,
      blueprintId: null, version: null, pools: values.assignments.map(value => ({ poolId: value.poolId, poolRevision: value.poolRevision })), reason: values.reason,
      values: { checkpoint, pools: values.assignments, bindings: values.bindings } };
    const receipt = await this.executor().execute(command, user, authorization, { source, applicationSource: values.assignments.length ? applicationSource : null });
    if (receipt.operationId !== key || receipt.action !== 'retire_sources' || receipt.pools.length !== values.assignments.length) fail(503, 'Original complete retirement receipt unavailable');
    await this.executor().unchanged(source, applicationSource, user, authorization);
    const retired = (await this.database.query('SELECT id FROM company_blueprint_user_assignments WHERE removal_operation_id=$1 ORDER BY id', [key])).rows.map(row => row.id);
    return { ...envelope(original), operationId: key, outcome: receipt.outcome, userId, workflowId: values.workflowId,
      results: receipt.pools.map(child => {
        const capture = values.assignments.find(value => value.poolId === child.poolId);
        if (!capture || child.seatReleased !== true) fail(503, 'Complete seat retirement not confirmed');
        return { poolId: child.poolId, assignmentId: capture.assignmentId, status: 'released', eventId: child.eventId, poolRevision: child.afterRevision };
      }), retiredBindings: retired, deliveryStatus: 'pending' };
  }
  async returnLicenses(userId, input, key, user, authorization, correlationId = randomUUID()) {
    identifier(userId); const values = retirementValues(input); operationKey(key);
    if (values.workflowId !== null) {
      const workflow = new (require('./CompanyOffboarding').CompanyOffboarding)(this.companies, this.options.offboarding).v2;
      return workflow.retireRequested(values.workflowId, userId, values, key, user, authorization, correlationId);
    }
    return this.retire(userId, values, key, user, authorization, correlationId);
  }
}

module.exports = { CompanyLicenseSources, assignmentView, envelope };
