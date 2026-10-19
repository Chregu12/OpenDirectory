'use strict';

const { createHash, randomUUID } = require('node:crypto');
const { validContext, validRevision } = require('../../../../packages/identity-authorization-contract');
const { getPolicyPermissions, freshPolicyAuthentication } = require('../../../../packages/policy-authorization-contract');
const contract = require('../../../../packages/policy-command-contract');
const { PolicyCommandSource } = require('./PolicyCommandSource');
const tokenHash = authorization => createHash('sha256').update(authorization.slice(7)).digest('hex');
const itemKey = reference => reference.configurationId || 'gpo';
const scope = frame => ({ resourceKind: frame.reference.resourceKind, resourceId: frame.reference.resourceId, resourceVersion: frame.reference.resourceVersion,
  publicationId: frame.reference.publicationId, configurationVersion: frame.configurationVersion, configurationHash: frame.configurationHash, publicationVersion: frame.publicationVersion });
function operator(claims, authorization) {
  const identity = claims.identity_authorization;
  return { kind: 'user', issuer: claims.iss, subject: claims.sub, userId: identity.userId, revision: identity.revision, linkRevision: identity.linkRevision,
    rolesRevision: identity.rolesRevision, clientId: claims.client_id, tokenId: claims.jti, tokenHash: tokenHash(authorization), expiresAt: claims.exp,
    authTime: claims.auth_time, mfaRevision: claims.mfa_authorization.revision };
}
function receipt(row) {
  const frame = row.policy_context;
  return contract.receipt({ schemaVersion: 1, commandId: row.id, operationId: row.policy_operation_id, deviceId: row.device_id,
    deviceGeneration: String(row.policy_generation), operatorUserId: row.policy_actor.userId, reference: frame.reference,
    configurationVersion: frame.configurationVersion, configurationHash: frame.configurationHash, publicationVersion: frame.publicationVersion,
    payloadHash: frame.payloadHash, expiresAt: new Date(row.policy_delivery_until).toISOString(), persistence: 'committed' });
}
function view(row) {
  return { id: row.id, command: 'update_policy', payload: row.payload, status: row.effective_status || row.status, issuedAt: new Date(row.issued_at).toISOString(),
    dispatchedAt: row.policy_dispatched_at ? new Date(row.policy_dispatched_at).toISOString() : null,
    completedAt: row.completed_at ? new Date(row.completed_at).toISOString() : null, result: row.result, policyReceipt: receipt(row), enforcementConfirmed: false };
}
function cancellationReceipt(row) {
  return contract.cancellation({ schemaVersion: 1, commandId: row.command_id, deviceId: row.original_receipt.deviceId, operationId: row.operation_id,
    cancelledByUserId: row.actor.userId, cancelledAt: new Date(row.cancelled_at).toISOString(), reason: row.reason, previouslyOffered: row.previously_offered_at !== null,
    policyReceipt: row.original_receipt, persistence: 'committed', furtherOffersStopped: true, enforcementConfirmed: false });
}
class PolicyDeviceQueue {
  constructor(database, { isUserRevoked, isDeviceRevoked, source } = {}) {
    this.database = database; this.isUserRevoked = isUserRevoked; this.isDeviceRevoked = isDeviceRevoked; this.source = source;
    this.activeTransactions = 0;
  }
  sourceClient() { if (!this.source) this.source = new PolicyCommandSource(); return this.source; }
  async check(claims, authorization, signal, device = false) {
    if (signal?.aborted) contract.fail(409, 'policy_command_operation_closed');
    if (typeof authorization !== 'string' || !/^Bearer [^\r\n]+$/.test(authorization) || typeof claims?.jti !== 'string' || !claims.jti || !Number.isSafeInteger(claims.exp) || claims.exp <= Math.floor(Date.now() / 1000)) contract.fail(401, 'current_policy_command_credential_required');
    if (device) {
      if (claims.token_use !== 'device' || claims.aud !== 'opendirectory-device-agent' || !contract.deviceId(claims.sub) || !validRevision(claims.device_generation) || !this.isDeviceRevoked) contract.fail(403, 'bound_device_credential_required');
      if (await this.isDeviceRevoked(tokenHash(authorization)) !== false) contract.fail(401, 'policy_device_credential_revoked');
    } else {
      if (claims.actor_type !== 'user' || claims.token_use !== 'access' || !validContext(claims.identity_authorization) || !getPolicyPermissions(claims).includes('policies.deploy') || !this.isUserRevoked) contract.fail(403, 'canonical_policy_deployer_required');
      if (!freshPolicyAuthentication(claims)) contract.fail(428, 'fresh_mfa_required');
      if (await this.isUserRevoked(tokenHash(authorization), claims) !== false) contract.fail(401, 'original_policy_operator_revoked');
      if (!freshPolicyAuthentication(claims)) contract.fail(428, 'fresh_mfa_required');
    }
    if (signal?.aborted) contract.fail(409, 'policy_command_operation_closed');
  }
  async transaction(claims, authorization, signal, operation, device = false) {
    let client; let admitted = false;
    try {
      await this.check(claims, authorization, signal, device);
      if (this.activeTransactions >= 4) contract.fail(503, 'policy_command_capacity_unavailable');
      this.activeTransactions++; admitted = true;
      if (!this.database.isAvailable()) contract.fail(503, 'policy_command_storage_unavailable');
      client = await this.database.pool.connect(); await client.query('BEGIN'); await client.query("SET LOCAL statement_timeout='7000ms';SET LOCAL lock_timeout='5000ms'");
      const result = await operation(client); await this.check(claims, authorization, signal, device); await client.query('COMMIT'); return result;
    } catch (error) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      if (error.status) throw error;
      if (error.constraint === 'policy_device_token_expired') contract.fail(401, 'policy_command_credential_expired');
      if (error.constraint === 'policy_device_mfa_expired') contract.fail(428, 'fresh_mfa_required');
      if (['23505','23514','40P01'].includes(error.code)) contract.fail(409, 'policy_command_changed_or_expired');
      contract.fail(503, 'policy_command_storage_unavailable');
    } finally { if (admitted) this.activeTransactions--; client?.release(); }
  }
  async device(client, id) {
    if (!contract.deviceId(id)) contract.fail(400, 'canonical_device_id_required');
    const row = (await client.query('SELECT id,platform,status,policy_generation FROM enrolled_devices WHERE id=$1 FOR UPDATE', [id])).rows[0];
    if (!row) contract.fail(404, 'policy_device_not_found');
    if (!['windows','macos','linux'].includes(row.platform) || !['active','flagged','quarantined'].includes(row.status)) contract.fail(409, 'current_supported_policy_device_required'); return row;
  }
  agent(claims, authorization, device) {
    if (claims.sub !== device.id || claims.platform !== device.platform || claims.device_generation !== String(device.policy_generation)) contract.fail(403, 'current_device_binding_required');
    return { kind: 'device', deviceId: device.id, platform: device.platform, generation: String(device.policy_generation), issuer: claims.iss,
      tokenId: claims.jti, tokenHash: tokenHash(authorization), expiresAt: claims.exp };
  }
  async proof(client, value) { await client.query("SELECT set_config('opendirectory.policy_device_command',$1,true)", [JSON.stringify(value)]); }
  async access(claims, authorization, signal) {
    return this.transaction(claims, authorization, signal, async client => {
      if ((await client.query('SELECT policy_device_schema_version() AS version')).rows[0]?.version !== 1) contract.fail(503, 'policy_command_storage_unavailable');
      return { schemaVersion: 1, commandContract: 'approved-content-v1', receiptContract: 'postgres-evidence-v1', admissionMaxSeconds: contract.ADMISSION_SECONDS,
        deliveryMaxSeconds: contract.DELIVERY_SECONDS, subject: claims.sub, userId: claims.identity_authorization.userId, freshMfa: true };
    });
  }
  async inventory(claims, authorization, signal) {
    return this.transaction(claims, authorization, signal, async client => {
      const rows = (await client.query("SELECT id,hostname,platform FROM enrolled_devices WHERE status IN('active','flagged','quarantined') ORDER BY id LIMIT 10001")).rows;
      if (rows.length > 10000 || rows.some(row => !contract.deviceId(row.id))) contract.fail(409, 'bounded_known_policy_device_inventory_required');
      return rows.map(row => ({ id: row.id, hostname: typeof row.hostname === 'string' ? row.hostname : null, platform: typeof row.platform === 'string' ? row.platform : null }));
    });
  }
  async queue(id, body, operationId, original, authorization, signal) {
    contract.fields(body, ['command','reference']); const reference = contract.reference(body.reference);
    if (body.command !== 'update_policy' || !contract.uuid(operationId)) contract.fail(400, 'captured_policy_command_operation_required');
    const claims = structuredClone(original || {});
    return this.transaction(claims, authorization, signal, async client => {
      const actor = operator(claims, authorization);
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended('policy-device-operation:'||$1,0))", [operationId]);
      const device = await this.device(client, id); await this.check(claims, authorization, signal);
      const request = { reference, deviceId: id, platform: device.platform, operationId };
      const frame = contract.frame(await this.sourceClient().frame(request, claims, authorization, signal), { ...request, operatorUserId: actor.userId });
      const origin = (await client.query('SELECT * FROM policy_device_operations WHERE id=$1', [operationId])).rows[0];
      if (origin && (!contract.same(origin.actor, actor) || !contract.same(origin.scope, scope(frame)))) contract.fail(409, 'policy_command_operation_mismatch');
      const existing = (await client.query("SELECT *,policy_delivery_until<=policy_device_now() AS expired FROM mdm_commands WHERE policy_operation_id=$1 AND device_id=$2 AND policy_item_key=$3 AND command='update_policy'", [operationId, id, itemKey(reference)])).rows[0];
      let row;
      if (existing) {
        if (existing.status === 'cancelled' || existing.expired || String(existing.policy_generation) !== String(device.policy_generation) || !contract.same(existing.policy_actor, actor)
          || !contract.same(existing.policy_context.reference, reference) || existing.policy_context.payloadHash !== frame.payloadHash) contract.fail(409, 'policy_command_retry_mismatch');
        row = existing;
      } else {
        await this.proof(client, { action: 'queued', actor, operationId, generation: String(device.policy_generation), frame });
        row = (await client.query("INSERT INTO mdm_commands(id,device_id,command,payload,status) VALUES($1,$2,'update_policy',$3,'pending') RETURNING *", [randomUUID(), id, JSON.stringify(frame.payload)])).rows[0];
      }
      const current = contract.frame(await this.sourceClient().frame(request, claims, authorization, signal), { ...request, operatorUserId: actor.userId });
      if (!contract.sameFrame(frame, current) || Date.parse(frame.admissionValidUntil) <= Date.now()) contract.fail(409, 'captured_policy_command_source_changed');
      return view(row);
    });
  }
  async ownedHistory(query, original, authorization, signal) {
    contract.fields(query, ['resourceKind','resourceId','limit','offset']);
    if (!['policy','blueprint'].includes(query.resourceKind) || !contract.uuid(query.resourceId) || !Number.isInteger(query.limit) || query.limit < 1 || query.limit > 200
      || !Number.isInteger(query.offset) || query.offset < 0 || query.offset > 1000000) contract.fail(400, 'bounded_owned_policy_commands_required');
    const claims = structuredClone(original);
    return this.transaction(claims, authorization, signal, async client => {
      if ((await client.query('SELECT policy_device_cancellation_schema_version() AS version')).rows[0]?.version !== 1) contract.fail(503, 'policy_command_cancellation_unavailable');
      const rows = (await client.query(`SELECT command.*,to_jsonb(cancellation.*) AS cancellation,
        CASE WHEN command.status='pending' AND (command.policy_delivery_until<=policy_device_now() OR command.policy_generation IS DISTINCT FROM device.policy_generation) THEN 'expired' ELSE command.status END AS effective_status
        FROM mdm_commands command LEFT JOIN enrolled_devices device ON device.id=command.device_id LEFT JOIN policy_device_cancellations cancellation ON cancellation.command_id=command.id
        WHERE command.command='update_policy' AND command.policy_context IS NOT NULL AND command.policy_actor->>'userId'=$1
        AND command.policy_context->'reference'->>'resourceKind'=$2 AND command.policy_context->'reference'->>'resourceId'=$3
        ORDER BY command.issued_at DESC,command.id LIMIT $4 OFFSET $5`, [claims.identity_authorization.userId, query.resourceKind, query.resourceId, query.limit + 1, query.offset])).rows;
      return { schemaVersion: 1, contract: 'owned-policy-cancellation-v1', userId: claims.identity_authorization.userId, resourceKind: query.resourceKind, resourceId: query.resourceId,
        commands: rows.slice(0, query.limit).map(row => ({ id: row.id, status: row.effective_status, policyReceipt: receipt(row), previouslyOffered: row.policy_dispatched_at !== null,
          cancellationReceipt: row.cancellation ? cancellationReceipt(row.cancellation) : null, enforcementConfirmed: false })), truncated: rows.length > query.limit };
    });
  }
  async cancel(id, commandId, body, operationId, original, authorization, signal) {
    contract.fields(body, ['policyReceipt','reason','acknowledgeScope']); contract.receipt(body.policyReceipt, undefined, 400);
    if (!contract.deviceId(id) || !contract.uuid(commandId) || !contract.uuid(operationId) || body.policyReceipt.commandId !== commandId || body.policyReceipt.deviceId !== id
      || body.acknowledgeScope !== true || typeof body.reason !== 'string' || body.reason.trim() !== body.reason || body.reason.length < 10 || body.reason.length > 500 || /[\u0000-\u001f\u007f]/.test(body.reason)) contract.fail(400, 'exact_policy_command_cancellation_required');
    const claims = structuredClone(original);
    return this.transaction(claims, authorization, signal, async client => {
      await client.query('SELECT id FROM enrolled_devices WHERE id=$1 FOR UPDATE', [id]); await this.check(claims, authorization, signal);
      const row = (await client.query("SELECT * FROM mdm_commands WHERE id=$1 AND device_id=$2 AND command='update_policy' FOR UPDATE", [commandId, id])).rows[0];
      if (!row?.policy_context || row.policy_actor.userId !== claims.identity_authorization.userId) contract.fail(404, 'owned_policy_command_not_found');
      if (!contract.same(receipt(row), body.policyReceipt)) contract.fail(409, 'captured_policy_command_receipt_changed');
      const retained = (await client.query('SELECT * FROM policy_device_cancellations WHERE command_id=$1', [commandId])).rows[0];
      if (retained) {
        if (retained.operation_id !== operationId || retained.reason !== body.reason) contract.fail(409, 'policy_command_cancellation_operation_changed');
        return cancellationReceipt(retained);
      }
      if (row.status !== 'pending') contract.fail(409, 'pending_policy_command_cancellation_required');
      await this.proof(client, { action: 'cancelled', commandId, operationId, actor: operator(claims, authorization), receipt: body.policyReceipt, reason: body.reason });
      await client.query("UPDATE mdm_commands SET status='cancelled' WHERE id=$1", [commandId]);
      return cancellationReceipt((await client.query('SELECT * FROM policy_device_cancellations WHERE command_id=$1', [commandId])).rows[0]);
    });
  }
  async pending(id, original, authorization, signal) {
    const claims = structuredClone(original);
    return this.transaction(claims, authorization, signal, async client => {
      const device = await this.device(client, id); const actor = this.agent(claims, authorization, device); await this.check(claims, authorization, signal, true);
      const rows = (await client.query("SELECT * FROM mdm_commands WHERE device_id=$1 AND command='update_policy' AND policy_context IS NOT NULL AND policy_generation=$2 AND status='pending' AND policy_delivery_until>policy_device_now() ORDER BY issued_at,id LIMIT 100 FOR UPDATE", [id, device.policy_generation])).rows;
      const result = [];
      for (let row of rows) {
        await this.proof(client, { action: 'dispatched', commandId: row.id, actor });
        row = (await client.query('UPDATE mdm_commands SET policy_version=policy_version+1 WHERE id=$1 RETURNING *', [row.id])).rows[0];
        result.push(view(row));
      }
      return result;
    }, true);
  }
  async report(id, commandId, body, original, authorization, signal) {
    contract.fields(body, ['status','result']); contract.json(body.result);
    if (!contract.uuid(commandId) || !['completed','failed'].includes(body.status) || Buffer.byteLength(JSON.stringify(body.result)) > 65536) contract.fail(400, 'bounded_terminal_device_report_required');
    const claims = structuredClone(original);
    return this.transaction(claims, authorization, signal, async client => {
      const device = await this.device(client, id); const actor = this.agent(claims, authorization, device); await this.check(claims, authorization, signal, true);
      const row = (await client.query("SELECT * FROM mdm_commands WHERE id=$1 AND device_id=$2 AND command='update_policy' FOR UPDATE", [commandId, id])).rows[0];
      if (!row) contract.fail(404, 'policy_command_not_found');
      if (!row.policy_context || String(row.policy_generation) !== String(device.policy_generation) || !row.policy_dispatched_at) contract.fail(409, 'dispatched_current_policy_command_required');
      if (row.status !== 'pending') {
        if (row.status !== body.status || !contract.same(row.result, body.result)) contract.fail(409, 'terminal_policy_command_report_changed'); return view(row);
      }
      await this.proof(client, { action: 'reported', commandId, actor });
      return view((await client.query('UPDATE mdm_commands SET status=$2,result=$3 WHERE id=$1 RETURNING *', [commandId, body.status, JSON.stringify(body.result)])).rows[0]);
    }, true);
  }
  async list(id, limit = 200, offset = 0) {
    if (!contract.deviceId(id)) contract.fail(400, 'canonical_device_id_required');
    if (!Number.isInteger(limit) || limit < 1 || limit > 200 || !Number.isInteger(offset) || offset < 0 || offset > 1000000) contract.fail(400, 'bounded_policy_command_history_required');
    if (!this.database.isAvailable()) contract.fail(503, 'policy_command_storage_unavailable');
    try {
      const rows = (await this.database.query(`SELECT *,CASE WHEN policy_context IS NULL THEN 'legacy-unverified'
        WHEN status='pending' AND (policy_delivery_until<=policy_device_now() OR policy_generation IS DISTINCT FROM (SELECT policy_generation FROM enrolled_devices WHERE id=$1)) THEN 'expired' ELSE status END AS effective_status
        FROM mdm_commands WHERE device_id=$1 AND command='update_policy' ORDER BY issued_at DESC,id LIMIT $2 OFFSET $3`, [id, limit + 1, offset])).rows;
      return { commands: rows.slice(0, limit).map(row => row.policy_context ? view(row) : { id: row.id, command: 'update_policy', status: 'legacy-unverified', payloadOmitted: true, reviewRequired: true, enforcementConfirmed: false }), truncated: rows.length > limit };
    } catch (error) { if (error.status) throw error; contract.fail(503, 'policy_command_storage_unavailable'); }
  }
}
module.exports = { PolicyDeviceQueue, operator, receipt, view };
