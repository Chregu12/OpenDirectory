'use strict';

const { randomUUID } = require('node:crypto');
const { readRoleState } = require('./RoleState');
const { validContext, validUuid, validRevision } = require('../../../../packages/identity-authorization-contract');
const { validTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');

function fail(status, code) { throw Object.assign(new Error(code), { status, code }); }
function checkpointError(error) { if (error.code === '28000') error.status = 401; throw error; }
async function beginAuthorityCheckpoint(client, claims) {
  if (!claims || typeof claims !== 'object') fail(401, 'original_command_claims_required');
  const user = structuredClone(claims);
  if (user.actor_type !== 'user' || typeof user.iss !== 'string' || !user.iss || typeof user.sub !== 'string' || !user.sub.trim()
    || !validContext(user.identity_authorization) || !Number.isSafeInteger(user.exp) || typeof user.jti !== 'string' || !user.jti || user.jti.length > 128) fail(401, 'original_command_claims_required');
  await client.query("SET LOCAL timezone='UTC'");
  const source = await readRoleState(client, user.identity_authorization.userId);
  if (source.rolesRevision !== user.identity_authorization.rolesRevision) fail(401, 'original_command_authority_changed');
  if (!acceptsRoleAuthentication(source.authentication, user)) fail(428, 'fresh_mfa_required');
  const proof = { ...user.identity_authorization, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp };
  const initial = (await client.query('SELECT identity_authority_command_context($1::jsonb) AS context', [JSON.stringify(proof)])).rows[0]?.context;
  if (initial?.schemaVersion !== 1 || Object.keys(initial).length !== 5 || !validTenantContext(initial.tenant) || initial.userId !== user.identity_authorization.userId
    || initial.linkRevision !== user.identity_authorization.linkRevision || !validRevision(initial.tenantGeneration)) fail(503, 'command_checkpoint_context_unavailable');
  const originalDeadline = Math.min(user.exp, source.authentication.required ? user.auth_time + source.authentication.maxAgeSeconds : Infinity);
  return async required => {
    const deadline = Math.min(originalDeadline, required?.required === true ? user.auth_time + required.maxAgeSeconds : Infinity);
    if (!Number.isSafeInteger(deadline) || deadline * 1000 <= Date.now()) fail(401, 'original_command_assurance_expired');
    const id = randomUUID();
    const record = (await client.query('SELECT identity_authority_command_checkpoint($1::uuid,$2::jsonb,$3::jsonb,$4::bigint) AS checkpoint', [id, JSON.stringify(proof), JSON.stringify(initial), String(deadline)])).rows[0]?.checkpoint;
    if (!record || Object.keys(record).length !== 4 || !validUuid(record.id) || record.id !== id || record.tenantId !== initial.tenant.id || record.validUntil !== String(deadline) || record.recorded !== true) fail(503, 'command_checkpoint_unavailable');
    const receipt = await client.query(`SELECT checkpoint.id FROM identity_authority_command_checkpoints checkpoint
      JOIN identity_authority_command_checkpoint_events event USING(id) JOIN identity_authority_command_checkpoint_outbox outbox USING(id)
      WHERE checkpoint.id=$1 AND checkpoint.tenant_id=$2 AND checkpoint.user_id=$3 AND checkpoint.transaction_id=txid_current()
      AND checkpoint.token_sha256=identity_authority_hash($4::jsonb) AND extract(epoch FROM checkpoint.valid_until)=$5::bigint
      AND event.tenant_id=checkpoint.tenant_id AND outbox.tenant_id=checkpoint.tenant_id AND event.action='authority-checkpoint' AND outbox.action=event.action AND outbox.status='pending'
      AND event.scope_sha256=identity_authority_hash(to_jsonb(checkpoint))`, [id, initial.tenant.id, user.identity_authorization.userId, JSON.stringify(user.jti), String(deadline)]);
    if (receipt.rows.length !== 1 || receipt.rows[0].id !== id) fail(503, 'command_checkpoint_receipt_unavailable');
  };
}

module.exports = { beginAuthorityCheckpoint, checkpointError };
