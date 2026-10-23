'use strict';

const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const jwt = require('jsonwebtoken');
const contract = require('../../../../packages/employee-invitation-contract');
const { validTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { validRevision } = require('../../../../packages/identity-authorization-contract');

function fail(status, code) { throw Object.assign(new Error(code), { status, code }); }
function identifier(value) { try { contract.identifier(value); return true; } catch { return false; } }
function revision(value) { return typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) && !(value.length === 19 && value > '9223372036854775807'); }
function witness(value) { try { return contract.invitationWitness(value); } catch { fail(503, 'employee_invitation_unavailable'); } }
function pinnedOrigin(value, fallback) {
  let url;
  try { url = new URL(value || fallback); } catch { throw new Error('Pinned employee invitation receiver required'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('Pinned employee invitation receiver required');
  return url;
}
function validInvitation(value, witness) {
  const fields = ['id', 'tenantId', 'userId', 'loginName', 'organizationName', 'status', 'revision', 'createdAt', 'expiresAt', 'credentialCreated', 'identityConfirmed'];
  if (!value || Array.isArray(value) || Object.keys(value).length !== fields.length || fields.some(field => !Object.hasOwn(value, field))
    || value.id !== witness.id || value.userId !== witness.request.userId || value.tenantId !== witness.tenant.id
    || value.loginName !== witness.request.loginName || value.organizationName !== witness.source.organizationName
    || !['pending', 'credential_pending', 'accepted'].includes(value.status) || !validRevision(value.revision)
    || typeof value.createdAt !== 'string' || !Number.isFinite(Date.parse(value.createdAt)) || typeof value.expiresAt !== 'string' || !Number.isFinite(Date.parse(value.expiresAt))
    || typeof value.credentialCreated !== 'boolean' || typeof value.identityConfirmed !== 'boolean'
    || value.credentialCreated !== (witness.credential !== null) || value.identityConfirmed !== (value.status === 'accepted')) throw new Error('Invalid employee invitation response');
  return value;
}
function validReceipt(value, witness) {
  const fields = ['schemaVersion', 'employeeInvitationProtocol', 'invitationId', 'subjectId', 'userId', 'tenant', 'linkRevision', 'acceptanceEventId', 'confirmed'];
  if (!value || Array.isArray(value) || Object.keys(value).length !== fields.length || fields.some(field => !Object.hasOwn(value, field))
    || value.schemaVersion !== 1 || value.employeeInvitationProtocol !== 1 || value.invitationId !== witness.id || value.subjectId !== witness.subjectId
    || value.userId !== witness.request.userId || !validTenantContext(value.tenant) || value.tenant.id !== witness.tenant.id || !validRevision(value.linkRevision) || value.confirmed !== true) return false;
  try { contract.identifier(value.acceptanceEventId); return true; } catch { return false; }
}
function sameOriginal(first, next) {
  return first.id === next.id && first.subjectId === next.subjectId && first.creationEventId === next.creationEventId
    && isDeepStrictEqual(first.tenant, next.tenant) && isDeepStrictEqual(first.request, next.request) && isDeepStrictEqual(first.source, next.source);
}

class EmployeeInvitationGateway {
  constructor({ signingKeys, issuer, authEndpoint = process.env.OAUTH_EMPLOYEE_INVITATION_AUTH_URL || process.env.AUTH_SERVICE_URL || 'http://auth-service:3002',
    identityEndpoint = process.env.OAUTH_EMPLOYEE_INVITATION_IDENTITY_URL || process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001',
    fetchImpl = (...args) => global.fetch(...args) } = {}) {
    this.keys = signingKeys; this.issuer = issuer; this.auth = pinnedOrigin(authEndpoint, 'http://auth-service:3002');
    this.identity = pinnedOrigin(identityEndpoint, 'http://identity-service:3001'); this.fetch = fetchImpl;
  }
  assertion(operation, path, body, ownerAuthorization = null) {
    return jwt.sign({ iss: this.issuer, sub: 'oauth-provider', aud: contract.AUDIENCE, token_use: contract.PURPOSE, actor_type: 'workload',
      scope: 'employees.invitations.' + operation, htm: 'POST', htu: path, body_sha256: contract.digest(body), owner_sha256: ownerAuthorization ? contract.digest(ownerAuthorization) : null, jti: crypto.randomUUID() },
    this.keys.privateKey, { algorithm: 'RS256', keyid: this.keys.kid, header: { typ: contract.TYPE }, expiresIn: 30 });
  }
  async request(receiver, operation, path, body, ownerAuthorization = null) {
    const assertion = this.assertion(operation, path, body, ownerAuthorization); const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 4000);
    try {
      const headers = { Authorization: 'Bearer ' + assertion, 'Content-Type': 'application/json', ...(ownerAuthorization ? { 'X-OpenDirectory-Owner-Authorization': ownerAuthorization } : {}) };
      const response = await this.fetch(new URL(path, receiver), { method: 'POST', headers,
        body: JSON.stringify(body), redirect: 'error', cache: 'no-store', signal: controller.signal });
      if (![200, 201].includes(response.status) || !response.headers.get('content-type')?.includes('application/json')) {
        if ([400, 401, 403, 404, 409, 412, 429].includes(response.status)) fail(response.status, response.status === 401 || response.status === 404 ? 'invalid_employee_invitation' : 'employee_invitation_rejected');
        fail(503, 'employee_invitation_unavailable');
      }
      const chunks = []; let length = 0;
      for await (const chunk of response.body) { length += chunk.length; if (length > 32768) throw new Error('Oversized employee invitation response'); chunks.push(Buffer.from(chunk)); }
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch (error) { if (error.status) throw error; fail(503, 'employee_invitation_unavailable'); }
    finally { clearTimeout(timer); controller.abort(); }
  }
  async inspectToken(token) {
    contract.parseToken(token);
    const input = { token };
    const result = await this.request(this.auth, 'inspect', contract.AUTH_BASE + '/inspect', input);
    contract.exact(result, ['schemaVersion', 'employeeInvitationProtocol', 'invitation', 'witness']);
    if (result.schemaVersion !== 1 || result.employeeInvitationProtocol !== 1) fail(503, 'employee_invitation_unavailable');
    const original = witness(result.witness);
    try { validInvitation(result.invitation, original); } catch { fail(503, 'employee_invitation_unavailable'); }
    return { witness: original, invitation: result.invitation };
  }
  publicInvitation(invitation) {
    return { organizationName: invitation.organizationName, loginName: invitation.loginName, status: invitation.status,
      expiresAt: invitation.expiresAt, credentialCreated: invitation.credentialCreated, identityConfirmed: invitation.identityConfirmed };
  }
  async inspect(token) { return this.publicInvitation((await this.inspectToken(token)).invitation); }
  async manage(operation, raw, authorization, expectedActorUserId) {
    if (typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)) fail(401, 'employee_invitation_owner_required');
    let input;
    if (operation === 'create') input = contract.createInput(raw);
    else if (operation === 'list') { contract.exact(raw, ['page']); if (!Number.isSafeInteger(raw.page) || raw.page < 1 || raw.page > 1000000) fail(400, 'positive_employee_invitation_page_required'); input = raw; }
    else if (operation === 'get') { contract.exact(raw, ['id']); contract.identifier(raw.id); input = raw; }
    else if (operation === 'revoke') {
      contract.exact(raw, ['id', 'revision', 'reason', 'confirm']); contract.identifier(raw.id);
      if (!revision(raw.revision) || raw.confirm !== true) fail(400, 'confirmed_employee_invitation_revocation_required');
      input = { ...raw, reason: contract.text(raw.reason, 10, 500) };
    } else fail(404, 'employee_invitation_operation_not_found');

    const path = contract.AUTH_BASE + '/' + operation;
    const value = await this.request(this.auth, operation, path, input, authorization);
    const baseFields = ['schemaVersion', 'employeeInvitationProtocol', 'actorUserId', 'tenant'];
    if (value?.schemaVersion !== 1 || value.employeeInvitationProtocol !== 1 || value.actorUserId !== expectedActorUserId || !validTenantContext(value.tenant)) fail(503, 'employee_invitation_unavailable');
    let invitation;
    if (operation === 'create') {
      contract.exact(value, [...baseFields, 'invitation', 'created', 'invitationToken']);
      invitation = value.invitation;
      if (typeof value.created !== 'boolean' || value.created && typeof value.invitationToken !== 'string' || !value.created && value.invitationToken !== null) fail(503, 'employee_invitation_unavailable');
      if (value.invitationToken !== null) contract.parseToken(value.invitationToken);
      this.validManagementInvitation(invitation, value.tenant);
      return { schemaVersion: 1, employeeInvitationProtocol: 1, invitation, created: value.created, invitationToken: value.invitationToken };
    }
    if (operation === 'list') {
      contract.exact(value, [...baseFields, 'page', 'hasMore', 'invitations']);
      if (value.page !== input.page || typeof value.hasMore !== 'boolean' || !Array.isArray(value.invitations) || value.invitations.length > 25) fail(503, 'employee_invitation_unavailable');
      for (const row of value.invitations) this.validManagementInvitation(row, value.tenant);
      return { schemaVersion: 1, employeeInvitationProtocol: 1, page: value.page, hasMore: value.hasMore, invitations: value.invitations };
    }
    if (operation === 'get') {
      contract.exact(value, [...baseFields, 'invitation']); invitation = value.invitation; this.validManagementInvitation(invitation, value.tenant);
      return { schemaVersion: 1, employeeInvitationProtocol: 1, invitation };
    }
    contract.exact(value, [...baseFields, 'invitation', 'witness']); invitation = value.invitation; this.validManagementInvitation(invitation, value.tenant);
    const revokeWitness = witness(value.witness);
    if (invitation.id !== input.id || revokeWitness.id !== input.id || invitation.status !== 'revoked') fail(503, 'employee_invitation_unavailable');
    const withdrawalInput = { witness: revokeWitness };
    const withdrawal = await this.request(this.identity, 'withdraw', contract.IDENTITY_BASE + '/withdraw', withdrawalInput);
    contract.exact(withdrawal, ['invitationId', 'withdrawn', 'changed', 'receipt']);
    if (withdrawal.invitationId !== input.id || withdrawal.withdrawn !== true || typeof withdrawal.changed !== 'boolean') fail(503, 'employee_invitation_withdrawal_unconfirmed');
    return { schemaVersion: 1, employeeInvitationProtocol: 1, invitation, partialEnrollmentWithdrawn: true };
  }
  validManagementInvitation(value, tenant) {
    const fields = ['id', 'tenantId', 'userId', 'loginName', 'organizationName', 'status', 'revision', 'createdAt', 'expiresAt', 'credentialCreated', 'identityConfirmed'];
    if (!value || Array.isArray(value) || Object.keys(value).length !== fields.length || fields.some(field => !Object.hasOwn(value, field))
      || !revision(value.revision) || value.tenantId !== tenant.id || !identifier(value.id) || !identifier(value.userId)
      || typeof value.loginName !== 'string' || typeof value.organizationName !== 'string' || !['pending', 'credential_pending', 'accepted', 'revoked'].includes(value.status)
      || typeof value.createdAt !== 'string' || !Number.isFinite(Date.parse(value.createdAt)) || typeof value.expiresAt !== 'string' || !Number.isFinite(Date.parse(value.expiresAt))
      || typeof value.credentialCreated !== 'boolean' || typeof value.identityConfirmed !== 'boolean'
      || value.identityConfirmed !== (value.status === 'accepted')) fail(503, 'employee_invitation_unavailable');
    return value;
  }
  async accept(input) {
    contract.exact(input, ['token', 'password']); contract.parseToken(input.token); contract.password(input.password);
    const { witness: original } = await this.inspectToken(input.token);
    const observationBody = { witness: original }; const observationProof = this.assertion('observe', contract.IDENTITY_BASE + '/observe', observationBody);
    const credentialInput = { token: input.token, password: input.password, observationAssertion: observationProof };
    const credential = await this.request(this.auth, 'credential', contract.AUTH_BASE + '/credential', credentialInput);
    try { contract.exact(credential, ['invitation', 'witness']); } catch { fail(503, 'employee_invitation_unavailable'); }
    const credentialWitness = witness(credential.witness);
    if (!sameOriginal(original, credentialWitness)) fail(409, 'employee_invitation_changed');
    try { validInvitation(credential.invitation, credentialWitness); } catch { fail(503, 'employee_invitation_unavailable'); }

    const completionBody = { witness: credentialWitness };
    const completion = await this.request(this.identity, 'complete', contract.IDENTITY_BASE + '/complete', completionBody);
    try { contract.exact(completion, ['receipt', 'active', 'replayed']); } catch { fail(503, 'employee_invitation_unavailable'); }
    if (completion.active !== true || typeof completion.replayed !== 'boolean' || !validReceipt(completion.receipt, credentialWitness)) fail(409, 'employee_invitation_activation_unconfirmed');

    const activationBody = { id: credentialWitness.id, receipt: completion.receipt };
    const activated = await this.request(this.auth, 'activate', contract.AUTH_BASE + '/activate', activationBody);
    try { contract.exact(activated, ['invitation', 'witness', 'replayed']); } catch { fail(503, 'employee_invitation_unavailable'); }
    const activatedWitness = witness(activated.witness);
    try { validInvitation(activated.invitation, activatedWitness); } catch { fail(503, 'employee_invitation_unavailable'); }
    if (activated.invitation.status !== 'accepted' || activated.invitation.credentialCreated !== true || activated.invitation.identityConfirmed !== true || !sameOriginal(credentialWitness, activatedWitness)
      || !validReceipt(completion.receipt, activatedWitness) || typeof activated.replayed !== 'boolean') fail(503, 'employee_invitation_activation_unconfirmed');
    return { schemaVersion: 1, employeeInvitationProtocol: 1, status: 'accepted', organizationName: activated.invitation.organizationName,
      loginName: activated.invitation.loginName, mfaEnrollmentRequired: true };
  }
}

module.exports = { EmployeeInvitationGateway };
