import contract from '../../packages/employee-invitation-contract.js';
import identity from '../../packages/identity-authorization-contract.js';
import { open, lstat } from 'node:fs/promises';
import { resolve } from 'node:path';

const fields = ['id', 'tenantId', 'userId', 'loginName', 'organizationName', 'status', 'revision', 'createdAt', 'expiresAt', 'credentialCreated', 'identityConfirmed'];
function record(value) {
  contract.exact(value, fields);
  for (const key of ['id', 'tenantId', 'userId']) contract.identifier(value[key]);
  if (!identity.validRevision(value.revision) || typeof value.loginName !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._@+-]{2,253}$/.test(value.loginName)
    || typeof value.organizationName !== 'string' || !value.organizationName.trim() || value.organizationName.length > 255
    || !['pending', 'credential_pending', 'accepted', 'revoked'].includes(value.status)
    || !['createdAt', 'expiresAt'].every(key => typeof value[key] === 'string' && Number.isFinite(Date.parse(value[key])) && new Date(value[key]).toISOString() === value[key])
    || Date.parse(value.expiresAt) <= Date.parse(value.createdAt)
    || typeof value.credentialCreated !== 'boolean' || typeof value.identityConfirmed !== 'boolean'
    || value.identityConfirmed !== (value.status === 'accepted') || value.status === 'pending' && value.credentialCreated
    || ['credential_pending', 'accepted'].includes(value.status) && !value.credentialCreated) throw new Error('Employee invitation record unconfirmed');
  return value;
}
function checked(response, status, extra) {
  const value = response.data;
  contract.exact(value, ['schemaVersion', 'employeeInvitationProtocol', ...extra]);
  if (response.status !== status || value.schemaVersion !== 1 || value.employeeInvitationProtocol !== 1) throw new Error('Employee invitation response unconfirmed');
  return value;
}
export function createEmployeeInvitationClient(client) {
  return {
    async list(page = 1) {
      if (!Number.isSafeInteger(page) || page < 1 || page > 1000000) throw new Error('Positive employee invitation page required');
      const value = checked(await client.employeeInvitation('list', { page }), 200, ['page', 'hasMore', 'invitations']);
      if (value.page !== page || typeof value.hasMore !== 'boolean' || !Array.isArray(value.invitations) || value.invitations.length > 25) throw new Error('Employee invitation page unconfirmed');
      value.invitations.forEach(record);
      if (new Set(value.invitations.map(row => row.id)).size !== value.invitations.length || new Set(value.invitations.map(row => row.tenantId)).size > 1) throw new Error('Original employee invitation page unconfirmed');
      return value;
    },
    async get(id) {
      contract.identifier(id);
      const value = checked(await client.employeeInvitation('get', { id }), 200, ['invitation']);
      if (record(value.invitation).id !== id) throw new Error('Original employee invitation unconfirmed');
      return value;
    },
    async create(raw) {
      const input = contract.createInput(raw);
      const response = await client.employeeInvitation('create', input);
      const value = response.data;
      if (typeof value?.created !== 'boolean') throw new Error('Employee invitation creation unconfirmed');
      checked(response, value.created ? 201 : 200, ['invitation', 'created', 'invitationToken', 'mailStatus']);
      const invitation = record(value.invitation);
      if (invitation.id !== input.id || invitation.userId !== input.userId || invitation.loginName !== input.loginName
        || Date.parse(invitation.expiresAt) - Date.parse(invitation.createdAt) !== input.durationHours * 3600000) throw new Error('Original employee invitation creation unconfirmed');
      if (value.created) {
        if (contract.parseToken(value.invitationToken).id !== input.id || invitation.status !== 'pending' || invitation.revision !== '1'
          || !['sent', 'failed', 'not_configured'].includes(value.mailStatus)) throw new Error('One-time employee invitation unconfirmed');
      } else if (value.invitationToken !== null || value.mailStatus !== 'not_sent') throw new Error('Replayed invitation must not disclose another secret');
      return value;
    },
    async revoke(raw) {
      contract.exact(raw, ['id', 'revision', 'reason', 'confirm']); contract.identifier(raw.id);
      if (!identity.validRevision(raw.revision) || raw.confirm !== true) throw new Error('Confirmed original employee invitation revision required');
      const input = { ...raw, reason: contract.text(raw.reason, 10, 500) };
      const value = checked(await client.employeeInvitation('revoke', input), 200, ['invitation', 'partialEnrollmentWithdrawn']);
      const invitation = record(value.invitation);
      if (invitation.id !== input.id || invitation.status !== 'revoked' || BigInt(invitation.revision) !== BigInt(input.revision) + 1n
        || value.partialEnrollmentWithdrawn !== true) throw new Error('Original employee invitation withdrawal unconfirmed');
      return value;
    },
  };
}

export async function createEmployeeInvitationFile(client, raw, filename) {
  const input = contract.createInput(raw);
  const resultFile = resolve(filename);
  const file = await open(resultFile, 'wx', 0o600);
  try {
    await file.chmod(0o600);
    const original = await file.stat({ bigint: true });
    if ((original.mode & 0o777n) !== 0o600n) throw new Error('Private POSIX invitation result permissions required');
    const response = await client.create(input);
    const current = await lstat(resultFile, { bigint: true });
    if (current.dev !== original.dev || current.ino !== original.ino) throw new Error('Invitation result destination changed');
    const { invitationToken, mailStatus, ...metadata } = response;
    const summary = { ...metadata, resultFile, mailRequestStatus: mailStatus === 'sent' ? 'provider_accepted' : mailStatus, deliveryConfirmed: false };
    await file.writeFile(JSON.stringify({ ...summary, invitationToken }, null, 2) + '\n');
    await file.sync();
    const retained = await lstat(resultFile, { bigint: true });
    if (retained.dev !== original.dev || retained.ino !== original.ino) throw new Error('Invitation result destination changed');
    return summary;
  } finally { await file.close(); }
}
