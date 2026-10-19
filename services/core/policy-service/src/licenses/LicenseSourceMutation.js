'use strict';

const { LicenseError } = require('./LicenseError');

async function syncRecipients(allocator, client, licenseId, sources, actor, deadline = Infinity) {
  await allocator.assertPoolAccess(licenseId, client, { legacyOnly: true });
  let retained = 0;
  for (const userId of new Set(sources.map(source => source.user_id))) {
    if (Date.now() > deadline) throw new LicenseError(503, 'license_review_verification_timeout');
    await allocator.assertLegacySubject(userId, client);
    const result = await allocator.syncUser(client, licenseId, userId, actor);
    if (result.added) throw new LicenseError(409, 'license_projection_requires_reconciliation');
    if (result.row) retained++;
  }
  await allocator.syncCounter(client, licenseId);
  return retained;
}

async function withdrawSource(allocator, client, grant, actor, deadline = Infinity) {
  await allocator.assertPoolAccess(grant.licenseId, client, { legacyOnly: true });
  const sources = (await client.query('SELECT user_id FROM license_assignment_sources WHERE grant_id=$1 AND license_id=$2', [grant.id, grant.licenseId])).rows;
  for (const userId of new Set(sources.map(source => source.user_id))) await allocator.assertLegacySubject(userId, client);
  if (grant.kind === 'group') {
    await client.query("UPDATE license_group_rules SET enabled=false,status='revoked',last_error=NULL WHERE grant_id=$1 AND license_id=$2", [grant.id, grant.licenseId]);
    await client.query("UPDATE license_requests SET allocation_status='revoked' WHERE license_id=$1 AND assignee_type='group' AND assignee_id=$2 AND status='approved'", [grant.licenseId, grant.recipientId]);
  }
  await client.query('DELETE FROM license_assignment_sources WHERE grant_id=$1 AND license_id=$2', [grant.id, grant.licenseId]);
  const usersRetainingAssignment = await syncRecipients(allocator, client, grant.licenseId, sources, actor, deadline);
  return { sourcesRemoved: sources.length, usersRetainingAssignment };
}

module.exports = { syncRecipients, withdrawSource };
