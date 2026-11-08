'use strict';

const { configuration } = require('../src/licenses/providers/ReadConfiguration');
const { ProviderReadClient } = require('../src/licenses/providers/ProviderReadClient');
const { ProviderError } = require('../src/licenses/fulfillment/transport');

async function probe(config, options) {
  const data = await new ProviderReadClient(config, options).inspect();
  if (config.provider === 'adobe-enterprise') return { ok: true, provider: config.provider, organizationId: data.organizationId,
    profileId: data.profileId, profileName: data.profileName, productName: data.productName, observedMembers: data.members.length };
  if (config.provider === 'slack-scim') return { ok: true, provider: config.provider, directoryKind: data.directoryKind, directoryId: data.directoryId,
    observedUsers: data.users.length, activeAccounts: data.users.filter(user => user.active).length };
  if (config.provider === 'atlassian-cloud') return { ok: true, provider: config.provider, organizationId: data.organizationId, directoryId: data.directoryId, observedUsers: data.users.length };
  if (config.provider === 'gitlab-cloud') return { ok: true, provider: config.provider, groupId: data.groupId, groupPath: data.groupPath, observedBillableMembers: data.billableMembers.length };
  return config.provider === 'google-workspace'
    ? { ok: true, provider: config.provider, customerId: data.customerId, productId: data.productId, skuId: data.skuId, assignedUsers: data.assignments.length }
    : { ok: true, provider: config.provider, organization: data.organization, billedSeats: data.totalSeats, pendingCancellations: data.seats.filter(seat => seat.pendingCancellationDate !== null).length };
}
async function main() {
  if (process.argv.length !== 2) throw new Error('Use the protected configuration file');
  const config = configuration(process.env.LICENSE_PROVIDER_PROBE_CONFIG_FILE);
  process.stdout.write(JSON.stringify(await probe(config)) + '\n');
}
if (require.main === module) main().catch(error => {
  const code = error instanceof ProviderError && /^(google_licenses|google_token|github_copilot|adobe_profiles|adobe_token|slack_directory|atlassian_directory|gitlab_billable)_[a-z0-9_]{1,80}$/.test(error.code) ? error.code : 'provider_probe_rejected';
  process.stderr.write(JSON.stringify({ ok: false, code, ...(error.retryAfter ? { retryAfter: error.retryAfter } : {}) }) + '\n'); process.exitCode = 1;
});
module.exports = { probe };
