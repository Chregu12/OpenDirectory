'use strict';
const { randomUUID } = require('node:crypto');
const { CompanyRegistrations } = require('../../services/core/identity-service/src/CompanyRegistrations');
const { CompanyRegistrationReviews } = require('../../services/core/identity-service/src/CompanyRegistrationReviews');
const { AuthorizationState } = require('../../services/core/identity-service/src/AuthorizationState');
const { changeOperator } = require('../../services/core/identity-service/scripts/company-review-operator');
const { PURPOSE, AUDIENCE, BASE_PATH } = require('../../packages/company-registration-contract');
const { requestDigest } = require('../../packages/company-registration-contract/digest');
const { provisionTenant, adoptTenant } = require('./tenant-ownership-fixture.cjs');
async function activeCompany(database, schema, issuer, { subject: selectedSubject, username: selectedUsername } = {}) {
  const state = new AuthorizationState(database);
  const claims = async subject => { const current = await state.state(issuer, subject); const now = Math.floor(Date.now() / 1000); return {
    iss: issuer, sub: subject, actor_type: 'user', token_use: 'access', roles: current.roles, identity_authorization: current.context, jti: randomUUID(), exp: now + 3600, auth_time: now, amr: ['pwd', 'otp'],
    mfa_authorization: { schemaVersion: 1, userId: current.context.userId, revision: '1', authTime: now, methods: ['pwd', 'otp'] },
  }; };
  const reviewerId = randomUUID(); const reviewerSubject = 'reviewer-' + reviewerId;
  await database.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [reviewerId, reviewerSubject, reviewerSubject + '@example.invalid']);
  await database.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, reviewerSubject, reviewerId]);
  const home = (await database.query("SELECT identity_tenant_id('user',$1::uuid) AS id", [reviewerId])).rows[0]?.id;
  if (!home) { const tenant = await provisionTenant(database, schema, { enabled: true }); await adoptTenant(database, schema, tenant, [{ kind: 'user', resourceId: reviewerId }]); }
  await changeOperator(database, { issuer, userId: reviewerId, version: '0', enabled: true, reason: 'Actual independent company reviewer native fixture' });
  const registrationId = randomUUID(); const subject = selectedSubject || 'owner-' + registrationId;
  const profile = { name: 'Automation company', legalForm: 'AG', registrationNumber: '', taxId: '', addressLine1: 'Business Street 1', addressLine2: '', postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'UTC', defaultLanguage: 'de', contactEmail: 'office@example.invalid', contactPhone: '', website: '' };
  const input = { registrationId, subject, principal: { username: selectedUsername || subject, email: subject + '@example.invalid', displayName: 'Actual company owner' }, profile };
  const registrations = new CompanyRegistrations(database);
  const receive = (operation, body) => { const now = Math.floor(Date.now() / 1000); return registrations.receive(operation, body, {
    iss: issuer, sub: 'oauth-provider', aud: AUDIENCE, token_use: PURPOSE, actor_type: 'workload', htm: 'POST', htu: BASE_PATH + '/' + operation,
    body_sha256: requestDigest(operation, body), registration_subject: subject, jti: randomUUID(), iat: now, exp: now + 30,
  }); };
  await receive('submit', input); const reviewer = await claims(reviewerSubject);
  const reviews = new CompanyRegistrationReviews(database, { revalidate: async () => {} }); const before = await reviews.get(registrationId, reviewer);
  await reviews.decide(registrationId, { decision: 'approved', reason: 'Actual independent company evidence review', confirm: true }, before.etag, reviewer, 'Bearer native-reviewer');
  const receipt = await receive('activate', { registrationId, subject, consoleClientId: 'web-app' });
  return { user: await claims(subject), receipt };
}
module.exports = { activeCompany };
