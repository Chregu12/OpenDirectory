'use strict';

const { createRemoteJWKSet, jwtVerify } = require('jose');
const { BASE_PATH, AUDIENCE, PURPOSE, TYPE, normalizeInternal, identifier, validReceipt } = require('../../../../packages/company-registration-contract');
const { requestDigest } = require('../../../../packages/company-registration-contract/digest');
function fail(status, code, cause) { throw Object.assign(new Error(code, cause ? { cause } : undefined), { status, code }); }
function registrationRequest({ issuer = process.env.OIDC_ISSUER || 'http://localhost:3001', jwksUri = process.env.JWKS_URI || 'http://localhost:3001/jwks' } = {}) {
  let keys;
  return operation => async (req, res, next) => {
    try {
      if (!req.headers.authorization?.startsWith('Bearer ') || Object.keys(req.query || {}).length) fail(401, 'invalid_registration_proof');
      if (!keys) keys = createRemoteJWKSet(new URL(jwksUri));
      const claims = ['iss', 'sub', 'aud', 'token_use', 'actor_type', 'htm', 'htu', 'body_sha256', 'registration_subject', 'jti', 'iat', 'exp'];
      const { payload, protectedHeader } = await jwtVerify(req.headers.authorization.slice(7), keys, { issuer, audience: AUDIENCE, algorithms: ['RS256'], requiredClaims: claims, maxTokenAge: '30s' });
      const input = normalizeInternal(operation, req.body);
      if (protectedHeader.typ !== TYPE || Object.keys(payload).length !== claims.length || payload.sub !== 'oauth-provider' || payload.token_use !== PURPOSE || payload.actor_type !== 'workload'
        || payload.htm !== 'POST' || payload.htu !== BASE_PATH + '/' + operation || payload.registration_subject !== input.subject || !identifier(payload.jti)
        || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp) || payload.exp <= payload.iat || payload.exp > payload.iat + 30 || payload.iat > Math.floor(Date.now() / 1000)
        || payload.body_sha256 !== requestDigest(operation, input)) fail(401, 'invalid_registration_proof');
      req.registrationProof = payload; req.registrationInput = input; req.authorityIssuer = payload.iss; next();
    } catch (error) {
      const status = error.status || (/^ERR_J(?:WT|WS|OSE)/.test(error.code || '') ? 401 : 503);
      res.set('Cache-Control', 'no-store').status(status).json({ error: status === 503 ? 'registration_authority_unavailable' : 'invalid_registration_request' });
    }
  };
}
function registrationError(error) {
  const status = error.status || ({ '23503': 404, '23505': 409, '23514': 400, '28000': 401, '42501': 503 }[error.code]) || 503;
  fail(status, ({ 400: 'invalid_company_registration', 401: 'registration_proof_expired', 404: 'registration_not_found', 409: 'registration_conflict' })[status] || 'company_registration_unavailable', error);
}
class CompanyRegistrations {
  constructor(database) { this.database = database; }
  async receive(operation, input, claims) {
    input = normalizeInternal(operation, structuredClone(input)); claims = structuredClone(claims);
    if (claims?.token_use !== PURPOSE || claims.actor_type !== 'workload' || claims.registration_subject !== input.subject || claims.body_sha256 !== requestDigest(operation, input)
      || !identifier(claims.jti) || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) || claims.exp <= Math.floor(Date.now() / 1000) || claims.exp > claims.iat + 30) fail(401, 'invalid_registration_proof');
    return this.database.transaction(async client => {
      await client.query("SET LOCAL timezone='UTC'"); await client.query('SELECT identity_company_registration_receiving()');
      await client.query('SELECT identity_company_activation_receiving()');
      let replayed = true;
      if (operation === 'submit' || operation === 'activate') {
        const proof = { issuer: claims.iss, subject: input.subject, nonce: claims.jti, issuedAt: claims.iat, expiresAt: claims.exp, requestSha256: claims.body_sha256 };
        const routine = operation === 'activate' ? 'identity_company_activate' : 'identity_company_activation_admit';
        const admission = (await client.query(`SELECT ${routine}($1::jsonb,$2::jsonb) AS receipt`, [JSON.stringify(proof), JSON.stringify(input)])).rows[0]?.receipt;
        if (!identifier(admission?.id) || operation === 'submit' && admission.id !== input.registrationId || typeof admission.replayed !== 'boolean') fail(503, 'company_registration_unavailable'); replayed = admission.replayed;
      }
      const row = (await client.query(`SELECT registration.*,identity_company_registration_retained_valid(registration.id) AS valid FROM identity_company_registrations registration
        WHERE registration.id=$1 AND registration.issuer=$2 AND registration.subject=$3`, [input.registrationId, claims.iss, input.subject])).rows[0];
      if (!row) fail(404, 'registration_not_found'); if (row.valid !== true) fail(503, 'company_registration_unavailable');
      const receipt = { schemaVersion: 1, registrationId: row.id, tenantId: row.tenant_id, administratorId: row.user_id, createdAt: row.created_at.toISOString(),
        status: 'pending-verification', tenantEnabled: false, administratorEnabled: false, profileSaved: false, activationSupported: false, replayed };
      const review = (await client.query('SELECT *,identity_company_review_valid(registration_id) AS valid FROM identity_company_registration_reviews WHERE registration_id=$1', [row.id])).rows[0];
      if (review) {
        if (!review.valid) fail(503, 'company_registration_unavailable');
        receipt.schemaVersion = 2; receipt.status = review.decision === 'approved' ? 'pending-activation' : 'rejected'; receipt.reviewedAt = review.created_at.toISOString();
      }
      const activation = (await client.query(`SELECT activation.*,tenant.enabled AS tenant_enabled,identity_company_owner_active(activation) AS user_enabled FROM identity_company_activations activation
        JOIN identity_tenants tenant ON tenant.id=activation.tenant_id JOIN users account ON account.id=activation.user_id WHERE activation.registration_id=$1`, [row.id])).rows[0];
      if (activation) {
        receipt.schemaVersion = 3; receipt.status = activation.tenant_enabled && activation.user_enabled ? 'active' : 'suspended'; receipt.tenantEnabled = activation.tenant_enabled; receipt.administratorEnabled = activation.user_enabled;
        receipt.profileSaved = true; receipt.activationSupported = true; receipt.activatedAt = activation.created_at.toISOString(); receipt.consoleClientId = activation.console_client_id; receipt.mfaRequired = true;
      }
      if (!validReceipt(receipt, input.registrationId)) fail(503, 'company_registration_unavailable'); return receipt;
    }, { readOnly: operation === 'status' }).catch(registrationError);
  }
}
module.exports = { CompanyRegistrations, registrationRequest };
