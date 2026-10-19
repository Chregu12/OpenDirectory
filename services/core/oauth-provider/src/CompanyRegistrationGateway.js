'use strict';

const { randomUUID } = require('node:crypto');
const jwt = require('jsonwebtoken');
const { BASE_PATH, AUDIENCE, PURPOSE, TYPE, normalizeInternal, normalizePublic, principalFor, validReceipt } = require('../../../../packages/company-registration-contract');
const { requestDigest } = require('../../../../packages/company-registration-contract/digest');
const { authenticateUser } = require('./authenticateUser');
const { protectedClient } = require('./ClientRegistry');
function fail(status, code) { throw Object.assign(new Error(code), { status, code }); }
class CompanyRegistrationGateway {
  constructor({ signingKeys, issuer, endpoint = process.env.OAUTH_IDENTITY_AUTHORITY_URL || 'http://identity-service:3001/internal/identity/authorization-state',
    authenticate = authenticateUser, fetchImpl = (...args) => global.fetch(...args), consoleClientId = process.env.COMPANY_CONSOLE_CLIENT_ID || '', client = async () => null }) {
    const url = new URL(endpoint);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/internal/identity/authorization-state') throw new Error('Invalid company registration receiver URL');
    this.endpoint = url; this.keys = signingKeys; this.issuer = issuer; this.authenticate = authenticate; this.fetch = fetchImpl; this.consoleClientId = consoleClientId; this.client = client;
  }
  async execute(operation, body) {
    body = normalizePublic(operation, body);
    const authenticated = await this.authenticate({ username: body.username, password: body.password, ...(body.mfaCode ? { mfaCode: body.mfaCode } : {}) });
    if (authenticated.error) fail(authenticated.status, authenticated.error);
    if (operation === 'activate') {
      const configured = await this.client(this.consoleClientId);
      if (!configured?.enabled || configured.publicClient || !configured.grantTypes.includes('authorization_code') || !protectedClient(configured)) fail(503, 'company_console_configuration_required');
    }
    let input;
    try { input = normalizeInternal(operation, { registrationId: body.registrationId, subject: authenticated.user?.id,
      ...(operation === 'submit' ? { principal: principalFor(authenticated.user).principal, profile: body.profile } : operation === 'activate' ? { consoleClientId: this.consoleClientId } : {}) }); }
    catch { fail(503, 'registration_principal_unavailable'); }
    const path = BASE_PATH + '/' + operation;
    const assertion = jwt.sign({ iss: this.issuer, sub: 'oauth-provider', aud: AUDIENCE, token_use: PURPOSE, actor_type: 'workload',
      htm: 'POST', htu: path, body_sha256: requestDigest(operation, input), registration_subject: input.subject, jti: randomUUID() }, this.keys.privateKey,
    { algorithm: 'RS256', keyid: this.keys.kid, header: { typ: TYPE }, expiresIn: 30 });
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await this.fetch(new URL(path, this.endpoint), { method: 'POST', redirect: 'error', cache: 'no-store', signal: controller.signal,
        headers: { Authorization: 'Bearer ' + assertion, 'Content-Type': 'application/json' }, body: JSON.stringify(input) });
      if (![200, 201].includes(response.status)) fail([400, 401, 404, 409, 429].includes(response.status) ? response.status : 503,
        ({ 400: 'invalid_company_registration', 401: 'registration_proof_expired', 404: 'registration_not_found', 409: 'registration_conflict', 429: 'registration_rate_limited' })[response.status] || 'company_registration_unavailable');
      if (!response.headers.get('content-type')?.includes('application/json')) fail(503, 'company_registration_unavailable');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) { length += chunk.length; if (length > 16384) fail(503, 'company_registration_unavailable'); chunks.push(Buffer.from(chunk)); }
      const receipt = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!validReceipt(receipt, input.registrationId) || operation === 'status' && !receipt.replayed || operation === 'activate' && (receipt.schemaVersion !== 3 || receipt.consoleClientId !== this.consoleClientId)) fail(503, 'company_registration_unavailable');
      return receipt;
    } catch (error) { if (error.status) throw error; fail(503, 'company_registration_unavailable'); }
    finally { clearTimeout(timer); controller.abort(); }
  }
}
module.exports = { CompanyRegistrationGateway };
