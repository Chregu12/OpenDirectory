'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const contract = require('../../../../packages/credential-authorization-contract');
const { validTenantContext } = require('../../../../packages/tenant-authorization-contract');

class CredentialAuthorityError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}

class CredentialAuthority {
  constructor({ signingKeys, issuer, endpoint = process.env.AUTH_SERVICE_URL || 'http://auth-service:3002', fetchImpl = (...args) => global.fetch(...args) }) {
    const url = new URL(endpoint);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash || url.search || url.pathname !== '/') {
      throw new Error('Invalid credential authority URL');
    }
    this.url = url; this.keys = signingKeys; this.issuer = issuer; this.fetch = fetchImpl;
  }

  async state(subject) {
    if (!contract.validSubject(subject)) throw new CredentialAuthorityError(403, 'credential_subject_ineligible');
    const path = contract.PATH;
    const assertion = jwt.sign({ iss: this.issuer, sub: 'oauth-provider', aud: contract.AUDIENCE, actor_type: 'workload',
      token_use: contract.PURPOSE, scope: contract.SCOPE, htm: 'POST', htu: path, request_subject: subject, jti: crypto.randomUUID() },
    this.keys.privateKey, { algorithm: 'RS256', keyid: this.keys.kid, header: { typ: contract.TYPE }, expiresIn: 30 });
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 1500);
    try {
      const response = await this.fetch(new URL(path, this.url), { method: 'POST', redirect: 'error', cache: 'no-store',
        headers: { Authorization: 'Bearer ' + assertion, 'Content-Type': 'application/json' }, body: JSON.stringify({ subject }), signal: controller.signal });
      if (response.status !== 200 || !response.headers.get('content-type')?.includes('application/json')) throw new Error('Credential authority unavailable');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) { length += chunk.length; if (length > 32768) throw new Error('Oversized credential response'); chunks.push(Buffer.from(chunk)); }
      const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!contract.exact(value, ['schemaVersion','credentialAuthenticationProtocol','subject','known','ready','subjectId','securityRevision','invitation'])
        || value.schemaVersion !== 1 || value.credentialAuthenticationProtocol !== 1 || value.subject !== subject || typeof value.known !== 'boolean'
        || typeof value.ready !== 'boolean') throw new Error('Malformed credential state');
      if (!value.known) {
        if (value.ready || value.subjectId !== null || value.securityRevision !== null || value.invitation !== null) throw new Error('Malformed unknown credential state');
        return { known: false, ready: false, binding: null, invitation: null };
      }
      if (!contract.uuid(value.subjectId) || value.subjectId !== subject || (value.ready
        ? !contract.validRevision(value.securityRevision)
        : value.securityRevision !== null)) throw new Error('Malformed known credential state');
      let invitation = null;
      if (value.invitation !== null) {
        const item = value.invitation;
        if (!contract.exact(item, ['invitationId','userId','tenant']) || !contract.uuid(item.invitationId) || !contract.uuid(item.userId) || !validTenantContext(item.tenant)) throw new Error('Malformed invitation state');
        invitation = item;
      }
      if (!value.ready) throw new CredentialAuthorityError(403, 'credential_not_eligible');
      return { known: true, ready: true, subjectId: value.subjectId, securityRevision: value.securityRevision, invitation };
    } catch (error) {
      if (error instanceof CredentialAuthorityError) throw error;
      throw new CredentialAuthorityError(503, 'credential_authority_unavailable');
    } finally { clearTimeout(timer); controller.abort(); }
  }
}

module.exports = { CredentialAuthority, CredentialAuthorityError };
