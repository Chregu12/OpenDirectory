'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

class BrowserAuthError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}

function secretFile(filename, binary = false) {
  let descriptor;
  try {
    if (!path.isAbsolute(filename || '')) throw new Error('Absolute secret path required');
    descriptor = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0));
    const info = fs.fstatSync(descriptor);
    if (!info.isFile() || info.size > 4096 || !info.size || typeof process.getuid !== 'function'
      || (info.uid !== process.getuid() && info.uid !== 0) || (info.mode & 0o077)) throw new Error('Unprotected secret');
    const data = Buffer.alloc(4097); let length = 0;
    while (length < data.length) {
      const count = fs.readSync(descriptor, data, length, data.length - length, null);
      if (!count) break;
      length += count;
    }
    if (length > 4096) throw new Error('Oversized secret');
    const value = data.subarray(0, length);
    if (binary) { if (value.length !== 32) throw new Error('A 256-bit cookie key is required'); return Buffer.from(value); }
    const text = value.toString('utf8').trim();
    if (!/^[A-Za-z0-9_-]{32,128}$/.test(text)) throw new Error('Invalid client secret');
    return text;
  } catch { throw new BrowserAuthError(503, 'browser_auth_secret_unavailable'); }
  finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}

function safeUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new BrowserAuthError(503, 'browser_auth_configuration_invalid'); }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new BrowserAuthError(503, 'browser_auth_configuration_invalid');
  return url;
}

function equal(first, second) {
  if (typeof first !== 'string' || typeof second !== 'string') return false;
  const firstBytes = Buffer.from(first); const secondBytes = Buffer.from(second);
  return firstBytes.length === secondBytes.length && crypto.timingSafeEqual(firstBytes, secondBytes);
}

function cookieValue(request, name) {
  const matching = (request.headers.get('cookie') || '').split(';').map(part => part.trim()).filter(part => part.startsWith(name + '='));
  if (matching.length !== 1) return null;
  return matching[0].slice(name.length + 1);
}

class BrowserAuth {
  constructor({ origin = process.env.BROWSER_AUTH_ORIGIN, issuer = process.env.BROWSER_AUTH_ISSUER,
    publicUrl = process.env.BROWSER_AUTH_PUBLIC_URL, internalUrl = process.env.BROWSER_AUTH_INTERNAL_URL,
    clientId = process.env.BROWSER_AUTH_CLIENT_ID || 'web-app', keyFile = process.env.BROWSER_AUTH_KEY_FILE,
    clientSecretFile = process.env.BROWSER_AUTH_CLIENT_SECRET_FILE, allowHttpLoopback = process.env.BROWSER_AUTH_ALLOW_HTTP_LOOPBACK === 'true',
    apiAudience = process.env.BROWSER_AUTH_API_AUDIENCE || 'opendirectory-api',
    fetchImpl = (...args) => global.fetch(...args), now = () => Date.now() } = {}) {
    this.origin = safeUrl(origin).origin; this.issuer = safeUrl(issuer).origin;
    this.publicUrl = safeUrl(publicUrl); this.internalUrl = safeUrl(internalUrl);
    const local = url => ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    for (const url of [new URL(this.origin), new URL(this.issuer), this.publicUrl]) {
      if (url.protocol !== 'https:' && !(allowHttpLoopback && local(url))) throw new BrowserAuthError(503, 'browser_auth_https_required');
    }
    if (!/^[A-Za-z0-9._~-]{1,255}$/.test(clientId)) throw new BrowserAuthError(503, 'browser_auth_configuration_invalid');
    if (typeof apiAudience !== 'string' || !apiAudience || apiAudience.length > 255) throw new BrowserAuthError(503, 'browser_auth_configuration_invalid');
    this.apiAudience = apiAudience;
    this.clientId = clientId; this.key = secretFile(keyFile, true); this.clientSecret = secretFile(clientSecretFile);
    this.fetch = fetchImpl; this.now = now; this.secure = this.origin.startsWith('https:');
    this.prefix = this.secure ? '__Secure-' : '';
    this.flowCookie = this.prefix + 'od_login'; this.sessionCookie = this.prefix + 'od_session'; this.csrfCookie = this.secure ? '__Host-od_csrf' : 'od_csrf';
    this.redirectUri = this.origin + '/auth/callback';
    this.scopes = 'openid profile email roles sessions.self.read sessions.self.revoke';
  }

  seal(value, purpose) {
    const nonce = crypto.randomBytes(12); const cipher = crypto.createCipheriv('aes-256-gcm', this.key, nonce);
    cipher.setAAD(Buffer.from(['od-browser-v1', this.origin, this.issuer, this.clientId, purpose].join('|')));
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    const result = ['v1', nonce.toString('base64url'), encrypted.toString('base64url'), cipher.getAuthTag().toString('base64url')].join('.');
    if (result.length > 3600) throw new BrowserAuthError(503, 'browser_auth_cookie_too_large');
    return result;
  }

  unseal(value, purpose) {
    try {
      if (typeof value !== 'string' || value.length > 3600 || !/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid cookie');
      const [, nonce, encrypted, tag] = value.split('.');
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, Buffer.from(nonce, 'base64url'));
      decipher.setAAD(Buffer.from(['od-browser-v1', this.origin, this.issuer, this.clientId, purpose].join('|')));
      decipher.setAuthTag(Buffer.from(tag, 'base64url'));
      const decoded = JSON.parse(Buffer.concat([decipher.update(Buffer.from(encrypted, 'base64url')), decipher.final()]).toString('utf8'));
      if (!decoded || !Number.isFinite(decoded.expiresAt) || decoded.expiresAt <= this.now()) throw new Error('Expired cookie');
      return decoded;
    } catch { throw new BrowserAuthError(401, 'browser_auth_session_invalid'); }
  }

  cookie(headers, name, value, cookiePath, maxAge, httpOnly = true, sameSite = 'Strict') {
    headers.append('Set-Cookie', `${name}=${value}; Path=${cookiePath}; Max-Age=${Math.max(0, Math.floor(maxAge))}; SameSite=${sameSite}${httpOnly ? '; HttpOnly' : ''}${this.secure ? '; Secure' : ''}`);
  }

  headers() { return new Headers({ 'Cache-Control': 'no-store', Pragma: 'no-cache', 'Referrer-Policy': 'no-referrer' }); }

  clear(headers) {
    this.cookie(headers, this.sessionCookie, '', '/api/auth/oidc', 0);
    this.cookie(headers, this.csrfCookie, '', '/', 0, false);
  }

  store(headers, session) {
    this.cookie(headers, this.sessionCookie, this.seal(session, 'session'), '/api/auth/oidc', (session.expiresAt - this.now()) / 1000);
    this.cookie(headers, this.csrfCookie, session.csrf, '/', (session.expiresAt - this.now()) / 1000, false);
  }

  checkOrigin(request, session) {
    if (request.headers.get('origin') !== this.origin || (request.headers.has('sec-fetch-site') && !['same-origin', 'none'].includes(request.headers.get('sec-fetch-site')))
      || !equal(request.headers.get('x-od-csrf'), session.csrf)) throw new BrowserAuthError(403, 'browser_auth_origin_or_csrf_denied');
  }

  async json(endpoint, options = {}, limit = 65536, errorMapper, timeoutMs = 5000) {
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await this.fetch(new URL(endpoint, this.internalUrl), { ...options, redirect: 'error', cache: 'no-store', signal: controller.signal });
      if (!response.headers.get('content-type')?.includes('application/json')) throw new BrowserAuthError(503, 'browser_auth_authority_unavailable');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) {
        length += chunk.length; if (length > limit) throw new Error('Oversized response'); chunks.push(Buffer.from(chunk));
      }
      const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!response.ok) throw errorMapper ? errorMapper(response.status, data) : new BrowserAuthError([400, 401, 403].includes(response.status) ? 401 : 503, 'browser_auth_authority_denied');
      return data;
    } catch (error) {
      if (error instanceof BrowserAuthError) throw error;
      throw new BrowserAuthError(503, 'browser_auth_authority_unavailable');
    } finally { clearTimeout(timer); controller.abort(); }
  }

  async companyRegistration(request, operation) {
    const headers = this.headers(); headers.set('Content-Type', 'application/json'); headers.set('X-Content-Type-Options', 'nosniff');
    try {
      const { normalizePublic, validReceipt, validCapabilities } = require('../../../../packages/company-registration-contract');
      if (new URL(request.url).search || !['capabilities', 'submit', 'status', 'activate'].includes(operation)) throw new BrowserAuthError(400, 'invalid_company_registration');
      if (operation === 'capabilities') {
        if (request.method !== 'GET') throw new BrowserAuthError(400, 'invalid_company_registration');
        const capabilities = await this.json('/oauth/company-registration');
        if (!validCapabilities(capabilities)) throw new BrowserAuthError(503, 'company_registration_unavailable');
        return new Response(JSON.stringify(capabilities), { headers });
      }
      if (request.method !== 'POST' || request.headers.get('content-type')?.split(';')[0] !== 'application/json') throw new BrowserAuthError(400, 'invalid_company_registration');
      if (request.headers.get('origin') !== this.origin || request.headers.get('x-od-company-registration') !== '1'
        || (request.headers.has('sec-fetch-site') && !['same-origin', 'none'].includes(request.headers.get('sec-fetch-site')))) throw new BrowserAuthError(403, 'browser_auth_origin_or_csrf_denied');
      const chunks = []; let length = 0;
      if (Number(request.headers.get('content-length')) > 32768) throw new BrowserAuthError(400, 'invalid_company_registration');
      for await (const chunk of request.body || []) { length += chunk.length; if (length > 32768) throw new BrowserAuthError(400, 'invalid_company_registration'); chunks.push(Buffer.from(chunk)); }
      let body;
      try { body = normalizePublic(operation, JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { throw new BrowserAuthError(400, 'invalid_company_registration'); }
      const receipt = await this.json('/oauth/company-registration/' + operation, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }, 16384,
        status => new BrowserAuthError([400, 401, 403, 404, 409, 429].includes(status) ? status : 503, ({ 401: 'registration_credentials_rejected', 404: 'registration_not_found', 409: 'registration_conflict', 429: 'registration_rate_limited' })[status] || 'company_registration_unavailable'));
      if (!validReceipt(receipt, body.registrationId) || operation === 'status' && !receipt.replayed || operation === 'activate' && receipt.schemaVersion !== 3) throw new BrowserAuthError(503, 'company_registration_unavailable');
      return new Response(JSON.stringify(receipt), { status: operation === 'submit' && !receipt.replayed ? 201 : 200, headers });
    } catch (error) {
      return new Response(JSON.stringify({ error: error instanceof BrowserAuthError ? error.code : 'company_registration_unavailable' }), { status: error instanceof BrowserAuthError ? error.status : 503, headers });
    }
  }

  async employeeInvitation(request, operation) {
    const headers = this.headers(); headers.set('Content-Type', 'application/json'); headers.set('X-Content-Type-Options', 'nosniff');
    try {
      const contract = require('../../../../packages/employee-invitation-contract');
      if (!['capabilities', 'inspect', 'accept'].includes(operation) || new URL(request.url).search) throw new BrowserAuthError(400, 'invalid_employee_invitation');
      if (operation === 'capabilities') {
        if (request.method !== 'GET') throw new BrowserAuthError(400, 'invalid_employee_invitation');
        const value = await this.json('/oauth/employee-invitations');
        if (!value || Object.keys(value).length !== 3 || value.schemaVersion !== 1 || typeof value.enabled !== 'boolean' || value.requiresFirstLoginMfa !== true) throw new BrowserAuthError(503, 'employee_invitation_unavailable');
        return new Response(JSON.stringify(value), { headers });
      }
      if (request.method !== 'POST' || request.headers.get('content-type')?.split(';')[0] !== 'application/json') throw new BrowserAuthError(400, 'invalid_employee_invitation');
      if (request.headers.get('origin') !== this.origin || request.headers.get('x-od-employee-invitation') !== '1'
        || (request.headers.has('sec-fetch-site') && !['same-origin', 'none'].includes(request.headers.get('sec-fetch-site')))) throw new BrowserAuthError(403, 'browser_auth_origin_or_csrf_denied');
      const chunks = []; let length = 0;
      if (Number(request.headers.get('content-length')) > 8192) throw new BrowserAuthError(400, 'invalid_employee_invitation');
      for await (const chunk of request.body || []) { length += chunk.length; if (length > 8192) throw new BrowserAuthError(400, 'invalid_employee_invitation'); chunks.push(Buffer.from(chunk)); }
      let input;
      try {
        const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (operation === 'inspect') { contract.exact(value, ['token']); contract.parseToken(value.token); input = { token: value.token }; }
        else { contract.exact(value, ['token', 'password']); contract.parseToken(value.token); contract.password(value.password); input = { token: value.token, password: value.password }; }
      } catch { throw new BrowserAuthError(400, 'invalid_employee_invitation'); }
      const errors = new Set(['invalid_employee_invitation', 'employee_invitation_rejected', 'employee_invitation_changed', 'employee_password_requires_12_characters_and_at_most_72_utf8_bytes',
        'employee_invitation_activation_unconfirmed', 'employee_invitation_rate_limited']);
      const result = await this.json('/oauth/employee-invitations/' + operation, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input) }, 16384,
        (status, data) => [400, 401, 403, 404, 409, 429].includes(status) && errors.has(data?.error)
          ? new BrowserAuthError(status, data.error === 'employee_invitation_rejected' ? 'invalid_employee_invitation' : data.error)
          : new BrowserAuthError(status === 429 ? 429 : 503, status === 429 ? 'employee_invitation_rate_limited' : 'employee_invitation_unavailable'), operation === 'accept' ? 22000 : 8000);
      if (operation === 'inspect') {
        if (!result || Object.keys(result).length !== 6 || typeof result.organizationName !== 'string' || typeof result.loginName !== 'string'
          || !['pending', 'credential_pending', 'accepted'].includes(result.status) || typeof result.expiresAt !== 'string' || !Number.isFinite(Date.parse(result.expiresAt))
          || typeof result.credentialCreated !== 'boolean' || typeof result.identityConfirmed !== 'boolean') throw new BrowserAuthError(503, 'employee_invitation_unavailable');
      } else if (!result || Object.keys(result).length !== 6 || result.schemaVersion !== 1 || result.employeeInvitationProtocol !== 1 || result.status !== 'accepted'
        || typeof result.organizationName !== 'string' || typeof result.loginName !== 'string' || result.mfaEnrollmentRequired !== true) throw new BrowserAuthError(503, 'employee_invitation_unavailable');
      return new Response(JSON.stringify(result), { headers });
    } catch (error) {
      return new Response(JSON.stringify({ error: error instanceof BrowserAuthError ? error.code : 'employee_invitation_unavailable' }),
        { status: error instanceof BrowserAuthError ? error.status : 503, headers });
    }
  }

  async employeeInvitationOwner(request, operation) {
    const headers = this.headers(); headers.set('Content-Type', 'application/json'); headers.set('X-Content-Type-Options', 'nosniff');
    try {
      const contract = require('../../../../packages/employee-invitation-contract');
      if (!['create', 'list', 'get', 'revoke'].includes(operation) || request.method !== 'POST' || new URL(request.url).search
        || request.headers.get('content-type')?.split(';')[0] !== 'application/json') throw new BrowserAuthError(400, 'invalid_employee_invitation');
      if (request.headers.get('origin') !== this.origin || request.headers.get('x-od-employee-invitation-owner') !== '1'
        || (request.headers.has('sec-fetch-site') && !['same-origin', 'none'].includes(request.headers.get('sec-fetch-site')))) throw new BrowserAuthError(403, 'browser_auth_origin_or_csrf_denied');
      const authorization = request.headers.get('authorization');
      if (typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)) throw new BrowserAuthError(401, 'employee_invitation_owner_required');
      const chunks = []; let length = 0;
      if (Number(request.headers.get('content-length')) > 32768) throw new BrowserAuthError(400, 'invalid_employee_invitation');
      for await (const chunk of request.body || []) { length += chunk.length; if (length > 32768) throw new BrowserAuthError(400, 'invalid_employee_invitation'); chunks.push(Buffer.from(chunk)); }
      let input;
      try {
        const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (operation === 'create') input = contract.createInput(value);
        else if (operation === 'list') { contract.exact(value, ['page']); if (!Number.isSafeInteger(value.page) || value.page < 1 || value.page > 1000000) throw new Error(); input = value; }
        else if (operation === 'get') { contract.exact(value, ['id']); contract.identifier(value.id); input = value; }
        else {
          contract.exact(value, ['id', 'revision', 'reason', 'confirm']); contract.identifier(value.id);
          if (typeof value.revision !== 'string' || !/^[1-9][0-9]{0,18}$/.test(value.revision) || value.confirm !== true) throw new Error();
          input = { ...value, reason: contract.text(value.reason, 10, 500) };
        }
      } catch { throw new BrowserAuthError(400, 'invalid_employee_invitation'); }
      const errors = new Set(['invalid_employee_invitation', 'employee_invitation_owner_required', 'original_employee_invitation_owner_required',
        'employee_invitation_rejected', 'employee_invitation_changed', 'employee_invitation_withdrawal_unconfirmed', 'employee_invitation_rate_limited']);
      const result = await this.json('/oauth/employee-invitations/owner/' + operation, { method: 'POST', headers: { Authorization: authorization, 'Content-Type': 'application/json' }, body: JSON.stringify(input) }, 32768,
        (status, data) => [400, 401, 403, 404, 409, 412, 428, 429].includes(status) && errors.has(data?.error)
          ? new BrowserAuthError(status, data.error === 'employee_invitation_rejected' ? 'employee_invitation_changed' : data.error)
          : new BrowserAuthError(status === 429 ? 429 : 503, status === 429 ? 'employee_invitation_rate_limited' : 'employee_invitation_owner_unavailable'), 10000);
      const validView = value => !!value && !Array.isArray(value) && Object.keys(value).length === 11
        && ['id', 'tenantId', 'userId'].every(field => typeof value[field] === 'string') && typeof value.loginName === 'string' && typeof value.organizationName === 'string'
        && ['pending', 'credential_pending', 'accepted', 'revoked'].includes(value.status) && typeof value.revision === 'string' && /^[1-9][0-9]{0,18}$/.test(value.revision)
        && ['createdAt', 'expiresAt'].every(field => typeof value[field] === 'string' && Number.isFinite(Date.parse(value[field])))
        && typeof value.credentialCreated === 'boolean' && typeof value.identityConfirmed === 'boolean' && value.identityConfirmed === (value.status === 'accepted');
      const exact = fields => !!result && !Array.isArray(result) && Object.keys(result).length === fields.length && fields.every(field => Object.hasOwn(result, field));
      if (operation === 'create') {
        if (!exact(['schemaVersion', 'employeeInvitationProtocol', 'invitation', 'created', 'invitationToken']) || result.schemaVersion !== 1 || result.employeeInvitationProtocol !== 1
          || !validView(result.invitation) || typeof result.created !== 'boolean' || (result.created ? typeof result.invitationToken !== 'string' : result.invitationToken !== null)) throw new BrowserAuthError(503, 'employee_invitation_owner_unavailable');
      } else if (operation === 'list') {
        if (!exact(['schemaVersion', 'employeeInvitationProtocol', 'page', 'hasMore', 'invitations']) || result.schemaVersion !== 1 || result.employeeInvitationProtocol !== 1
          || result.page !== input.page || typeof result.hasMore !== 'boolean' || !Array.isArray(result.invitations) || result.invitations.length > 25 || result.invitations.some(value => !validView(value))) throw new BrowserAuthError(503, 'employee_invitation_owner_unavailable');
      } else if (operation === 'get') {
        if (!exact(['schemaVersion', 'employeeInvitationProtocol', 'invitation']) || result.schemaVersion !== 1 || result.employeeInvitationProtocol !== 1 || !validView(result.invitation)) throw new BrowserAuthError(503, 'employee_invitation_owner_unavailable');
      } else if (!exact(['schemaVersion', 'employeeInvitationProtocol', 'invitation', 'partialEnrollmentWithdrawn']) || result.schemaVersion !== 1 || result.employeeInvitationProtocol !== 1
        || !validView(result.invitation) || result.invitation.status !== 'revoked' || result.partialEnrollmentWithdrawn !== true) throw new BrowserAuthError(503, 'employee_invitation_owner_unavailable');
      return new Response(JSON.stringify(result), { status: operation === 'create' && result.created ? 201 : 200, headers });
    } catch (error) {
      return new Response(JSON.stringify({ error: error instanceof BrowserAuthError ? error.code : 'employee_invitation_owner_unavailable' }),
        { status: error instanceof BrowserAuthError ? error.status : 503, headers });
    }
  }

  async recovery(request, action) { return this.registration(request, action, 'recovery'); }
  async enrollment(request, action) { return this.registration(request, action, 'enrollment'); }
  async registration(request, action, purpose) {
    const headers = this.headers(); headers.set('Content-Type', 'application/json'); headers.set('X-Content-Type-Options', 'nosniff');
    try {
      if (!['recovery', 'enrollment'].includes(purpose)) throw new BrowserAuthError(400, 'invalid_request');
      const fields = action === 'start' ? ['username', 'password', 'mfaCode', purpose === 'enrollment' ? 'clientId' : 'recoveryCode'] : action === 'confirm' ? ['challenge', 'code'] : null;
      if (!fields || request.method !== 'POST' || new URL(request.url).search || request.headers.get('content-type')?.split(';')[0] !== 'application/json') throw new BrowserAuthError(400, 'invalid_request');
      if (request.headers.get('origin') !== this.origin || request.headers.get(purpose === 'enrollment' ? 'x-od-enrollment' : 'x-od-recovery') !== '1'
        || (request.headers.has('sec-fetch-site') && !['same-origin', 'none'].includes(request.headers.get('sec-fetch-site')))) throw new BrowserAuthError(403, 'browser_auth_origin_or_csrf_denied');
      const chunks = []; let length = 0;
      if (Number(request.headers.get('content-length')) > 8192) throw new BrowserAuthError(400, 'invalid_request');
      for await (const chunk of request.body || []) { length += chunk.length; if (length > 8192) throw new BrowserAuthError(400, 'invalid_request'); chunks.push(Buffer.from(chunk)); }
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new BrowserAuthError(400, 'invalid_request'); }
      if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(field => !fields.includes(field))) throw new BrowserAuthError(400, 'invalid_request');
      const errors = new Set(['invalid_request', 'invalid_credentials', 'mfa_required', 'invalid_recovery_code_format', 'invalid_recovery_code', 'invalid_recovery_challenge', 'invalid_otp', 'mfa_temporarily_locked', 'recovery_identity_changed', 'identity_not_eligible', 'invalid_enrollment_challenge', 'enrollment_authorization_changed', 'mfa_already_enabled', 'mfa_enrollment_not_allowed', 'application_not_assigned']);
      const result = await this.json('/oauth/mfa/' + purpose + '/' + action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }, 16384,
        (status, data) => [400, 401, 403, 409, 429].includes(status) && errors.has(data?.error) ? new BrowserAuthError(status, data.error) : new BrowserAuthError(503, 'browser_auth_authority_unavailable'));
      return new Response(JSON.stringify(result), { headers });
    } catch (error) { return new Response(JSON.stringify({ error: error instanceof BrowserAuthError ? error.code : 'browser_auth_authority_unavailable' }), { status: error instanceof BrowserAuthError ? error.status : 503, headers }); }
  }

  async verify(token, purpose, nonce) {
    try {
      if (typeof token !== 'string' || token.length > 16384) throw new Error('Invalid token');
      const jose = await import('jose');
      if (!this.jwks) this.jwks = jose.createRemoteJWKSet(new URL('/.well-known/jwks.json', this.internalUrl), { timeoutDuration: 2500, cooldownDuration: 1000 });
      const { payload, protectedHeader } = await jose.jwtVerify(token, this.jwks, { issuer: this.issuer, audience: purpose === 'id' ? this.clientId : this.apiAudience,
        algorithms: ['RS256'], requiredClaims: ['sub', 'exp', 'iat', 'jti', 'sid', 'auth_time'] });
      if (Object.keys(protectedHeader).some(field => !['alg', 'kid', 'typ'].includes(field)) || !protectedHeader.kid
        || (protectedHeader.typ !== undefined && protectedHeader.typ !== 'JWT')) throw new Error('Invalid header');
      const now = Math.floor(this.now() / 1000);
      if (payload.token_use !== purpose || payload.actor_type !== 'user' || typeof payload.sub !== 'string' || !payload.sub.trim()
        || payload.sub.length > 255 || !Number.isInteger(payload.iat) || payload.iat > now + 5 || payload.exp <= payload.iat
        || typeof payload.jti !== 'string' || !payload.jti || payload.jti.length > 255
        || !Number.isInteger(payload.auth_time) || payload.auth_time > payload.iat || payload.auth_time <= 0
        || typeof payload.sid !== 'string' || !/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/i.test(payload.sid)
        || (purpose === 'access' && payload.client_id !== this.clientId) || (purpose === 'id' && !equal(payload.nonce, nonce))) throw new Error('Invalid token binding');
      return payload;
    } catch (error) {
      if (error.code === 'ERR_JWKS_TIMEOUT' || error.code === 'ERR_JWKS_INVALID' || error instanceof TypeError
        || /Expected 200 OK/.test(error.message)) throw new BrowserAuthError(503, 'browser_auth_authority_unavailable');
      throw new BrowserAuthError(401, 'browser_auth_token_invalid');
    }
  }

  async active(token, claims) {
    const state = await this.json('/oauth/access-state', { headers: { Authorization: 'Bearer ' + token } }, 4096);
    if (state?.schemaVersion !== 1 || typeof state.active !== 'boolean') throw new BrowserAuthError(503, 'browser_auth_authority_invalid');
    if (!state.active) throw new BrowserAuthError(401, 'browser_auth_session_revoked');
    if (state.issuer !== claims.iss || state.subject !== claims.sub || state.tokenId !== claims.jti || state.expiresAt !== claims.exp) throw new BrowserAuthError(503, 'browser_auth_authority_invalid');
  }

  exchange(body) {
    return this.json('/oauth/token', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...body, client_id: this.clientId, client_secret: this.clientSecret }) });
  }

  pair(value) {
    if (!value || value.token_type !== 'Bearer' || typeof value.access_token !== 'string' || typeof value.refresh_token !== 'string'
      || !/^[A-Za-z0-9_-]{32,128}$/.test(value.refresh_token)) throw new BrowserAuthError(401, 'browser_auth_token_invalid');
    return value;
  }

  binding(claims, session) {
    return claims.iss === this.issuer && claims.sub === session.subject && claims.sid === session.sid && claims.auth_time === session.authTime;
  }

  async login() {
    const state = crypto.randomBytes(32).toString('base64url'); const verifier = crypto.randomBytes(32).toString('base64url');
    const nonce = crypto.randomBytes(32).toString('base64url');
    const url = new URL('/oauth/authorize', this.publicUrl);
    url.search = new URLSearchParams({ response_type: 'code', client_id: this.clientId, redirect_uri: this.redirectUri, scope: this.scopes, state, nonce,
      code_challenge_method: 'S256', code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url') }).toString();
    const headers = this.headers(); headers.set('Location', url.href);
    this.cookie(headers, this.flowCookie, this.seal({ state, verifier, nonce, expiresAt: this.now() + 600000 }, 'flow'), '/auth/callback', 600, true, 'Lax');
    return new Response(null, { status: 303, headers });
  }

  async callback(request) {
    const headers = this.headers();
    this.cookie(headers, this.flowCookie, '', '/auth/callback', 0, true, 'Lax');
    try {
      const query = new URL(request.url).searchParams;
      const flow = this.unseal(cookieValue(request, this.flowCookie), 'flow');
      if (query.getAll('state').length !== 1 || !equal(query.get('state'), flow.state) || query.has('error') || query.getAll('code').length !== 1 || !query.get('code')) throw new BrowserAuthError(401, 'browser_auth_callback_invalid');
      const pair = this.pair(await this.exchange({ grant_type: 'authorization_code', code: query.get('code'), redirect_uri: this.redirectUri, code_verifier: flow.verifier }));
      const identity = await this.verify(pair.id_token, 'id', flow.nonce); const access = await this.verify(pair.access_token, 'access');
      if (identity.sub !== access.sub || identity.sid !== access.sid || identity.auth_time !== access.auth_time) throw new BrowserAuthError(401, 'browser_auth_token_invalid');
      await this.active(pair.access_token, access);
      const session = { refreshToken: pair.refresh_token, subject: access.sub, sid: access.sid, authTime: access.auth_time,
        csrf: crypto.randomBytes(32).toString('base64url'), expiresAt: access.auth_time * 1000 + 30 * 86400_000 };
      this.store(headers, session); headers.set('Location', this.origin + '/dashboard');
      return new Response(null, { status: 303, headers });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.code || 'browser_auth_callback_invalid' }), { status: error.status || 503, headers: new Headers([...headers, ['Content-Type', 'application/json']]) });
    }
  }

  async session(request) {
    const headers = this.headers();
    try {
      const session = this.unseal(cookieValue(request, this.sessionCookie), 'session'); this.checkOrigin(request, session);
      if (typeof session.refreshToken !== 'string' || typeof session.csrf !== 'string' || typeof session.subject !== 'string') throw new BrowserAuthError(401, 'browser_auth_session_invalid');
      let accessToken = request.headers.get('authorization')?.replace(/^Bearer /, ''); let claims;
      if (accessToken) {
        try { claims = await this.verify(accessToken, 'access'); if (!this.binding(claims, session)) claims = null; }
        catch (error) { if (error.status !== 401) throw error; claims = null; }
      }
      if (!claims) {
        const pair = this.pair(await this.exchange({ grant_type: 'refresh_token', refresh_token: session.refreshToken }));
        session.refreshToken = pair.refresh_token; this.store(headers, session);
        accessToken = pair.access_token; claims = await this.verify(accessToken, 'access');
        if (!this.binding(claims, session)) throw new BrowserAuthError(401, 'browser_auth_session_invalid');
      }
      await this.active(accessToken, claims);
      headers.set('Content-Type', 'application/json');
      const roles = Array.isArray(claims.roles) ? claims.roles.filter(role => typeof role === 'string') : [];
      return new Response(JSON.stringify({ access_token: accessToken, expires_at: claims.exp * 1000, user: {
        id: claims.sub, name: typeof claims.name === 'string' ? claims.name : claims.sub,
        username: typeof claims.preferred_username === 'string' ? claims.preferred_username : claims.sub,
        email: typeof claims.email === 'string' ? claims.email : null, roles, role: roles[0] || 'Benutzer' } }), { headers });
    } catch (error) {
      if (error.status === 401) this.clear(headers);
      headers.set('Content-Type', 'application/json');
      return new Response(JSON.stringify({ error: error.code || 'browser_auth_unavailable' }), { status: error.status || 503, headers });
    }
  }

  async logout(request) {
    const headers = this.headers();
    try {
      const session = this.unseal(cookieValue(request, this.sessionCookie), 'session'); this.checkOrigin(request, session);
      await this.json('/oauth/revoke', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: session.refreshToken, client_id: this.clientId, client_secret: this.clientSecret }) });
      this.clear(headers); headers.set('Content-Type', 'application/json');
      return new Response(JSON.stringify({ revoked: true }), { headers });
    } catch (error) {
      headers.set('Content-Type', 'application/json');
      return new Response(JSON.stringify({ error: error.code || 'browser_auth_logout_unavailable' }), { status: error.status || 503, headers });
    }
  }
}

let instance;
function getBrowserAuth() { if (!instance) instance = new BrowserAuth(); return instance; }
module.exports = { BrowserAuth, BrowserAuthError, getBrowserAuth };
