'use strict';

class AdapterError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function bearer(value) {
  if (typeof value !== 'string' || !/^Bearer [A-Za-z0-9._~-]+$/.test(value)) throw new AdapterError(401, 'A bearer token is required');
  return value;
}

class PolicyLicenseClient {
  constructor({ baseUrl = process.env.POLICY_SERVICE_URL || 'http://policy-service:3004', fetchImpl = global.fetch, timeoutMs = 10000, maxBytes = 2 * 1024 * 1024 } = {}) {
    this.baseUrl = new URL(baseUrl);
    if (!['http:', 'https:'].includes(this.baseUrl.protocol) || this.baseUrl.username || this.baseUrl.password || this.baseUrl.search || this.baseUrl.hash || this.baseUrl.pathname !== '/') throw new Error('Invalid policy service URL');
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000 || !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 2 * 1024 * 1024) throw new Error('Invalid policy transport limits');
    this.fetch = fetchImpl; this.timeoutMs = timeoutMs; this.maxBytes = maxBytes;
  }

  async request(method, path, authorization, { body, query = {} } = {}) {
    bearer(authorization);
    if (!['GET', 'POST', 'PUT', 'DELETE'].includes(method) || !/^\/api\/licenses(?:\/|$)/.test(path) || /[?#\\]/.test(path)
      || path.split('/').some(segment => segment === '.' || segment === '..' || /%(?:2f|2e|5c)/i.test(segment))) throw new AdapterError(400, 'Invalid canonical license path');
    const url = new URL(path, this.baseUrl);
    for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetch(url, { method, headers: { Authorization: authorization, Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }), redirect: 'error', cache: 'no-store', signal: controller.signal });
      if (response.status >= 300 && response.status < 400) throw new AdapterError(503, 'Canonical license redirects are not permitted');
      if (response.status === 204) return { status: 204, body: null };
      if (response.headers.get('content-type')?.split(';')[0].trim() !== 'application/json') throw new AdapterError(503, 'Invalid canonical license response');
      const chunks = []; let size = 0;
      for await (const chunk of response.body) {
        size += chunk.length;
        if (size > this.maxBytes) { controller.abort(); throw new AdapterError(503, 'Canonical license response exceeds the limit'); }
        chunks.push(Buffer.from(chunk));
      }
      const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new AdapterError(503, 'Invalid canonical license response');
      return { status: response.status, body: value, retryAfter: response.headers.get('retry-after') };
    } catch (error) {
      if (error instanceof AdapterError) throw error;
      throw new AdapterError(503, 'Canonical license service unavailable');
    } finally { clearTimeout(timer); }
  }

  async access(authorization) {
    const result = await this.request('GET', '/api/licenses/access', authorization);
    if (result.status !== 200) throw new AdapterError([401, 403, 429].includes(result.status) ? result.status : 503, 'Canonical license authorization failed');
    const value = result.body;
    if (!['active', 'unlinked', 'disabled', 'unavailable'].includes(value.identityState) || !Array.isArray(value.permissions)
      || value.permissions.some(permission => typeof permission !== 'string') || typeof value.tokenSubject !== 'string' || !value.tokenSubject.trim()
      || (value.identityState === 'active' && (typeof value.subject !== 'string' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value.subject)))
      || (value.identityState !== 'active' && (value.subject !== null || value.permissions.length)) || value.demoMode !== false) throw new AdapterError(503, 'Canonical persistent license authorization unavailable');
    return value;
  }
}

function requireActive(access) {
  if (access.identityState !== 'active') throw new AdapterError(access.identityState === 'unavailable' ? 503 : 403, 'A linked, enabled canonical identity is required');
}

module.exports = { PolicyLicenseClient, AdapterError, bearer, requireActive };
