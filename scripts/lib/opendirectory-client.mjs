const MAX_BODY = 1024 * 1024;

function base(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname))) throw new Error('HTTPS or HTTP loopback is required');
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('Use an origin without credentials, path, query or fragment');
  return url;
}

export class ApiError extends Error {
  constructor(status, code) { super(`${code} (HTTP ${status})`); this.name = 'ApiError'; this.status = status; this.code = code; }
}

async function json(url, options) {
  const response = await fetch(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(15000), cache: 'no-store' });
  if (response.status === 204) return { status: 204, data: null, etag: response.headers.get('etag') };
  if (!response.headers.get('content-type')?.includes('application/json')) throw new ApiError(response.status, 'unexpected_response');
  const chunks = []; let length = 0;
  for await (const chunk of response.body) {
    length += chunk.length; if (length > MAX_BODY) throw new ApiError(response.status, 'response_too_large'); chunks.push(Buffer.from(chunk));
  }
  const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!response.ok) throw new ApiError(response.status, typeof data?.error === 'string' && /^[a-z0-9_]{1,80}$/.test(data.error) ? data.error : 'request_failed');
  return { status: response.status, data, etag: response.headers.get('etag') };
}

export function createClient({ issuer, apiUrl = issuer, clientId, clientSecret, scopes = '', adminToken }) {
  const authority = base(issuer); const api = base(apiUrl);
  function apiPath(path) {
    if (typeof path !== 'string' || !path.startsWith('/api/') || /[\u0000-\u0020\u007f\\#]/.test(path)) throw new Error('Use an /api/ path');
    const target = new URL(path, api);
    if (target.origin !== api.origin || !target.pathname.startsWith('/api/')) throw new Error('API path leaves the configured origin');
    return target;
  }
  async function token() {
    if (typeof clientId !== 'string' || !clientId || typeof clientSecret !== 'string' || !clientSecret || typeof scopes !== 'string') throw new Error('App client ID, secret and optional scopes are required');
    const result = await json(new URL('/oauth/token', authority), { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret, scope: scopes }).toString() });
    if (result.status !== 200 || typeof result.data?.access_token !== 'string' || !result.data.access_token
      || result.data.token_type?.toLowerCase() !== 'bearer' || !Number.isFinite(result.data.expires_in) || result.data.expires_in <= 0) throw new Error('Token issuance was not confirmed');
    return result.data.access_token;
  }
  async function request(method, path, body, { administrative = false, etag } = {}) {
    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method) || (method === 'GET' && body !== undefined)) throw new Error('Unsupported request');
    const url = apiPath(path);
    if (administrative && (typeof adminToken !== 'string' || !adminToken)) throw new Error('An administrator user access token is required');
    const bearer = administrative ? adminToken : await token();
    return json(url, { method, headers: { Authorization: 'Bearer ' + bearer, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(etag ? { 'If-Match': etag } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  }
  function clientPath(id) {
    if (typeof id !== 'string' || !/^[A-Za-z0-9._~-]{1,255}$/.test(id) || ['.', '..'].includes(id)) throw new Error('Invalid app ID');
    return '/api/clients/' + encodeURIComponent(id);
  }
  async function current(id) {
    const result = await request('GET', clientPath(id), undefined, { administrative: true }); const client = result.data;
    if (result.status !== 200 || client?.clientId !== id || typeof client.version !== 'string' || !/^[1-9][0-9]{0,18}$/.test(client.version)
      || result.etag !== `"od-client:${id}:${client.version}"`) throw new Error('Current app version was not confirmed');
    return result;
  }
  return {
    request,
    async check() {
      const accessToken = await token();
      const result = await json(new URL('/oauth/introspect', authority), { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: accessToken, client_id: clientId, client_secret: clientSecret }).toString() });
      if (result.status !== 200 || result.data?.active !== true || result.data.client_id !== clientId) throw new Error('App authentication is inactive or unconfirmed');
      return result.data;
    },
    async createApp(name, appScopes = []) {
      if (typeof name !== 'string' || !name.trim() || name.length > 255 || !Array.isArray(appScopes) || appScopes.some(scope => typeof scope !== 'string' || !scope || /\s/.test(scope))) throw new Error('A name and individual scope strings are required');
      const result = await request('POST', '/api/clients', { name: name.trim(), publicClient: false, enabled: false, redirectUris: [], grantTypes: ['client_credentials'], scopes: appScopes }, { administrative: true });
      const client = result.data;
      if (result.status !== 201 || typeof client?.clientId !== 'string' || client.name !== name.trim() || client.publicClient !== false || client.enabled !== false || client.version !== '1'
        || JSON.stringify(client.grantTypes) !== '["client_credentials"]' || JSON.stringify(client.redirectUris) !== '[]' || JSON.stringify(client.scopes) !== JSON.stringify(appScopes)
        || typeof client.clientSecret !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(client.clientSecret)) throw new Error('App creation was not confirmed; inspect the registry before retrying');
      return client;
    },
    async enableApp(id, enabled) {
      if (typeof enabled !== 'boolean') throw new Error('enabled must be a boolean');
      const before = await current(id);
      const body = Object.fromEntries(['name', 'publicClient', 'redirectUris', 'grantTypes', 'scopes'].map(key => [key, before.data[key]]));
      const result = await request('PUT', clientPath(id), { ...body, enabled }, { administrative: true, etag: before.etag });
      if (result.status !== 200 || result.data?.clientId !== id || result.data.enabled !== enabled || String(BigInt(before.data.version) + 1n) !== result.data.version) throw new Error('App update was not confirmed; inspect the registry before retrying');
      return result.data;
    },
    async rotateApp(id) {
      const before = await current(id);
      const result = await request('POST', clientPath(id) + '/rotate-secret', {}, { administrative: true, etag: before.etag });
      if (result.status !== 200 || result.data?.clientId !== id || String(BigInt(before.data.version) + 1n) !== result.data.version
        || typeof result.data.clientSecret !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(result.data.clientSecret)) throw new Error('Secret replacement was not confirmed; inspect the registry before retrying');
      return result.data;
    },
  };
}
