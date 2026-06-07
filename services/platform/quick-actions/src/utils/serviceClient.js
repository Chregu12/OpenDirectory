'use strict';

// Base URLs from env or Kubernetes service names
const SERVICES = {
  auth:      process.env.AUTH_SERVICE_URL      || 'http://authentication-service',
  directory: process.env.DIRECTORY_SERVICE_URL || 'http://enterprise-directory',
  kerberos:  process.env.KERBEROS_SERVICE_URL  || 'http://kerberos-kdc',
  samba:     process.env.SAMBA_SERVICE_URL     || 'http://samba-ad-dc',
  device:    process.env.DEVICE_SERVICE_URL    || 'http://device-service',
  policy:    process.env.POLICY_SERVICE_URL    || 'http://policy-service',
  pim:       process.env.PIM_SERVICE_URL       || 'http://conditional-access',
  mdm:       process.env.MDM_SERVICE_URL       || 'http://mobile-management',
  appStore:  process.env.APP_STORE_SERVICE_URL || 'http://app-store',
};

const TIMEOUT_MS = 10_000;

// ── Client Credentials token cache ────────────────────────────────────────────

const TOKEN_ENDPOINT  = process.env.TOKEN_ENDPOINT || 'http://localhost:3001/token';
const CLIENT_ID       = 'quick-actions';
const CLIENT_SECRET   = process.env.QA_CLIENT_SECRET;

/** Cached access token state */
let _cachedToken   = null;
let _tokenExpiresAt = 0; // ms since epoch

/**
 * Obtain a service access token via OAuth 2.0 Client Credentials grant.
 * The token is cached until it expires (with a 30-second safety buffer).
 *
 * @returns {Promise<string>} Bearer access_token
 */
async function getServiceToken() {
  const now = Date.now();

  // Return cached token if still valid
  if (_cachedToken && now < _tokenExpiresAt) {
    return _cachedToken;
  }

  if (!CLIENT_SECRET) {
    throw new Error('QA_CLIENT_SECRET environment variable is required for service authentication');
  }

  const { default: fetch } = await import('node-fetch');

  const body = new URLSearchParams({
    grant_type:    'client_credentials',
    client_id:     CLIENT_ID,
    client_secret: CLIENT_SECRET,
    scope:         'openid roles',
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  let res;
  try {
    res = await fetch(TOKEN_ENDPOINT, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    body.toString(),
      signal:  controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Token endpoint returned ${res.status}: ${text}`);
  }

  const data = await res.json();
  const { access_token, expires_in } = data;

  if (!access_token) {
    throw new Error('Token endpoint did not return an access_token');
  }

  _cachedToken    = access_token;
  // expires_in is in seconds; subtract 30s buffer
  _tokenExpiresAt = now + ((expires_in || 3600) - 30) * 1000;

  return _cachedToken;
}

// ── HTTP client ────────────────────────────────────────────────────────────────

/**
 * Make an HTTP call to an internal service.
 *
 * @param {string} service  - key in SERVICES map (e.g. 'auth', 'directory')
 * @param {string} method   - HTTP verb ('GET', 'POST', 'PATCH', 'DELETE', …)
 * @param {string} path     - URL path starting with '/' (e.g. '/api/users')
 * @param {object} [body]   - optional JSON body (only sent for non-GET requests)
 * @returns {Promise<object>} parsed JSON response body
 * @throws  {Error}          if the request times out, the network is unreachable,
 *                           or the server returns a non-2xx status
 */
async function call(service, method, path, body) {
  const { default: fetch } = await import('node-fetch');

  const baseUrl = SERVICES[service];
  if (!baseUrl) throw new Error(`Unknown service: "${service}"`);

  const url = `${baseUrl}${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  // Obtain token via Client Credentials before every call (cached internally)
  const token = await getServiceToken();

  const headers = {
    'Content-Type':  'application/json',
    'Authorization': `Bearer ${token}`,
  };

  const options = {
    method: method.toUpperCase(),
    headers,
    signal: controller.signal,
  };

  if (body !== undefined && method.toUpperCase() !== 'GET') {
    options.body = JSON.stringify(body);
  }

  try {
    const res = await fetch(url, options);
    clearTimeout(timer);

    let data;
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      data = await res.json();
    } else {
      data = { _raw: await res.text() };
    }

    if (!res.ok) {
      const err = new Error(
        `Service "${service}" returned ${res.status} for ${method} ${path}`
      );
      err.status = res.status;
      err.body   = data;
      throw err;
    }

    return data;
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      const timeoutErr = new Error(
        `Service "${service}" timed out after ${TIMEOUT_MS}ms for ${method} ${path}`
      );
      timeoutErr.code = 'ETIMEOUT';
      throw timeoutErr;
    }
    throw err;
  }
}

/**
 * Ping a service's /health endpoint. Returns { healthy, latencyMs, error? }.
 */
async function ping(service) {
  const start = Date.now();
  try {
    await call(service, 'GET', '/health');
    return { healthy: true, latencyMs: Date.now() - start };
  } catch (err) {
    return { healthy: false, latencyMs: Date.now() - start, error: err.message };
  }
}

module.exports = { call, ping, getServiceToken, SERVICES };
