'use strict';

// Thin OAuth2 Client Credentials client used to call device-service on behalf
// of api-backend. Modeled after services/platform/quick-actions/src/utils/serviceClient.js
// (token caching + refresh-before-expiry), but scoped to the single
// api-backend -> device-service delegation path.

const axios = require('axios');

const TIMEOUT_MS = 5000;

function getConfig() {
  return {
    deviceServiceUrl: process.env.DEVICE_SERVICE_URL || 'http://device-service:3003',
    tokenUrl: process.env.OAUTH_TOKEN_URL || 'http://oauth-provider:3010/oauth/token',
    clientId: process.env.API_BACKEND_CLIENT_ID || 'api-backend',
    clientSecret: process.env.API_BACKEND_CLIENT_SECRET || '',
  };
}

/** Cached access token state (module-level so it survives across requests) */
let _cachedToken = null;
let _tokenExpiresAt = 0; // ms since epoch

/**
 * Clears the cached token, forcing the next getServiceToken() call to
 * re-authenticate. Used after the downstream service rejects a token
 * (401/403) in case it was revoked or the signing key rotated.
 */
function resetTokenCache() {
  _cachedToken = null;
  _tokenExpiresAt = 0;
}

/**
 * Obtain a service access token via the OAuth 2.0 Client Credentials grant
 * against oauth-provider. The token is cached until shortly before it
 * expires (30s safety buffer).
 *
 * @returns {Promise<string>} Bearer access_token
 */
async function getServiceToken() {
  const now = Date.now();

  if (_cachedToken && now < _tokenExpiresAt) {
    return _cachedToken;
  }

  const { tokenUrl, clientId, clientSecret } = getConfig();

  if (!clientSecret) {
    throw new Error('API_BACKEND_CLIENT_SECRET environment variable is required for device-service delegation');
  }

  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: clientId,
    client_secret: clientSecret,
    scope: 'openid roles',
  });

  let res;
  try {
    res = await axios.post(tokenUrl, body.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: TIMEOUT_MS,
      validateStatus: () => true,
    });
  } catch (err) {
    const wrapped = new Error(`Token endpoint request failed: ${err.message}`);
    wrapped.code = err.code;
    wrapped.cause = err;
    throw wrapped;
  }

  if (res.status < 200 || res.status >= 300) {
    const err = new Error(`Token endpoint returned ${res.status}`);
    err.status = res.status;
    err.body = res.data;
    throw err;
  }

  const { access_token, expires_in } = res.data || {};
  if (!access_token) {
    throw new Error('Token endpoint did not return an access_token');
  }

  _cachedToken = access_token;
  // expires_in is in seconds; subtract 30s buffer so we refresh proactively
  _tokenExpiresAt = now + ((expires_in || 3600) - 30) * 1000;

  return _cachedToken;
}

/**
 * Call device-service with a Client Credentials bearer token.
 *
 * @param {string} method  - HTTP verb ('GET', 'POST', ...)
 * @param {string} path    - URL path starting with '/' (e.g. '/api/devices')
 * @returns {Promise<object>} parsed JSON response body
 * @throws {Error} on timeout, network failure (ECONNREFUSED, ...), or a
 *                 non-2xx response from device-service. The thrown error
 *                 carries a `.status` (HTTP status) or `.code` (network
 *                 error code, e.g. 'ECONNREFUSED'/'ECONNABORTED') so callers
 *                 can decide whether to fall back.
 */
async function callDeviceService(method, path) {
  const { deviceServiceUrl } = getConfig();
  const token = await getServiceToken();

  let res;
  try {
    res = await axios.request({
      method,
      url: `${deviceServiceUrl}${path}`,
      headers: { Authorization: `Bearer ${token}` },
      timeout: TIMEOUT_MS,
      validateStatus: () => true,
    });
  } catch (err) {
    const wrapped = new Error(`device-service request failed: ${err.message}`);
    wrapped.code = err.code;
    wrapped.cause = err;
    throw wrapped;
  }

  if (res.status === 401 || res.status === 403) {
    // Token may have been rejected (revoked / key rotation) — drop the cache
    // so the next call re-authenticates instead of retrying with a bad token.
    resetTokenCache();
    const err = new Error(`device-service returned ${res.status}`);
    err.status = res.status;
    err.body = res.data;
    throw err;
  }

  if (res.status < 200 || res.status >= 300) {
    const err = new Error(`device-service returned ${res.status}`);
    err.status = res.status;
    err.body = res.data;
    throw err;
  }

  return res.data;
}

module.exports = { getServiceToken, callDeviceService, resetTokenCache, getConfig };
