const axios = require('axios');

const TOKEN_ENDPOINT = process.env.TOKEN_ENDPOINT || 'http://localhost:3001/token';
const CLIENT_ID = 'quick-actions';
const CLIENT_SECRET = process.env.QA_CLIENT_SECRET;

// Cached token state
let cachedToken = null;
let tokenExpiresAt = 0;

/**
 * Obtain a service access token via OAuth 2.0 Client Credentials grant.
 * The token is cached until it expires (with a 30-second safety buffer).
 */
async function getServiceToken() {
  const now = Date.now();

  // Return cached token if still valid
  if (cachedToken && now < tokenExpiresAt) {
    return cachedToken;
  }

  if (!CLIENT_SECRET) {
    throw new Error('QA_CLIENT_SECRET environment variable is required for service authentication');
  }

  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    scope: 'openid roles',
  });

  const response = await axios.post(TOKEN_ENDPOINT, params.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    timeout: 10000,
  });

  const { access_token, expires_in } = response.data;

  if (!access_token) {
    throw new Error('Token endpoint did not return an access_token');
  }

  cachedToken = access_token;
  // expires_in is in seconds; subtract 30s buffer
  tokenExpiresAt = now + ((expires_in || 3600) - 30) * 1000;

  return cachedToken;
}

/**
 * Create an axios instance that automatically attaches a Bearer token
 * obtained via the Client Credentials flow.
 *
 * @param {string} baseURL - Base URL of the target service
 * @returns {Promise<import('axios').AxiosInstance>}
 */
async function createServiceClient(baseURL) {
  const token = await getServiceToken();

  return axios.create({
    baseURL,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    timeout: 30000,
  });
}

/**
 * Make an authenticated service-to-service request.
 *
 * @param {string} method  - HTTP method
 * @param {string} url     - Full URL or path (relative to baseURL if provided)
 * @param {object} options - axios request config overrides
 */
async function serviceRequest(method, url, options = {}) {
  const token = await getServiceToken();

  return axios({
    method,
    url,
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
}

module.exports = { getServiceToken, createServiceClient, serviceRequest };
