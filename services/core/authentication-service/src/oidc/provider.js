'use strict';

const { Provider } = require('oidc-provider');

const configuration = {
  clients: [
    {
      client_id: 'web-app',
      client_secret: undefined, // public client - no secret
      grant_types: ['authorization_code', 'refresh_token'],
      redirect_uris: [process.env.WEB_APP_REDIRECT_URI || 'http://localhost:3000/auth/callback'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none', // PKCE only
    },
    {
      client_id: 'quick-actions',
      client_secret: process.env.QA_CLIENT_SECRET || 'quick-actions-secret',
      grant_types: ['client_credentials'],
      redirect_uris: [],
      response_types: [],
    },
    {
      client_id: 'device-service',
      client_secret: process.env.DEVICE_SVC_SECRET || 'device-service-secret',
      grant_types: ['client_credentials'],
      redirect_uris: [],
      response_types: [],
    },
    {
      client_id: 'policy-service',
      client_secret: process.env.POLICY_SVC_SECRET || 'policy-service-secret',
      grant_types: ['client_credentials'],
      redirect_uris: [],
      response_types: [],
    },
  ],

  pkce: { required: () => true },

  scopes: ['openid', 'profile', 'email', 'offline_access', 'roles', 'groups'],

  claims: {
    openid: ['sub'],
    profile: ['name', 'preferred_username'],
    email: ['email'],
    roles: ['roles'],
    groups: ['groups'],
  },

  findAccount: async (ctx, id) => ({
    accountId: id,
    async claims(use, scope) {
      // Lazy-require to avoid circular dependency issues at module load time
      // TODO: replace with PostgresUserRepository (requires db instance injection)
      let user = null;
      try {
        const db = require('../db');
        if (db && typeof db.isAvailable === 'function' && db.isAvailable()) {
          const result = await db.query('SELECT * FROM users WHERE id=$1', [id]);
          user = result.rows[0] || null;
        }
      } catch (_err) {
        // DB not available — return minimal claims
      }
      return {
        sub: id,
        email: user?.email,
        name: user?.display_name || user?.username,
        preferred_username: user?.username,
        roles: user?.roles || [],
        groups: user?.groups || [],
      };
    },
  }),

  ttl: {
    AccessToken: 3600,
    AuthorizationCode: 600,
    IdToken: 3600,
    RefreshToken: 86400 * 30,
    ClientCredentials: 3600,
  },

  features: {
    devInteractions: { enabled: false },
    clientCredentials: { enabled: true },
    revocation: { enabled: true },
    introspection: { enabled: true },
    rpInitiatedLogout: { enabled: true },
    // Resource Indicators are required in v9 to issue JWT access tokens
    resourceIndicators: {
      enabled: true,
      defaultResource: () => 'urn:opendirectory:api',
      getResourceServerInfo: () => ({
        scope: 'openid profile email roles groups offline_access',
        accessTokenFormat: 'jwt',
      }),
      useGrantedResource: () => true,
    },
  },

  cookies: {
    keys: [process.env.COOKIE_SECRET || 'oidc-cookie-secret-change-in-prod'],
  },

  // Interaction routing (login page)
  interactions: {
    url: (ctx, interaction) => `/interaction/${interaction.uid}`,
  },
};

/**
 * Load JWKS from file/env, or generate a fresh RSA-256 key pair.
 * The generated key is persisted to JWKS_PATH so it survives restarts.
 */
async function getJWKS() {
  const fs = require('fs');
  const path = require('path');
  const { generateKeyPair, exportJWK } = require('jose');

  const jwksPath =
    process.env.JWKS_PATH ||
    path.join(__dirname, '../../.oidc_jwks.json');

  // 1. Try to load from env var (JSON string)
  if (process.env.JWKS_KEYS) {
    try {
      return JSON.parse(process.env.JWKS_KEYS);
    } catch (err) {
      // fall through to file / generation
    }
  }

  // 2. Try to load from secrets file
  const secretsFile = '/run/secrets/oidc_jwks.json';
  if (fs.existsSync(secretsFile)) {
    return JSON.parse(fs.readFileSync(secretsFile, 'utf8'));
  }

  // 3. Try the configured/default path
  if (fs.existsSync(jwksPath)) {
    return JSON.parse(fs.readFileSync(jwksPath, 'utf8'));
  }

  // 4. Generate a new RSA-256 key pair
  const { privateKey } = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  const jwk = await exportJWK(privateKey);
  jwk.kid = 'oidc-signing-key-1';
  jwk.use = 'sig';
  jwk.alg = 'RS256';
  const jwks = { keys: [jwk] };

  // Persist so the same key is reused across restarts (best-effort)
  try {
    fs.writeFileSync(jwksPath, JSON.stringify(jwks, null, 2));
  } catch (_err) {
    // Not fatal — key will be regenerated on next restart
  }

  return jwks;
}

/**
 * Build and return a configured node-oidc-provider instance.
 * @param {string} issuer  The canonical issuer URL (e.g. "https://auth.example.com")
 * @returns {Promise<import('node-oidc-provider').Provider>}
 */
async function createProvider(issuer) {
  const jwks = await getJWKS();
  const cfg = { ...configuration, jwks };
  const provider = new Provider(issuer, cfg);
  return provider;
}

module.exports = { createProvider };
