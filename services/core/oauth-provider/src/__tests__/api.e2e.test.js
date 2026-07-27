'use strict';

/**
 * E2E API tests for the OAuth Provider service (OAuth2 / OIDC / SCIM / Device
 * Enrollment identity provider — replaces Microsoft Entra ID).
 *
 * Uses supertest in-process against the real Express app exported by
 * ../index.js, with pg / redis / the gRPC event bus mocked at the module
 * boundary (same pattern as authentication-service's and device-service's
 * api.e2e.test.js suites).
 *
 * ─── Why the mocks below exist ─────────────────────────────────────────────
 *
 * src/index.js is a ~1900-line "god file" that, as a side effect of being
 * required, immediately:
 *   1. Generates two RSA-2048 keypairs (RS256 signing + SAML signing).
 *   2. Seeds in-memory OAuth clients / SCIM users / enrollment tokens /
 *      device registry.
 *   3. Kicks off `db.initDb().then(() => { ... app.listen(PORT) })` — i.e.
 *      it calls app.listen() unconditionally, with no test/dev guard.
 *   4. Starts two `setInterval` timers (metrics gauge refresh, device
 *      auto-quarantine sweep), each every 30s.
 *
 * To make this requirable in a test process without a real Postgres/Redis
 * and without binding a fixed TCP port:
 *   - `pg` is mocked so `db.isAvailable()` resolves true against a no-op
 *     pool (matches the established pattern in other services' e2e suites).
 *   - `redis` is mocked so initRedis() resolves without a real connection.
 *   - `@opendirectory/grpc-event-bus` is mocked (virtual — the real package
 *     name doesn't resolve from node_modules; the code's own try/catch falls
 *     back to a relative require, but registering the virtual mock short-
 *     circuits that fallback exactly like api-gateway's gateway.e2e.test.js
 *     already does).
 *   - `OAUTH_PROVIDER_PORT=0` is set before require so the god file's
 *     internal `app.listen(PORT)` binds an ephemeral port instead of
 *     colliding with a real 3010 listener. supertest never talks to that
 *     internal listener anyway — it wraps the exported `app` with its own
 *     ephemeral server per request.
 *   - package.json's test script uses `jest --forceExit` because of the two
 *     setInterval timers and the internal app.listen(), same as
 *     device-service/policy-service/api-gateway already do.
 *
 * ─── Scope ──────────────────────────────────────────────────────────────
 *
 * This suite does NOT attempt to cover all ~68 routes in the file. It
 * targets the endpoints that are security-critical and/or most-used:
 *   - OIDC discovery / JWKS
 *   - OAuth2 core: /oauth/authorize validation, /oauth/token (all 4 grant
 *     types + error paths), /oauth/userinfo, /oauth/introspect,
 *     /oauth/revoke
 *   - Device authorization flow (RFC 8628)
 *   - Enrollment tokens (device-join depends on these)
 *   - SCIM 2.0 Users
 *
 * A dedicated "Security findings" describe block at the bottom documents,
 * with tests that assert *current* (not desired) behavior, four real gaps
 * this suite surfaced. They are intentionally green (they characterize what
 * the code does today) — see the block's header comment and the test-agent
 * report for why they are not silently fixed here.
 */

// ─── Mocks — must be registered before any require of ../index ────────────

process.env.OAUTH_PROVIDER_PORT = '0'; // avoid binding the real port (3010) during tests
process.env.OAUTH_ISSUER = 'https://opendirectory.test';
process.env.GRAFANA_CLIENT_SECRET = 'test-grafana-secret';
process.env.DEVPORTAL_CLIENT_SECRET = 'test-devportal-secret';

jest.mock('pg', () => ({
  Pool: jest.fn().mockImplementation(() => ({
    query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
    connect: jest.fn().mockResolvedValue({
      query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
      release: jest.fn(),
    }),
    end: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
  })),
}));

jest.mock('redis', () => ({
  createClient: jest.fn().mockImplementation(() => ({
    on: jest.fn(),
    connect: jest.fn().mockResolvedValue(undefined),
    setEx: jest.fn().mockResolvedValue('OK'),
    get: jest.fn().mockResolvedValue(null),
  })),
}));

jest.mock('@opendirectory/grpc-event-bus', () => ({
  EventBusClient: jest.fn().mockImplementation(() => ({
    connect: jest.fn().mockResolvedValue(undefined),
    publish: jest.fn().mockResolvedValue(undefined),
  })),
}), { virtual: true });

// ─── Now require the app ───────────────────────────────────────────────────

const crypto = require('crypto');
const request = require('supertest');
const app = require('../index');

/** Pull the `code` query param off a Location header from a 302 redirect. */
function codeFromRedirect(location) {
  const url = new URL(location);
  return url.searchParams.get('code');
}

// ─── Auth helpers for the admin-surface tests ──────────────────────────────
//
// grafana-od-client is seeded with client_credentials in its grantTypes
// allowlist (see src/index.js's seed data) specifically so tests can mint
// real, JWKS-verifiable tokens through the actual /oauth/token endpoint
// rather than hand-rolling JWTs — scope is client-requested and flows
// straight into the token payload's `scope` claim, so requesting
// `oauth.admin` here exercises exactly the same code path
// src/middleware/oidcAuth.js's hasAdminAccess() checks in production.

/** Mints a real access token carrying the oauth.admin scope. */
async function getAdminToken() {
  const res = await request(app).post('/oauth/token').send({
    grant_type: 'client_credentials',
    client_id: 'grafana-od-client',
    client_secret: 'test-grafana-secret',
    scope: 'oauth.admin',
  });
  if (res.status !== 200) throw new Error(`getAdminToken: /oauth/token returned ${res.status}: ${JSON.stringify(res.body)}`);
  return res.body.access_token;
}

/** Mints a real, validly-signed access token that does NOT carry admin rights. */
async function getNonAdminToken() {
  const res = await request(app).post('/oauth/token').send({
    grant_type: 'client_credentials',
    client_id: 'grafana-od-client',
    client_secret: 'test-grafana-secret',
    scope: 'openid profile',
  });
  if (res.status !== 200) throw new Error(`getNonAdminToken: /oauth/token returned ${res.status}: ${JSON.stringify(res.body)}`);
  return res.body.access_token;
}

/** Enrolls a device (public endpoint) and returns its long-lived deviceToken. */
async function enrollDevice(hostname = `test-device-${Math.random().toString(36).slice(2)}`) {
  const adminToken = await getAdminToken();
  const tokensRes = await request(app).get('/api/enrollment/tokens').set('Authorization', `Bearer ${adminToken}`);
  const linuxToken = tokensRes.body.find((t) => t.platform === 'linux').token;
  const res = await request(app).post('/api/enrollment/register').send({
    token: linuxToken, platform: 'linux', hostname, os: '6.8.0',
  });
  return { deviceId: res.body.deviceId, deviceToken: res.body.deviceToken };
}

describe('oauth-provider E2E', () => {
  // ── OIDC discovery / JWKS ────────────────────────────────────────────────
  describe('OIDC discovery', () => {
    it('GET /.well-known/openid-configuration returns issuer + endpoints', async () => {
      const res = await request(app).get('/.well-known/openid-configuration');
      expect(res.status).toBe(200);
      expect(res.body.issuer).toBe('https://opendirectory.test');
      expect(res.body.token_endpoint).toBe('https://opendirectory.test/oauth/token');
      expect(res.body.grant_types_supported).toEqual(expect.arrayContaining(['authorization_code', 'client_credentials', 'refresh_token']));
    });

    it('GET /.well-known/jwks.json exposes an RS256 public key', async () => {
      const res = await request(app).get('/.well-known/jwks.json');
      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(1);
      expect(res.body.keys[0]).toMatchObject({ kty: 'RSA', alg: 'RS256', use: 'sig' });
    });
  });

  describe('GET /health', () => {
    it('reports service identity', async () => {
      const res = await request(app).get('/health');
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ status: 'ok', service: 'oauth-provider', algorithm: 'RS256' });
    });
  });

  // ── /oauth/authorize validation ──────────────────────────────────────────
  describe('GET /oauth/authorize', () => {
    it('rejects an unknown client_id with 400 invalid_client', async () => {
      const res = await request(app).get('/oauth/authorize').query({ client_id: 'does-not-exist', response_type: 'code' });
      expect(res.status).toBe(400);
      expect(res.text).toMatch(/invalid_client/);
    });

    it('rejects a redirect_uri not registered for the client with 400 invalid_redirect_uri', async () => {
      const res = await request(app).get('/oauth/authorize').query({
        client_id: 'grafana-od-client',
        redirect_uri: 'https://evil.example.com/callback',
        response_type: 'code',
      });
      expect(res.status).toBe(400);
      expect(res.text).toMatch(/invalid_redirect_uri/);
    });

    it('renders the login form for a valid client_id + registered redirect_uri', async () => {
      const res = await request(app).get('/oauth/authorize').query({
        client_id: 'grafana-od-client',
        redirect_uri: 'https://grafana.example.com/login/generic_oauth',
        response_type: 'code',
      });
      expect(res.status).toBe(200);
      expect(res.text).toContain('Grafana Dashboard');
      expect(res.text).toContain('name="username"');
    });
  });

  // ── /oauth/token — client_credentials grant ──────────────────────────────
  describe('POST /oauth/token — client_credentials', () => {
    it('issues an access token for valid client credentials', async () => {
      const res = await request(app).post('/oauth/token').send({
        grant_type: 'client_credentials',
        client_id: 'grafana-od-client',
        client_secret: 'test-grafana-secret',
        scope: 'read',
      });
      expect(res.status).toBe(200);
      expect(res.body.token_type).toBe('Bearer');
      expect(typeof res.body.access_token).toBe('string');
      expect(res.body.access_token.split('.')).toHaveLength(3); // JWT shape
    });

    it('rejects an unknown client_id with 401 invalid_client', async () => {
      const res = await request(app).post('/oauth/token').send({
        grant_type: 'client_credentials',
        client_id: 'no-such-client',
        client_secret: 'whatever',
      });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid_client');
    });

    it('rejects a wrong client_secret with 401 invalid_client', async () => {
      const res = await request(app).post('/oauth/token').send({
        grant_type: 'client_credentials',
        client_id: 'grafana-od-client',
        client_secret: 'wrong-secret',
      });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid_client');
    });

    it('rejects an unsupported grant_type with 400 unsupported_grant_type (valid client)', async () => {
      const res = await request(app).post('/oauth/token').send({
        grant_type: 'password', // ROPC — never implemented here
        client_id: 'grafana-od-client',
        client_secret: 'test-grafana-secret',
        username: 'alice',
        password: 'irrelevant',
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('unsupported_grant_type');
    });
  });

  // ── authorization_code → token → refresh_token, end to end ──────────────
  describe('Authorization code + refresh token flow', () => {
    const CLIENT_ID = 'devportal-od-client';
    const CLIENT_SECRET = 'test-devportal-secret';
    const REDIRECT_URI = 'http://localhost:4000/callback';

    async function obtainAuthCode() {
      const res = await request(app).post('/oauth/authorize/login').send({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: 'openid profile email',
        state: 'xyz123',
        username: 'alice',
        password: 'correct-horse-battery-staple',
      });
      expect(res.status).toBe(302);
      expect(res.headers.location.startsWith(REDIRECT_URI)).toBe(true);
      return codeFromRedirect(res.headers.location);
    }

    it('POST /oauth/authorize/login redirects with an auth code + preserved state', async () => {
      const res = await request(app).post('/oauth/authorize/login').send({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: 'openid profile email',
        state: 'preserve-me',
        username: 'alice',
        password: 'whatever',
      });
      expect(res.status).toBe(302);
      const url = new URL(res.headers.location);
      expect(url.searchParams.get('code')).toBeTruthy();
      expect(url.searchParams.get('state')).toBe('preserve-me');
    });

    it('exchanges a valid code for access/id/refresh tokens', async () => {
      const code = await obtainAuthCode();
      const res = await request(app).post('/oauth/token').send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      });
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ token_type: 'Bearer' });
      expect(typeof res.body.access_token).toBe('string');
      expect(typeof res.body.id_token).toBe('string');
      expect(typeof res.body.refresh_token).toBe('string');
    });

    it('a code can only be redeemed once (second exchange → 400 invalid_grant)', async () => {
      const code = await obtainAuthCode();
      const first = await request(app).post('/oauth/token').send({
        grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
      });
      expect(first.status).toBe(200);

      const second = await request(app).post('/oauth/token').send({
        grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
      });
      expect(second.status).toBe(400);
      expect(second.body.error).toBe('invalid_grant');
    });

    it('rejects a bogus authorization code with 400 invalid_grant', async () => {
      const res = await request(app).post('/oauth/token').send({
        grant_type: 'authorization_code',
        code: 'totally-made-up-code',
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('invalid_grant');
    });

    it('refresh_token grant issues a new access token and rotates the refresh token', async () => {
      const code = await obtainAuthCode();
      const tokenRes = await request(app).post('/oauth/token').send({
        grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
      });
      const refreshRes = await request(app).post('/oauth/token').send({
        grant_type: 'refresh_token',
        refresh_token: tokenRes.body.refresh_token,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      });
      expect(refreshRes.status).toBe(200);
      expect(typeof refreshRes.body.access_token).toBe('string');
      // NOTE: the new access_token can be byte-identical to the old one when both
      // are issued within the same wall-clock second — the JWT payload (sub, iss,
      // aud, name, email, groups, scope, iat) is otherwise identical and RS256
      // (RSASSA-PKCS1-v1_5) signing is deterministic. So token *equality* is not
      // a meaningful assertion here; what actually rotates is the refresh token.
      expect(refreshRes.body.refresh_token).not.toBe(tokenRes.body.refresh_token);

      // The old refresh token is one-time-use: the endpoint deletes its map
      // entry before issuing the new pair, so reusing it must now fail.
      const reuseRes = await request(app).post('/oauth/token').send({
        grant_type: 'refresh_token',
        refresh_token: tokenRes.body.refresh_token,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      });
      expect(reuseRes.status).toBe(400);
      expect(reuseRes.body.error).toBe('invalid_grant');
    });

    it('rejects a bogus refresh_token with 400 invalid_grant', async () => {
      const res = await request(app).post('/oauth/token').send({
        grant_type: 'refresh_token',
        refresh_token: 'not-a-real-refresh-token',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('invalid_grant');
    });
  });

  // ── Device authorization flow (RFC 8628) ─────────────────────────────────
  describe('Device authorization flow', () => {
    it('POST /oauth/device/code issues a device_code + user_code', async () => {
      const res = await request(app).post('/oauth/device/code').send({ client_id: 'devportal-od-client', scope: 'openid profile' });
      expect(res.status).toBe(200);
      expect(res.body.device_code).toBeTruthy();
      // 3 random bytes hex-encoded (6 chars) with a dash inserted after the
      // first 4 -> "XXXX-XX" (not the more common "XXXX-XXXX" shape).
      expect(res.body.user_code).toMatch(/^[0-9A-F]{4}-[0-9A-F]{2}$/);
      expect(res.body.verification_uri).toContain('/oauth/device/verify');
    });

    it('polling before approval returns 400 authorization_pending', async () => {
      const codeRes = await request(app).post('/oauth/device/code').send({ client_id: 'devportal-od-client' });
      const res = await request(app).post('/oauth/token').send({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: codeRes.body.device_code,
        client_id: 'devportal-od-client',
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('authorization_pending');
    });

    it('unknown device_code returns 400 expired_token', async () => {
      const res = await request(app).post('/oauth/token').send({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: 'no-such-device-code',
        client_id: 'devportal-od-client',
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('expired_token');
    });

    it('approving the user_code then polling issues an access token', async () => {
      const codeRes = await request(app).post('/oauth/device/code').send({ client_id: 'devportal-od-client', scope: 'openid' });
      const approveRes = await request(app).post('/oauth/device/approve').send({
        user_code: codeRes.body.user_code,
        username: 'bob',
        password: 'whatever',
      });
      expect(approveRes.status).toBe(200);
      expect(approveRes.text).toMatch(/authorized/i);

      const tokenRes = await request(app).post('/oauth/token').send({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: codeRes.body.device_code,
        client_id: 'devportal-od-client',
      });
      expect(tokenRes.status).toBe(200);
      expect(typeof tokenRes.body.access_token).toBe('string');
    });
  });

  // ── /oauth/userinfo — bearer auth enforcement ────────────────────────────
  describe('GET /oauth/userinfo (auth enforcement)', () => {
    it('401s with no Authorization header', async () => {
      const res = await request(app).get('/oauth/userinfo');
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid_token');
    });

    it('401s with a garbage bearer token', async () => {
      const res = await request(app).get('/oauth/userinfo').set('Authorization', 'Bearer not-a-real-jwt');
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid_token');
    });

    it('200s with claims for a valid access token', async () => {
      const tokenRes = await request(app).post('/oauth/token').send({
        grant_type: 'client_credentials', client_id: 'grafana-od-client', client_secret: 'test-grafana-secret',
      });
      const res = await request(app).get('/oauth/userinfo').set('Authorization', `Bearer ${tokenRes.body.access_token}`);
      expect(res.status).toBe(200);
      expect(res.body.sub).toBe('grafana-od-client');
    });
  });

  // ── Introspection + revocation ───────────────────────────────────────────
  describe('POST /oauth/introspect + /oauth/revoke', () => {
    // `scope` is optional and otherwise unused by the assertions below — its
    // only purpose is to let a caller force a distinct token when issuing
    // more than one client_credentials token for the same client within the
    // same wall-clock second. RS256/PKCS#1v1.5 signing is deterministic, and
    // the token payload here (sub/iss/aud/iat/scope) has no per-call nonce,
    // so two same-second, same-scope calls for the same client produce
    // byte-identical JWTs (and therefore identical revocation hashes) —
    // without this, tests that revoke/introspect distinct "tokens" in quick
    // succession could accidentally collide with each other's tokens.
    async function issueClientCredsToken(scope) {
      const res = await request(app).post('/oauth/token').send({
        grant_type: 'client_credentials', client_id: 'grafana-od-client', client_secret: 'test-grafana-secret',
        ...(scope ? { scope } : {}),
      });
      return res.body.access_token;
    }

    it('introspect rejects a bad client_secret with 401 invalid_client', async () => {
      const token = await issueClientCredsToken();
      const res = await request(app).post('/oauth/introspect').send({ token, client_id: 'grafana-od-client', client_secret: 'wrong' });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid_client');
    });

    it('introspect reports active:true for a live token', async () => {
      const token = await issueClientCredsToken();
      const res = await request(app).post('/oauth/introspect').send({ token, client_id: 'grafana-od-client', client_secret: 'test-grafana-secret' });
      expect(res.status).toBe(200);
      expect(res.body.active).toBe(true);
      expect(res.body.sub).toBe('grafana-od-client');
    });

    it('introspect reports active:false for a garbage token', async () => {
      const res = await request(app).post('/oauth/introspect').send({ token: 'garbage', client_id: 'grafana-od-client', client_secret: 'test-grafana-secret' });
      expect(res.status).toBe(200);
      expect(res.body.active).toBe(false);
    });

    it('revoking a token (with correct client auth) makes it inactive on subsequent introspection', async () => {
      const token = await issueClientCredsToken('test-revoke-basic');
      const revokeRes = await request(app).post('/oauth/revoke').send({
        token, client_id: 'grafana-od-client', client_secret: 'test-grafana-secret',
      });
      expect(revokeRes.status).toBe(200);
      expect(revokeRes.body.ok).toBe(true);

      const introspectRes = await request(app).post('/oauth/introspect').send({ token, client_id: 'grafana-od-client', client_secret: 'test-grafana-secret' });
      expect(introspectRes.body.active).toBe(false);
    });

    // ── Regression coverage: /oauth/revoke previously had NO client
    // authentication at all — any caller who had (or could guess the SHA-256
    // hash of) a token could revoke it for someone else, a pure DoS/sabotage
    // primitive against any client's users. RFC 7009 §2.1 requires the same
    // client auth the token endpoint uses; this block proves it's now
    // enforced the same way /oauth/introspect enforces it (client_id +
    // client_secret in the body), and that a non-owning-but-authenticated
    // client cannot revoke another client's token.
    describe('client authentication on /oauth/revoke (was: none — RFC 7009 gap)', () => {
      it('rejects a revoke with no client credentials at all (401 invalid_client)', async () => {
        const token = await issueClientCredsToken('test-revoke-no-creds');
        const res = await request(app).post('/oauth/revoke').send({ token });
        expect(res.status).toBe(401);
        expect(res.body.error).toBe('invalid_client');

        // The token must still be live — an unauthenticated caller must not
        // be able to revoke it as a side effect of the failed attempt.
        const introspectRes = await request(app).post('/oauth/introspect').send({
          token, client_id: 'grafana-od-client', client_secret: 'test-grafana-secret',
        });
        expect(introspectRes.body.active).toBe(true);
      });

      it('rejects a revoke with a wrong client_secret (401 invalid_client)', async () => {
        const token = await issueClientCredsToken('test-revoke-wrong-secret');
        const res = await request(app).post('/oauth/revoke').send({
          token, client_id: 'grafana-od-client', client_secret: 'wrong',
        });
        expect(res.status).toBe(401);
        expect(res.body.error).toBe('invalid_client');
      });

      it('rejects a revoke from an unknown client_id (401 invalid_client)', async () => {
        const token = await issueClientCredsToken('test-revoke-unknown-client');
        const res = await request(app).post('/oauth/revoke').send({
          token, client_id: 'nonexistent-client', client_secret: 'whatever',
        });
        expect(res.status).toBe(401);
        expect(res.body.error).toBe('invalid_client');
      });

      it('a DIFFERENT, correctly-authenticated client cannot revoke a token it does not own', async () => {
        // grafana-od-client mints the token; devportal-od-client (a real,
        // separately-authenticated client) tries to revoke it. Per RFC 7009
        // §2.2 this must not leak anything — still 200 — but the token must
        // survive, unlike the pre-fix behavior where ANY caller could kill
        // ANY client's token.
        const token = await issueClientCredsToken('test-revoke-cross-client');
        const res = await request(app).post('/oauth/revoke').send({
          token, client_id: 'devportal-od-client', client_secret: 'test-devportal-secret',
        });
        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);

        const introspectRes = await request(app).post('/oauth/introspect').send({
          token, client_id: 'grafana-od-client', client_secret: 'test-grafana-secret',
        });
        expect(introspectRes.body.active).toBe(true);
      });

      it('the owning client can still revoke its own token (no functional regression)', async () => {
        const token = await issueClientCredsToken('test-revoke-owning-client');
        const res = await request(app).post('/oauth/revoke').send({
          token, client_id: 'grafana-od-client', client_secret: 'test-grafana-secret',
        });
        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);

        const introspectRes = await request(app).post('/oauth/introspect').send({
          token, client_id: 'grafana-od-client', client_secret: 'test-grafana-secret',
        });
        expect(introspectRes.body.active).toBe(false);
      });
    });
  });

  // ── Enrollment tokens (device-join depends on these) ─────────────────────
  //
  // GET /api/enrollment/tokens and the rotate endpoint are admin-only (P0
  // fix — they previously leaked raw, immediately-usable enrollment tokens
  // to anyone who could reach the service). POST /api/enrollment/register
  // stays public/unauthenticated by design: a device presents the
  // enrollment token itself as its credential, since it has no JWT yet.
  describe('Enrollment tokens', () => {
    it('GET /api/enrollment/tokens requires admin auth (401 with no token)', async () => {
      const res = await request(app).get('/api/enrollment/tokens');
      expect(res.status).toBe(401);
    });

    it('GET /api/enrollment/tokens rejects a non-admin token (403)', async () => {
      const nonAdminToken = await getNonAdminToken();
      const res = await request(app).get('/api/enrollment/tokens').set('Authorization', `Bearer ${nonAdminToken}`);
      expect(res.status).toBe(403);
    });

    it('GET /api/enrollment/tokens (admin) lists one token per platform', async () => {
      const adminToken = await getAdminToken();
      const res = await request(app).get('/api/enrollment/tokens').set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      const platforms = res.body.map((t) => t.platform).sort();
      expect(platforms).toEqual(['android', 'ios', 'linux', 'macos', 'windows']);
      for (const t of res.body) {
        expect(typeof t.token).toBe('string');
        expect(t.uses).toBe(0);
      }
    });

    it('register with an invalid token → 401 (public endpoint, no admin auth needed)', async () => {
      const res = await request(app).post('/api/enrollment/register').send({
        token: 'NOT-A-REAL-TOKEN', platform: 'linux', hostname: 'attacker-box',
      });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid token');
    });

    it('register with a valid token issues a device + long-lived device token', async () => {
      const adminToken = await getAdminToken();
      const tokensRes = await request(app).get('/api/enrollment/tokens').set('Authorization', `Bearer ${adminToken}`);
      const linuxToken = tokensRes.body.find((t) => t.platform === 'linux').token;

      const res = await request(app).post('/api/enrollment/register').send({
        token: linuxToken, platform: 'linux', hostname: 'ci-runner-01', os: '6.8.0',
      });
      expect(res.status).toBe(201);
      expect(res.body.deviceId).toBeTruthy();
      expect(typeof res.body.deviceToken).toBe('string');
      expect(res.body.deviceToken.split('.')).toHaveLength(3);
    });

    it('a token issued for one platform is rejected when submitted with a different platform', async () => {
      const adminToken = await getAdminToken();
      const tokensRes = await request(app).get('/api/enrollment/tokens').set('Authorization', `Bearer ${adminToken}`);
      const windowsToken = tokensRes.body.find((t) => t.platform === 'windows').token;

      const res = await request(app).post('/api/enrollment/register').send({
        token: windowsToken, platform: 'macos', hostname: 'spoofed-platform',
      });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid token');
    });

    it('rotating a platform token invalidates the previous token', async () => {
      const adminToken = await getAdminToken();
      const before = await request(app).get('/api/enrollment/tokens').set('Authorization', `Bearer ${adminToken}`);
      const oldMacToken = before.body.find((t) => t.platform === 'macos').token;

      const rotateRes = await request(app).post('/api/enrollment/tokens/macos/rotate').set('Authorization', `Bearer ${adminToken}`);
      expect(rotateRes.status).toBe(200);
      expect(rotateRes.body.token).not.toBe(oldMacToken);
      expect(rotateRes.body.uses).toBe(0);

      const registerWithOld = await request(app).post('/api/enrollment/register').send({
        token: oldMacToken, platform: 'macos', hostname: 'should-be-rejected',
      });
      expect(registerWithOld.status).toBe(401);

      const registerWithNew = await request(app).post('/api/enrollment/register').send({
        token: rotateRes.body.token, platform: 'macos', hostname: 'should-work',
      });
      expect(registerWithNew.status).toBe(201);
    });

    it('POST /api/enrollment/tokens/:platform/rotate requires admin auth (401 with no token)', async () => {
      const res = await request(app).post('/api/enrollment/tokens/macos/rotate');
      expect(res.status).toBe(401);
    });

    it('rotating an unknown platform returns 400', async () => {
      const adminToken = await getAdminToken();
      const res = await request(app).post('/api/enrollment/tokens/solaris/rotate').set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(400);
    });

    it('a token is rejected once it has been used maxUses times (429 token exhausted)', async () => {
      const adminToken = await getAdminToken();
      const tokensRes = await request(app).get('/api/enrollment/tokens').set('Authorization', `Bearer ${adminToken}`);
      const android = tokensRes.body.find((t) => t.platform === 'android'); // maxUses: 25

      for (let i = 0; i < android.maxUses; i++) {
        const res = await request(app).post('/api/enrollment/register').send({
          token: android.token, platform: 'android', hostname: `android-device-${i}`,
        });
        expect(res.status).toBe(201);
      }

      const overLimit = await request(app).post('/api/enrollment/register').send({
        token: android.token, platform: 'android', hostname: 'one-too-many',
      });
      expect(overLimit.status).toBe(429);
      expect(overLimit.body.error).toBe('token exhausted');
    });
  });

  // ── SCIM 2.0 Users ────────────────────────────────────────────────────────
  //
  // The whole /scim/v2/* surface is admin-only (P0 fix — it previously
  // exposed the full user/group directory, including emails, to anyone who
  // could reach the service, and allowed unauthenticated writes).
  describe('SCIM 2.0 /scim/v2/Users', () => {
    it('GET /scim/v2/Users requires admin auth (401 with no token, 403 for a non-admin token)', async () => {
      const noAuth = await request(app).get('/scim/v2/Users');
      expect(noAuth.status).toBe(401);

      const nonAdminToken = await getNonAdminToken();
      const forbidden = await request(app).get('/scim/v2/Users').set('Authorization', `Bearer ${nonAdminToken}`);
      expect(forbidden.status).toBe(403);
    });

    it('GET lists the seeded users in ListResponse shape (admin)', async () => {
      const adminToken = await getAdminToken();
      const res = await request(app).get('/scim/v2/Users').set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.schemas).toContain('urn:ietf:params:scim:api:messages:2.0:ListResponse');
      expect(res.body.totalResults).toBeGreaterThanOrEqual(2);
      const userNames = res.body.Resources.map((u) => u.userName);
      expect(userNames).toEqual(expect.arrayContaining(['alice', 'bob']));
    });

    it('POST without a token is rejected (401), never creates the user', async () => {
      const res = await request(app).post('/scim/v2/Users').send({
        userName: 'mallory', displayName: 'Should Not Exist',
      });
      expect(res.status).toBe(401);

      const adminToken = await getAdminToken();
      const listRes = await request(app).get('/scim/v2/Users').set('Authorization', `Bearer ${adminToken}`);
      expect(listRes.body.Resources.map((u) => u.userName)).not.toContain('mallory');
    });

    it('POST (admin) creates a new user with a SCIM User resource shape', async () => {
      const adminToken = await getAdminToken();
      const res = await request(app).post('/scim/v2/Users').set('Authorization', `Bearer ${adminToken}`).send({
        userName: 'carol', displayName: 'Carol Contractor', emails: [{ value: 'carol@opendirectory.local', primary: true }],
      });
      expect(res.status).toBe(201);
      expect(res.body.schemas).toContain('urn:ietf:params:scim:schemas:core:2.0:User');
      expect(res.body.id).toBeTruthy();
      expect(res.body.userName).toBe('carol');
      expect(res.body.meta.resourceType).toBe('User');

      // Newly created user is immediately visible via GET (list is in-memory, not DB-backed)
      const listRes = await request(app).get('/scim/v2/Users').set('Authorization', `Bearer ${adminToken}`);
      expect(listRes.body.Resources.map((u) => u.userName)).toContain('carol');
    });

    it('GET /scim/v2/Users/:id 404s for an unknown id (admin)', async () => {
      const adminToken = await getAdminToken();
      const res = await request(app).get('/scim/v2/Users/00000000-0000-0000-0000-000000000000').set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(404);
    });
  });

  // ── Security fixes — regression coverage ─────────────────────────────────
  //
  // This block used to be "Security findings (documented, not fixed here)":
  // four tests that deliberately pinned CURRENT (insecure) behavior so a
  // future accidental fix would show up as a "surprising" green-to-red
  // diff. All four gaps have since been fixed (P0 auth pass) — the tests
  // below assert the SECURE behavior instead, so a regression now shows up
  // the normal way: a red test.
  describe('Security fixes — regression coverage', () => {
    describe('Admin auth on the enrollment-token surface (was: unauthenticated leak)', () => {
      it('GET /api/enrollment/tokens no longer leaks tokens without authentication', async () => {
        const res = await request(app).get('/api/enrollment/tokens'); // no Authorization header at all
        expect(res.status).toBe(401);
        expect(res.body.token).toBeUndefined();
      });
    });

    describe('Auth on MDM command issuance (was: unauthenticated wipe/lock)', () => {
      it('POST /api/devices/:deviceId/commands rejects an unauthenticated "wipe" with 401', async () => {
        const res = await request(app)
          .post('/api/devices/dev-001/commands') // dev-001 is a real seeded device
          .send({ command: 'wipe', payload: {} });
        expect(res.status).toBe(401);
      });

      it('rejects a wipe from a valid but non-admin, non-internal caller (403)', async () => {
        const nonAdminToken = await getNonAdminToken();
        const res = await request(app)
          .post('/api/devices/dev-001/commands')
          .set('Authorization', `Bearer ${nonAdminToken}`)
          .send({ command: 'wipe', payload: {} });
        expect(res.status).toBe(403);
      });

      it('an admin token can issue a wipe command', async () => {
        const adminToken = await getAdminToken();
        const res = await request(app)
          .post('/api/devices/dev-001/commands')
          .set('Authorization', `Bearer ${adminToken}`)
          .send({ command: 'wipe', payload: {} });
        expect(res.status).toBe(201);
        expect(res.body.command).toBe('wipe');
      });

      // Server-to-server callers (antivirus-protection dispatching AV scans,
      // policy-service pushing GPO/blueprint MDM commands) have no end-user
      // JWT to present — they use the shared internal-service-token bypass
      // instead (src/middleware/oidcAuth.js's allowInternalToken option).
      describe('internal-service-token bypass', () => {
        const prevToken = process.env.OAUTH_PROVIDER_INTERNAL_TOKEN;
        beforeEach(() => { process.env.OAUTH_PROVIDER_INTERNAL_TOKEN = 'e2e-internal-secret'; });
        afterEach(() => {
          if (prevToken === undefined) delete process.env.OAUTH_PROVIDER_INTERNAL_TOKEN;
          else process.env.OAUTH_PROVIDER_INTERNAL_TOKEN = prevToken;
        });

        it('a correct internal token issues the command with no Authorization header at all', async () => {
          // update_policy is the command policy-service's GPO/blueprint push
          // actually sends.
          const res = await request(app)
            .post('/api/devices/dev-001/commands')
            .set('x-oauth-internal-token', 'e2e-internal-secret')
            .send({ command: 'update_policy', payload: {} });
          expect(res.status).toBe(201);
        });

        it('run_av_scan (antivirus-protection\'s real MDM command name) is accepted via the internal-token bypass', async () => {
          // Regression coverage: VALID_COMMANDS previously did not include
          // 'run_av_scan', the exact command name antivirus-protection's
          // POST /api/antivirus/scan dispatches (see
          // services/enterprise/antivirus-protection/src/index.js) — every
          // fleet-wide AV scan dispatch 400'd here. Fixed by adding it to
          // the allowlist.
          const res = await request(app)
            .post('/api/devices/dev-001/commands')
            .set('x-oauth-internal-token', 'e2e-internal-secret')
            .send({ command: 'run_av_scan', payload: { scanType: 'quick', paths: null } });
          expect(res.status).toBe(201);
          expect(res.body.command).toBe('run_av_scan');
        });

        it('a wrong internal token is rejected (401)', async () => {
          const res = await request(app)
            .post('/api/devices/dev-001/commands')
            .set('x-oauth-internal-token', 'not-the-secret')
            .send({ command: 'update_policy', payload: {} });
          expect(res.status).toBe(401);
        });

        it('the bypass fails closed when OAUTH_PROVIDER_INTERNAL_TOKEN is unset', async () => {
          delete process.env.OAUTH_PROVIDER_INTERNAL_TOKEN;
          const res = await request(app)
            .post('/api/devices/dev-001/commands')
            .set('x-oauth-internal-token', 'e2e-internal-secret')
            .send({ command: 'update_policy', payload: {} });
          expect(res.status).toBe(401);
        });

        it('a present (even garbage) Bearer token is never silently downgraded to the internal-token path', async () => {
          const res = await request(app)
            .post('/api/devices/dev-001/commands')
            .set('Authorization', 'Bearer not-a-real-jwt')
            .set('x-oauth-internal-token', 'e2e-internal-secret')
            .send({ command: 'update_policy', payload: {} });
          expect(res.status).toBe(403); // JWT verify fails; internal token is not consulted
        });

        it('GET /api/devices/registry also accepts the internal-token bypass', async () => {
          const res = await request(app)
            .get('/api/devices/registry')
            .set('x-oauth-internal-token', 'e2e-internal-secret');
          expect(res.status).toBe(200);
          expect(Array.isArray(res.body)).toBe(true);
        });
      });
    });

    describe('PKCE is now enforced (was: code_verifier accepted but never checked)', () => {
      function s256Challenge(verifier) {
        return crypto.createHash('sha256').update(verifier).digest('base64url');
      }

      it('redeeming a PKCE-protected code with NO code_verifier now fails (400 invalid_grant)', async () => {
        const loginRes = await request(app).post('/oauth/authorize/login').send({
          client_id: 'devportal-od-client',
          redirect_uri: 'http://localhost:4000/callback',
          scope: 'openid',
          code_challenge: 'some-s256-challenge-value',
          code_challenge_method: 'S256',
          username: 'alice',
          password: 'whatever',
        });
        const code = codeFromRedirect(loginRes.headers.location);

        const tokenRes = await request(app).post('/oauth/token').send({
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'http://localhost:4000/callback',
          client_id: 'devportal-od-client',
          client_secret: 'test-devportal-secret',
          // code_verifier intentionally omitted
        });
        expect(tokenRes.status).toBe(400);
        expect(tokenRes.body.error).toBe('invalid_grant');
      });

      it('redeeming with a WRONG code_verifier fails (400 invalid_grant)', async () => {
        const loginRes = await request(app).post('/oauth/authorize/login').send({
          client_id: 'devportal-od-client',
          redirect_uri: 'http://localhost:4000/callback',
          scope: 'openid',
          code_challenge: s256Challenge('the-real-verifier'),
          code_challenge_method: 'S256',
          username: 'alice',
          password: 'whatever',
        });
        const code = codeFromRedirect(loginRes.headers.location);

        const tokenRes = await request(app).post('/oauth/token').send({
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'http://localhost:4000/callback',
          client_id: 'devportal-od-client',
          client_secret: 'test-devportal-secret',
          code_verifier: 'a-completely-different-verifier',
        });
        expect(tokenRes.status).toBe(400);
        expect(tokenRes.body.error).toBe('invalid_grant');
      });

      it('a matching S256 code_verifier succeeds', async () => {
        const verifier = 'a-valid-code-verifier-1234567890';
        const loginRes = await request(app).post('/oauth/authorize/login').send({
          client_id: 'devportal-od-client',
          redirect_uri: 'http://localhost:4000/callback',
          scope: 'openid',
          code_challenge: s256Challenge(verifier),
          code_challenge_method: 'S256',
          username: 'alice',
          password: 'whatever',
        });
        const code = codeFromRedirect(loginRes.headers.location);

        const tokenRes = await request(app).post('/oauth/token').send({
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'http://localhost:4000/callback',
          client_id: 'devportal-od-client',
          client_secret: 'test-devportal-secret',
          code_verifier: verifier,
        });
        expect(tokenRes.status).toBe(200);
        expect(typeof tokenRes.body.access_token).toBe('string');
      });

      it('a matching plain code_verifier succeeds (code_challenge_method: plain)', async () => {
        const verifier = 'plain-verifier-used-as-is';
        const loginRes = await request(app).post('/oauth/authorize/login').send({
          client_id: 'devportal-od-client',
          redirect_uri: 'http://localhost:4000/callback',
          scope: 'openid',
          code_challenge: verifier, // plain: challenge === verifier
          code_challenge_method: 'plain',
          username: 'alice',
          password: 'whatever',
        });
        const code = codeFromRedirect(loginRes.headers.location);

        const tokenRes = await request(app).post('/oauth/token').send({
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'http://localhost:4000/callback',
          client_id: 'devportal-od-client',
          client_secret: 'test-devportal-secret',
          code_verifier: verifier,
        });
        expect(tokenRes.status).toBe(200);
      });

      it('a code obtained WITHOUT a code_challenge still redeems fine with no verifier (PKCE is optional, not mandatory)', async () => {
        const loginRes = await request(app).post('/oauth/authorize/login').send({
          client_id: 'devportal-od-client',
          redirect_uri: 'http://localhost:4000/callback',
          scope: 'openid',
          username: 'alice',
          password: 'whatever',
        });
        const code = codeFromRedirect(loginRes.headers.location);

        const tokenRes = await request(app).post('/oauth/token').send({
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'http://localhost:4000/callback',
          client_id: 'devportal-od-client',
          client_secret: 'test-devportal-secret',
        });
        expect(tokenRes.status).toBe(200);
      });
    });

    describe('redirect_uri is now re-validated at the token endpoint (was: never checked)', () => {
      it('a redirect_uri that differs from the one used at /oauth/authorize now fails (400 invalid_grant)', async () => {
        const loginRes = await request(app).post('/oauth/authorize/login').send({
          client_id: 'devportal-od-client',
          redirect_uri: 'http://localhost:4000/callback', // registered URI used at authorize time
          scope: 'openid',
          username: 'alice',
          password: 'whatever',
        });
        const code = codeFromRedirect(loginRes.headers.location);

        const tokenRes = await request(app).post('/oauth/token').send({
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'https://dev.example.com/auth/callback', // a *different* registered URI for the same client
          client_id: 'devportal-od-client',
          client_secret: 'test-devportal-secret',
        });
        expect(tokenRes.status).toBe(400);
        expect(tokenRes.body.error).toBe('invalid_grant');
      });

      it('a matching redirect_uri still succeeds', async () => {
        const loginRes = await request(app).post('/oauth/authorize/login').send({
          client_id: 'devportal-od-client',
          redirect_uri: 'http://localhost:4000/callback',
          scope: 'openid',
          username: 'alice',
          password: 'whatever',
        });
        const code = codeFromRedirect(loginRes.headers.location);

        const tokenRes = await request(app).post('/oauth/token').send({
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'http://localhost:4000/callback',
          client_id: 'devportal-od-client',
          client_secret: 'test-devportal-secret',
        });
        expect(tokenRes.status).toBe(200);
      });
    });

    describe('per-client grantTypes allowlist is now enforced (was: never checked)', () => {
      it('a client registered only for authorization_code/refresh_token can no longer mint tokens via client_credentials', async () => {
        // devportal-od-client is seeded WITHOUT client_credentials in grantTypes.
        const res = await request(app).post('/oauth/token').send({
          grant_type: 'client_credentials',
          client_id: 'devportal-od-client',
          client_secret: 'test-devportal-secret',
        });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('unauthorized_client');
      });

      it('a client WITH client_credentials in its allowlist can still use it (grafana-od-client)', async () => {
        const res = await request(app).post('/oauth/token').send({
          grant_type: 'client_credentials',
          client_id: 'grafana-od-client',
          client_secret: 'test-grafana-secret',
        });
        expect(res.status).toBe(200);
        expect(typeof res.body.access_token).toBe('string');
      });

      it('a client without the device-code grant in its allowlist cannot use the device flow', async () => {
        // grafana-od-client's grantTypes are authorization_code/refresh_token/client_credentials only.
        const codeRes = await request(app).post('/oauth/device/code').send({ client_id: 'grafana-od-client' });
        const res = await request(app).post('/oauth/token').send({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: codeRes.body.device_code,
          client_id: 'grafana-od-client',
        });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('unauthorized_client');
      });

      it('an entirely unimplemented grant_type still reports unsupported_grant_type, not unauthorized_client', async () => {
        // Regression guard: the grantTypes allowlist check must only apply to
        // grant types this server actually implements — 'password' (ROPC)
        // was never implemented at all and must keep falling through to the
        // generic unsupported_grant_type response.
        const res = await request(app).post('/oauth/token').send({
          grant_type: 'password',
          client_id: 'grafana-od-client',
          client_secret: 'test-grafana-secret',
          username: 'alice',
          password: 'irrelevant',
        });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('unsupported_grant_type');
      });
    });
  });

  // ── Admin surface auth enforcement (broad sampling) ──────────────────────
  //
  // Representative sweep across the rest of the management surface (client
  // registry, SCIM groups, device status, SCIM push log/connections/
  // conflicts, update rings, app-catalog provisioning, package deploy) to
  // catch a route that was missed when auth was added, without hand-writing
  // a full request/response test for every single one (the sections above
  // already cover the highest-severity routes in depth).
  describe('Admin surface auth enforcement (401 with no bearer token)', () => {
    const routes = [
      ['get',    '/api/clients'],
      ['post',   '/api/clients'],
      ['put',    '/api/clients/dummy-id'],
      ['delete', '/api/clients/dummy-id'],
      ['get',    '/scim/v2/Groups'],
      ['post',   '/scim/v2/Groups'],
      ['get',    '/scim/v2/Groups/dummy-id'],
      ['put',    '/scim/v2/Groups/dummy-id'],
      ['delete', '/scim/v2/Groups/dummy-id'],
      ['get',    '/api/devices/registry'],
      ['put',    '/api/devices/dummy-id/status'],
      ['get',    '/api/devices/dummy-id/commands'],
      ['get',    '/api/scim-push/log'],
      ['get',    '/api/scim/connections'],
      ['post',   '/api/scim/connections'],
      ['put',    '/api/scim/connections/dummy-id'],
      ['delete', '/api/scim/connections/dummy-id'],
      ['post',   '/api/scim/connections/dummy-id/sync'],
      ['get',    '/api/scim/connections/dummy-id/log'],
      ['get',    '/api/scim/conflicts'],
      ['post',   '/api/scim/conflicts/dummy-id/resolve'],
      ['get',    '/api/update-rings'],
      ['put',    '/api/update-rings/stable'],
      ['post',   '/api/update-rings/stable/assign'],
      ['post',   '/api/scim-push/someapp/provision'],
      ['post',   '/api/packages'],
      ['post',   '/api/packages/pkg-x/deploy/dev-x'],
      ['post',   '/api/packages/pkg-x/deploy-all'],
    ];

    it.each(routes)('%s %s -> 401 without a bearer token', async (method, path) => {
      const res = await request(app)[method](path);
      expect(res.status).toBe(401);
    });
  });

  // ── Device-self routes ────────────────────────────────────────────────────
  //
  // These are called by the device agent itself using the long-lived
  // deviceToken it receives at enrollment (see agent/internal/commands/
  // executor.go and agent/internal/compliance/checker.go — both already send
  // `Authorization: Bearer <DeviceToken>`), not an admin token. They require
  // SOME valid, non-revoked bearer JWT but not the oauth.admin scope/role.
  describe('Device-self routes require a bearer token (any valid JWT, not admin)', () => {
    it('GET /api/devices/:id/commands/pending -> 401 with no token', async () => {
      const res = await request(app).get('/api/devices/dev-001/commands/pending');
      expect(res.status).toBe(401);
    });

    it('a freshly-enrolled device token can poll its own pending-commands queue', async () => {
      const { deviceId, deviceToken } = await enrollDevice();
      const res = await request(app)
        .get(`/api/devices/${deviceId}/commands/pending`)
        .set('Authorization', `Bearer ${deviceToken}`);
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
    });

    it('PATCH /api/devices/:id/commands/:cmdId -> 401 with no token', async () => {
      const res = await request(app).patch('/api/devices/dev-001/commands/some-cmd-id').send({ status: 'completed' });
      expect(res.status).toBe(401);
    });

    it('POST /api/devices/:id/compliance-check -> 401 with no token', async () => {
      const res = await request(app).post('/api/devices/dev-001/compliance-check').send({ settings: {} });
      expect(res.status).toBe(401);
    });

    it('a device token can report its own compliance-check', async () => {
      const { deviceId, deviceToken } = await enrollDevice();
      const res = await request(app)
        .post(`/api/devices/${deviceId}/compliance-check`)
        .set('Authorization', `Bearer ${deviceToken}`)
        .send({ settings: {}, platform: 'linux' });
      expect(res.status).toBe(200);
    });

    it('POST /api/devices/:id/heartbeat -> 401 with no token', async () => {
      const res = await request(app).post('/api/devices/dev-001/heartbeat').send({});
      expect(res.status).toBe(401);
    });
  });
});
