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

const request = require('supertest');
const app = require('../index');

/** Pull the `code` query param off a Location header from a 302 redirect. */
function codeFromRedirect(location) {
  const url = new URL(location);
  return url.searchParams.get('code');
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
    async function issueClientCredsToken() {
      const res = await request(app).post('/oauth/token').send({
        grant_type: 'client_credentials', client_id: 'grafana-od-client', client_secret: 'test-grafana-secret',
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

    it('revoking a token makes it inactive on subsequent introspection', async () => {
      const token = await issueClientCredsToken();
      const revokeRes = await request(app).post('/oauth/revoke').send({ token });
      expect(revokeRes.status).toBe(200);
      expect(revokeRes.body.ok).toBe(true);

      const introspectRes = await request(app).post('/oauth/introspect').send({ token, client_id: 'grafana-od-client', client_secret: 'test-grafana-secret' });
      expect(introspectRes.body.active).toBe(false);
    });
  });

  // ── Enrollment tokens (device-join depends on these) ─────────────────────
  describe('Enrollment tokens', () => {
    it('GET /api/enrollment/tokens lists one token per platform', async () => {
      const res = await request(app).get('/api/enrollment/tokens');
      expect(res.status).toBe(200);
      const platforms = res.body.map((t) => t.platform).sort();
      expect(platforms).toEqual(['android', 'ios', 'linux', 'macos', 'windows']);
      for (const t of res.body) {
        expect(typeof t.token).toBe('string');
        expect(t.uses).toBe(0);
      }
    });

    it('register with an invalid token → 401', async () => {
      const res = await request(app).post('/api/enrollment/register').send({
        token: 'NOT-A-REAL-TOKEN', platform: 'linux', hostname: 'attacker-box',
      });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid token');
    });

    it('register with a valid token issues a device + long-lived device token', async () => {
      const tokensRes = await request(app).get('/api/enrollment/tokens');
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
      const tokensRes = await request(app).get('/api/enrollment/tokens');
      const windowsToken = tokensRes.body.find((t) => t.platform === 'windows').token;

      const res = await request(app).post('/api/enrollment/register').send({
        token: windowsToken, platform: 'macos', hostname: 'spoofed-platform',
      });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid token');
    });

    it('rotating a platform token invalidates the previous token', async () => {
      const before = await request(app).get('/api/enrollment/tokens');
      const oldMacToken = before.body.find((t) => t.platform === 'macos').token;

      const rotateRes = await request(app).post('/api/enrollment/tokens/macos/rotate');
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

    it('rotating an unknown platform returns 400', async () => {
      const res = await request(app).post('/api/enrollment/tokens/solaris/rotate');
      expect(res.status).toBe(400);
    });

    it('a token is rejected once it has been used maxUses times (429 token exhausted)', async () => {
      const tokensRes = await request(app).get('/api/enrollment/tokens');
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
  describe('SCIM 2.0 /scim/v2/Users', () => {
    it('GET lists the seeded users in ListResponse shape', async () => {
      const res = await request(app).get('/scim/v2/Users');
      expect(res.status).toBe(200);
      expect(res.body.schemas).toContain('urn:ietf:params:scim:api:messages:2.0:ListResponse');
      expect(res.body.totalResults).toBeGreaterThanOrEqual(2);
      const userNames = res.body.Resources.map((u) => u.userName);
      expect(userNames).toEqual(expect.arrayContaining(['alice', 'bob']));
    });

    it('POST creates a new user with a SCIM User resource shape', async () => {
      const res = await request(app).post('/scim/v2/Users').send({
        userName: 'carol', displayName: 'Carol Contractor', emails: [{ value: 'carol@opendirectory.local', primary: true }],
      });
      expect(res.status).toBe(201);
      expect(res.body.schemas).toContain('urn:ietf:params:scim:schemas:core:2.0:User');
      expect(res.body.id).toBeTruthy();
      expect(res.body.userName).toBe('carol');
      expect(res.body.meta.resourceType).toBe('User');

      // Newly created user is immediately visible via GET (list is in-memory, not DB-backed)
      const listRes = await request(app).get('/scim/v2/Users');
      expect(listRes.body.Resources.map((u) => u.userName)).toContain('carol');
    });

    it('GET /scim/v2/Users/:id 404s for an unknown id', async () => {
      const res = await request(app).get('/scim/v2/Users/00000000-0000-0000-0000-000000000000');
      expect(res.status).toBe(404);
    });
  });

  // ── Security findings ─────────────────────────────────────────────────────
  //
  // The tests below are intentionally written to assert CURRENT behavior,
  // not desired/secure behavior. They are green on purpose: they document
  // real gaps this test-authoring pass surfaced in oauth-provider, so a
  // future change that "accidentally" locks these down will show up as a
  // (welcome) test failure here rather than silently changing behavior.
  // See the test-agent report for full write-up, severity, and suggested
  // fixes for each. Do NOT read a passing test in this block as "this is
  // fine" — read it as "this is what happens today".
  describe('Security findings (documented, not fixed here)', () => {
    it('[FINDING] GET /api/enrollment/tokens requires no authentication and leaks raw, usable enrollment tokens for every platform', async () => {
      const res = await request(app).get('/api/enrollment/tokens'); // no Authorization header at all
      expect(res.status).toBe(200);
      expect(res.body.find((t) => t.platform === 'windows').token).toMatch(/^WE-/);
      // Anyone who can reach this service (no service-mesh mTLS boundary
      // assumed by the code itself) can list and use these tokens to
      // self-enroll a device on any supported platform.
    });

    it('[FINDING] POST /api/devices/:deviceId/commands accepts a "wipe" command with no authentication', async () => {
      const res = await request(app)
        .post('/api/devices/dev-001/commands') // dev-001 is a real seeded device
        .send({ command: 'wipe', payload: {} });
      expect(res.status).toBe(201);
      expect(res.body.command).toBe('wipe');
      // No credential of any kind (bearer token, API key, mTLS identity) is
      // required to queue a remote wipe on an arbitrary enrolled device.
      // Same applies to lock/unlock/install_app/uninstall_app.
    });

    it('[FINDING] PKCE code_verifier is accepted but never validated against code_challenge', async () => {
      // Authorize with a PKCE challenge...
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

      // ...then redeem it with NO code_verifier at all (and, separately, a
      // wrong one would behave identically — the field is read off req.body
      // in /oauth/token but never compared against the stored challenge).
      const tokenRes = await request(app).post('/oauth/token').send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost:4000/callback',
        client_id: 'devportal-od-client',
        client_secret: 'test-devportal-secret',
        // code_verifier intentionally omitted
      });
      expect(tokenRes.status).toBe(200); // RFC 7636 says this exchange should fail without a matching verifier
      expect(typeof tokenRes.body.access_token).toBe('string');
    });

    it('[FINDING] the token endpoint does not re-validate redirect_uri against the one used at /oauth/authorize', async () => {
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
      // RFC 6749 §4.1.3 requires this redirect_uri to match the one from the
      // authorization request bit-for-bit; the code never compares them.
      expect(tokenRes.status).toBe(200);
    });

    it('[FINDING] a client registered only for authorization_code can still mint tokens via client_credentials', async () => {
      // devportal-od-client is seeded with grantTypes: ['authorization_code'] only.
      const res = await request(app).post('/oauth/token').send({
        grant_type: 'client_credentials',
        client_id: 'devportal-od-client',
        client_secret: 'test-devportal-secret',
      });
      // /oauth/token never checks client.grantTypes for any grant type, so
      // grant-type restrictions configured via POST /api/clients are not
      // enforced anywhere.
      expect(res.status).toBe(200);
      expect(typeof res.body.access_token).toBe('string');
    });
  });
});
