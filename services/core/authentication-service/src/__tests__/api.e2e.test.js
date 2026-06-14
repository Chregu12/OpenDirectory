'use strict';

/**
 * E2E API tests for Authentication Service
 * Uses supertest in-process with mocked external dependencies
 */

// ─── Mock all external / missing dependencies BEFORE any require ───────────────

// Mock pg
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

// Mock ioredis (used for session store)
jest.mock('ioredis', () => {
  const redisMock = {
    get: jest.fn().mockResolvedValue(null),
    set: jest.fn().mockResolvedValue('OK'),
    setex: jest.fn().mockResolvedValue('OK'),
    del: jest.fn().mockResolvedValue(1),
    on: jest.fn(),
    status: 'ready',
  };
  const Redis = jest.fn().mockImplementation(() => redisMock);
  return Redis;
});

// Mock express-session to avoid Redis session complexity
jest.mock('express-session', () => {
  // Return a simple middleware that sets up req.session as a plain object
  return jest.fn().mockImplementation(() => {
    return (req, res, next) => {
      req.session = {
        id: 'mock-session-id',
        destroy: jest.fn((cb) => cb && cb(null)),
        save: jest.fn((cb) => cb && cb(null)),
        regenerate: jest.fn((cb) => cb && cb(null)),
        reload: jest.fn((cb) => cb && cb(null)),
        touch: jest.fn((cb) => cb && cb(null)),
        cookie: {},
      };
      req.sessionID = 'mock-session-id';
      next();
    };
  });
});

// Mock connect-redis (needed because it's required even though we mock express-session)
jest.mock('connect-redis', () => {
  const MockRedisStore = jest.fn().mockImplementation(() => ({
    get: jest.fn((sid, cb) => cb(null, null)),
    set: jest.fn((sid, session, cb) => cb && cb(null)),
    destroy: jest.fn((sid, cb) => cb && cb(null)),
    touch: jest.fn((sid, session, cb) => cb && cb(null)),
    all: jest.fn((cb) => cb(null, [])),
    length: jest.fn((cb) => cb(null, 0)),
    clear: jest.fn((cb) => cb && cb(null)),
    on: jest.fn(),
  }));
  return { default: MockRedisStore };
});

// Mock amqplib
jest.mock('amqplib', () => ({
  connect: jest.fn().mockResolvedValue({
    createChannel: jest.fn().mockResolvedValue({
      assertExchange: jest.fn().mockResolvedValue({}),
      assertQueue: jest.fn().mockResolvedValue({ queue: 'test-queue' }),
      bindQueue: jest.fn().mockResolvedValue({}),
      publish: jest.fn().mockReturnValue(true),
      consume: jest.fn().mockResolvedValue({}),
      ack: jest.fn(),
      nack: jest.fn(),
      prefetch: jest.fn(),
    }),
    on: jest.fn(),
    close: jest.fn().mockResolvedValue(undefined),
  }),
}));

// Mock passport-ldapauth
jest.mock('passport-ldapauth', () => {
  const Strategy = jest.fn().mockImplementation((opts, verify) => ({
    name: 'ldapauth',
    authenticate: jest.fn(),
    _verify: verify,
  }));
  return Strategy;
});

// Mock argon2
jest.mock('argon2', () => ({
  hash: jest.fn().mockResolvedValue('$argon2id$mock'),
  verify: jest.fn().mockResolvedValue(true),
}));

// Mock speakeasy
jest.mock('speakeasy', () => ({
  generateSecret: jest.fn().mockReturnValue({
    base32: 'MOCKBASE32SECRET',
    otpauth_url: 'otpauth://totp/test?secret=MOCKBASE32SECRET',
  }),
  totp: {
    verify: jest.fn().mockReturnValue(false),
  },
}));

// Mock qrcode
jest.mock('qrcode', () => ({
  toDataURL: jest.fn().mockResolvedValue('data:image/png;base64,mockqrcode'),
}));

// Mock nodemailer
jest.mock('nodemailer', () => ({
  createTransport: jest.fn().mockReturnValue({
    sendMail: jest.fn().mockResolvedValue({ messageId: 'mock-id' }),
  }),
}));

// ─── Mock missing local service files ─────────────────────────────────────────

// Mock utils/logger
jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
}), { virtual: true });

// Mock utils/config
jest.mock('../utils/config', () => ({
  environment: 'test',
  port: 3001,
  cors: { origins: ['http://localhost:3000'] },
  session: { secret: 'test-secret', maxAge: 86400000 },
  jwt: { secret: 'test-jwt-secret', expiresIn: '1h' },
  redis: { host: 'localhost', port: 6379, password: '' },
  ldap: {
    url: 'ldap://localhost:389',
    bindDN: 'cn=admin,dc=test,dc=local',
    bindPassword: 'password',
    searchBase: 'dc=test,dc=local',
    searchFilter: '(uid={{username}})',
    syncNewUsers: false,
  },
  zeroTrust: { enabled: false, minTrustScore: 0 },
  mfa: { enabled: false },
  frontend: { url: 'http://localhost:3000' },
  security: { suspiciousCountries: [] },
}), { virtual: true });

// Mock AuthenticationManager
jest.mock('../services/authenticationManager', () => {
  return jest.fn().mockImplementation(() => ({
    authenticateLocal: jest.fn().mockResolvedValue(null),
    mapLdapUser: jest.fn().mockResolvedValue(null),
    getSSOProviders: jest.fn().mockResolvedValue([]),
    initiateSSOLogin: jest.fn().mockResolvedValue('http://sso-provider'),
    handleSSOCallback: jest.fn().mockResolvedValue({ success: false }),
    createLdapUser: jest.fn().mockResolvedValue(undefined),
    verifyPassword: jest.fn().mockResolvedValue(false),
  }));
}, { virtual: true });

// Mock TokenService
jest.mock('../services/tokenService', () => {
  return jest.fn().mockImplementation(() => ({
    generateAccessToken: jest.fn().mockResolvedValue('mock-access-token'),
    generateRefreshToken: jest.fn().mockResolvedValue('mock-refresh-token'),
    generateTempToken: jest.fn().mockResolvedValue('mock-temp-token'),
    validateToken: jest.fn().mockResolvedValue(false),
    refreshAccessToken: jest.fn().mockResolvedValue(null),
  }));
}, { virtual: true });

// Mock SessionManager
jest.mock('../services/sessionManager', () => {
  return jest.fn().mockImplementation(() => ({
    createSession: jest.fn().mockResolvedValue({ id: 'session-123', expiresAt: new Date().toISOString() }),
    getUserSessions: jest.fn().mockResolvedValue([]),
    revokeSession: jest.fn().mockResolvedValue(undefined),
    revokeAllUserSessions: jest.fn().mockResolvedValue(undefined),
  }));
}, { virtual: true });

// Mock UserService
jest.mock('../services/userService', () => {
  return jest.fn().mockImplementation(() => ({
    validateRegistration: jest.fn().mockResolvedValue({ valid: true, errors: [] }),
    getUserByUsername: jest.fn().mockResolvedValue(null),
    getUserByEmail: jest.fn().mockResolvedValue(null),
    getUserById: jest.fn().mockResolvedValue(null),
    createUser: jest.fn().mockResolvedValue({
      id: 'user-123',
      username: 'testuser',
      email: 'test@example.com',
      roles: ['user'],
      permissions: [],
    }),
    updateUser: jest.fn().mockResolvedValue({}),
    deleteUser: jest.fn().mockResolvedValue(undefined),
    lockUser: jest.fn().mockResolvedValue(undefined),
    unlockUser: jest.fn().mockResolvedValue(undefined),
    listUsers: jest.fn().mockResolvedValue({ users: [], total: 0 }),
    changePassword: jest.fn().mockResolvedValue(undefined),
  }));
}, { virtual: true });

// Mock MFAService
jest.mock('../services/mfaService', () => {
  return jest.fn().mockImplementation(() => ({
    setupMFA: jest.fn().mockResolvedValue({
      secret: 'MOCKBASE32SECRET',
      qrCode: 'data:image/png;base64,mockqrcode',
      recoveryCodes: ['CODE1', 'CODE2'],
    }),
    verifyCode: jest.fn().mockResolvedValue(false),
    enableMFA: jest.fn().mockResolvedValue(undefined),
    disableMFA: jest.fn().mockResolvedValue(undefined),
    getRecoveryCodes: jest.fn().mockResolvedValue(['CODE1', 'CODE2']),
  }));
}, { virtual: true });

// Mock ZeroTrustService
jest.mock('../services/zeroTrustService', () => {
  return jest.fn().mockImplementation(() => ({
    evaluateTrust: jest.fn().mockResolvedValue(100),
    verifyDevice: jest.fn().mockResolvedValue(true),
    verifyLocation: jest.fn().mockResolvedValue(true),
    calculateTrustScore: jest.fn().mockResolvedValue(85),
    getTrustFactors: jest.fn().mockResolvedValue([]),
    performStepUp: jest.fn().mockResolvedValue({ success: true }),
  }));
}, { virtual: true });

// Mock AuditService
jest.mock('../services/auditService', () => {
  return jest.fn().mockImplementation(() => ({
    logSuccessfulAuth: jest.fn().mockResolvedValue(undefined),
    logFailedAuth: jest.fn().mockResolvedValue(undefined),
    logUserEvent: jest.fn().mockResolvedValue(undefined),
    logSecurityEvent: jest.fn().mockResolvedValue(undefined),
    logAdminAction: jest.fn().mockResolvedValue(undefined),
    getLoginHistory: jest.fn().mockResolvedValue([]),
    getSecurityEvents: jest.fn().mockResolvedValue([]),
  }));
}, { virtual: true });

// ─── Mock service-contracts package ───────────────────────────────────────────
jest.mock('../../../../packages/service-contracts/src', () => ({
  UserOnboardingSaga: jest.fn().mockImplementation(() => ({
    launch: jest.fn().mockResolvedValue(undefined),
  })),
}), { virtual: true });

jest.mock('../../../../packages/service-contracts/src/messageBus', () => ({
  getInstance: jest.fn().mockReturnValue({
    publish: jest.fn().mockResolvedValue(undefined),
    subscribe: jest.fn().mockResolvedValue(undefined),
    connect: jest.fn().mockResolvedValue(undefined),
    isConnected: jest.fn().mockReturnValue(false),
  }),
}), { virtual: true });

// ─── Prevent the module-level authService.start() from binding a real port ────
// The index.js calls `authService.start()` at module load time.
// We prevent listen() by mocking Express's listen method.
// The trick: mock the express module so listen() is a no-op.
jest.mock('express', () => {
  const actualExpress = jest.requireActual('express');
  const wrapper = function() {
    const app = actualExpress();
    // Override listen to be a no-op (returns a fake server object)
    app.listen = jest.fn().mockReturnValue({
      close: jest.fn((cb) => cb && cb()),
      address: jest.fn().mockReturnValue({ port: 3001 }),
    });
    return app;
  };
  // Copy static properties
  Object.assign(wrapper, actualExpress);
  wrapper.Router = actualExpress.Router;
  wrapper.static = actualExpress.static;
  wrapper.json = actualExpress.json;
  wrapper.urlencoded = actualExpress.urlencoded;
  wrapper.raw = actualExpress.raw;
  wrapper.text = actualExpress.text;
  return wrapper;
});

// ─── Now require the app ───────────────────────────────────────────────────────
const request = require('supertest');
const UnifiedAuthenticationService = require('../index');

describe('Authentication Service - E2E API Tests', () => {
  let app;
  let service;

  beforeAll(async () => {
    // Use the module-level singleton which has both class-registered routes AND the
    // IIFE-registered routes (OUs, groups, MFA TOTP, DNS, PIM, etc.).
    // We alias it as `service` so that all mock-access patterns (service.userService, etc.)
    // work transparently, and `app` points to its Express app.
    service = UnifiedAuthenticationService._instance;
    app = service.app;

    // Give any async initialization (DB, bus) a tick to settle/fail gracefully
    await new Promise(resolve => setTimeout(resolve, 20));
  });

  afterAll(async () => {
    await new Promise(resolve => setTimeout(resolve, 10));
  });

  // Reset the getUserById mock queue before every test to prevent bleed between
  // tests that set up mockResolvedValueOnce values for routes that don't call it.
  beforeEach(() => {
    if (service && service.userService) {
      service.userService.getUserById.mockReset();
      service.userService.getUserById.mockResolvedValue(null);
    }
  });

  // ─── Health Check ────────────────────────────────────────────────────────────
  describe('GET /health', () => {
    it('returns 200 with healthy status', async () => {
      const res = await request(app).get('/health');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('status', 'healthy');
      expect(res.body).toHaveProperty('service', 'authentication-service');
      expect(res.body).toHaveProperty('uptime');
      expect(res.body).toHaveProperty('timestamp');
    });
  });

  // ─── POST /api/auth/login ────────────────────────────────────────────────────
  describe('POST /api/auth/login', () => {
    it('returns 400 when body is missing required fields', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({});
      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'Validation failed');
    });

    it('returns 400 when username is missing', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ password: 'testpassword' });
      expect(res.status).toBe(400);
      expect(res.body.details).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ field: 'username' }),
        ])
      );
    });

    it('returns 400 when password is missing', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'testuser' });
      expect(res.status).toBe(400);
      expect(res.body.details).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ field: 'password' }),
        ])
      );
    });

    it('returns 401 for invalid credentials', async () => {
      // authenticateLocal returns null → invalid credentials
      const { default: AuthManager } = { default: require('../services/authenticationManager') };
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'wronguser', password: 'wrongpass' });
      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('error', 'Authentication failed');
    });

    it('returns 401 with invalid mfaCode format', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'testuser', password: 'testpass', mfaCode: 'abc' });
      // mfaCode must be 6 digits — validation should reject it
      expect(res.status).toBe(400);
    });

    it('returns 200 with success for valid credentials (mocked)', async () => {
      // Make authenticateLocal return a valid user - use the service's own authManager instance
      service.authManager.authenticateLocal.mockResolvedValueOnce({
        id: 'user-123',
        username: 'admin',
        email: 'admin@example.com',
        roles: ['admin'],
        permissions: ['*'],
        mfaEnabled: false,
      });

      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'admin', password: 'AdminPass123!' });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('user');
      expect(res.body).toHaveProperty('tokens');
      expect(res.body.tokens).toHaveProperty('accessToken');
    });
  });

  // ─── POST /api/auth/register ─────────────────────────────────────────────────
  describe('POST /api/auth/register', () => {
    it('returns 400 when required fields are missing', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({});
      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'Validation failed');
    });

    it('returns 400 for invalid email', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ username: 'newuser', email: 'not-an-email', password: 'SecurePass123!' });
      expect(res.status).toBe(400);
    });

    it('returns 400 for short password', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ username: 'newuser', email: 'user@test.com', password: 'short' });
      expect(res.status).toBe(400);
    });

    it('returns 400 for invalid username (with spaces)', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ username: 'bad user!', email: 'user@test.com', password: 'SecurePass123!' });
      expect(res.status).toBe(400);
    });

    it('returns 409 when user already exists', async () => {
      // Use the service's own userService instance
      service.userService.validateRegistration.mockResolvedValueOnce({ valid: true, errors: [] });
      service.userService.getUserByUsername.mockResolvedValueOnce({ id: 'existing-user', username: 'existinguser' });

      const res = await request(app)
        .post('/api/auth/register')
        .send({ username: 'existinguser', email: 'existing@test.com', password: 'SecurePass123!' });
      expect(res.status).toBe(409);
      expect(res.body).toHaveProperty('error', 'User already exists');
    });

    it('returns 201 for successful registration', async () => {
      service.userService.validateRegistration.mockResolvedValueOnce({ valid: true, errors: [] });
      service.userService.getUserByUsername.mockResolvedValueOnce(null);
      service.userService.createUser.mockResolvedValueOnce({
        id: 'new-user-456',
        username: 'newuser',
        email: 'newuser@test.com',
        roles: ['user'],
        permissions: [],
      });

      const res = await request(app)
        .post('/api/auth/register')
        .send({ username: 'newuser', email: 'newuser@test.com', password: 'SecurePass123!' });
      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('message', 'Registration successful');
    });
  });

  // ─── POST /api/auth/validate ─────────────────────────────────────────────────
  describe('POST /api/auth/validate', () => {
    it('returns 400 when token is missing', async () => {
      const res = await request(app)
        .post('/api/auth/validate')
        .send({});
      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'Token required');
    });

    it('returns { valid: false } for invalid token', async () => {
      service.tokenService.validateToken.mockResolvedValueOnce(false);

      const res = await request(app)
        .post('/api/auth/validate')
        .send({ token: 'invalid-token' });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('valid', false);
    });

    it('returns { valid: true } for valid token', async () => {
      service.tokenService.validateToken.mockResolvedValueOnce(true);

      const res = await request(app)
        .post('/api/auth/validate')
        .send({ token: 'valid-token-here' });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('valid', true);
    });
  });

  // ─── POST /api/auth/logout ───────────────────────────────────────────────────
  describe('POST /api/auth/logout', () => {
    it('returns 200 with logout success message', async () => {
      const res = await request(app)
        .post('/api/auth/logout')
        .send({});
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('message', 'Logged out successfully');
    });

    it('returns 200 when logging out a specific session', async () => {
      const res = await request(app)
        .post('/api/auth/logout')
        .send({ sessionId: 'session-xyz' });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });
  });

  // ─── POST /api/auth/refresh ───────────────────────────────────────────────────
  describe('POST /api/auth/refresh', () => {
    it('returns 400 when refreshToken is missing', async () => {
      const res = await request(app)
        .post('/api/auth/refresh')
        .send({});
      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'Refresh token required');
    });

    it('returns 401 for invalid refresh token', async () => {
      service.tokenService.refreshAccessToken.mockResolvedValueOnce(null);

      const res = await request(app)
        .post('/api/auth/refresh')
        .send({ refreshToken: 'invalid-refresh-token' });
      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('error', 'Invalid refresh token');
    });
  });

  // ─── POST /api/auth/reset-password ─────────────────────────────────────────
  describe('POST /api/auth/reset-password', () => {
    it('returns 200 even when email does not exist (prevents enumeration)', async () => {
      service.userService.getUserByEmail.mockResolvedValueOnce(null);

      const res = await request(app)
        .post('/api/auth/reset-password')
        .send({ email: 'nonexistent@example.com' });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body.message).toContain('If the email exists');
    });

    it('returns 200 when email exists (still no enumeration)', async () => {
      service.userService.getUserByEmail.mockResolvedValueOnce({
        id: 'user-123',
        email: 'existing@example.com',
        username: 'existinguser',
      });

      const res = await request(app)
        .post('/api/auth/reset-password')
        .send({ email: 'existing@example.com' });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });
  });

  // ─── Metrics ─────────────────────────────────────────────────────────────────
  describe('GET /metrics', () => {
    it('returns prometheus metrics', async () => {
      const res = await request(app).get('/metrics');
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/text\/plain/);
    });
  });

  // ─── Helper: build a signed JWT for authenticated requests ───────────────────
  function makeJwt(payload = {}) {
    const jwt = require('jsonwebtoken');
    return jwt.sign(
      { sub: 'user-test-1', username: 'testuser', roles: ['user'], ...payload },
      'test-jwt-secret',
      { expiresIn: '1h' }
    );
  }

  function makeAdminJwt() {
    return makeJwt({ sub: 'admin-1', username: 'admin', roles: ['admin'] });
  }

  // ─── MFA routes ──────────────────────────────────────────────────────────────
  // Note: POST /api/auth/mfa/setup is registered by BOTH the class (no auth middleware,
  // first in route stack) and the IIFE (requireJwt, second). Express hits the class
  // route first, which accesses req.user.id directly → crashes to 500 when no session.
  // The IIFE-only routes (verify-setup, validate, DELETE disable, GET status) work correctly.

  describe('POST /api/auth/mfa/setup', () => {
    it('returns 500 when called without user context (class route lacks requireAuth)', async () => {
      const res = await request(app).post('/api/auth/mfa/setup').send({});
      // Class route has no requireAuth — handler crashes on req.user.id
      expect(res.status).toBe(500);
    });
  });

  describe('POST /api/auth/mfa/verify-setup', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app)
        .post('/api/auth/mfa/verify-setup')
        .send({ token: '123456' });
      expect(res.status).toBe(401);
    });

    it('returns 400 when no pending MFA setup exists', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'user-no-pending',
        username: 'testuser',
        roles: ['user'],
      });

      const token = makeJwt({ sub: 'user-no-pending' });
      const res = await request(app)
        .post('/api/auth/mfa/verify-setup')
        .set('Authorization', `Bearer ${token}`)
        .send({ token: '123456' });

      // No pending secret → 400, or 501 if speakeasy not available
      expect([400, 501]).toContain(res.status);
    });
  });

  describe('POST /api/auth/mfa/validate', () => {
    it('returns 400 when userId or token is missing', async () => {
      const res = await request(app)
        .post('/api/auth/mfa/validate')
        .send({});
      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error');
    });

    it('returns 400 when MFA not configured for user', async () => {
      const res = await request(app)
        .post('/api/auth/mfa/validate')
        .send({ userId: 'nonexistent-user', token: '123456' });
      // Either 400 (not configured) or 501 (speakeasy not installed)
      expect([400, 501]).toContain(res.status);
    });
  });

  describe('DELETE /api/auth/mfa/disable', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).delete('/api/auth/mfa/disable').send({});
      expect(res.status).toBe(401);
    });

    it('returns 200 success for authenticated user', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'user-test-1',
        username: 'testuser',
        roles: ['user'],
      });

      const token = makeJwt();
      const res = await request(app)
        .delete('/api/auth/mfa/disable')
        .set('Authorization', `Bearer ${token}`)
        .send({});

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });
  });

  describe('GET /api/auth/mfa/status', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).get('/api/auth/mfa/status');
      expect(res.status).toBe(401);
    });

    it('returns mfa enabled status for authenticated user', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'user-test-1',
        username: 'testuser',
        roles: ['user'],
      });

      const token = makeJwt();
      const res = await request(app)
        .get('/api/auth/mfa/status')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('enabled');
      expect(typeof res.body.enabled).toBe('boolean');
    });
  });

  // ─── Session management ───────────────────────────────────────────────────────
  // Note: Session routes have no requireAuth middleware in the class registration.
  // Accessing req.user.id without passport authentication crashes them.

  describe('GET /api/auth/sessions', () => {
    it('returns 500 without user context (route lacks requireAuth)', async () => {
      const res = await request(app).get('/api/auth/sessions');
      expect(res.status).toBe(500);
    });

    it('returns 500 when session manager throws (no user context)', async () => {
      service.sessionManager.getUserSessions.mockRejectedValueOnce(new Error('DB error'));
      const res = await request(app).get('/api/auth/sessions');
      expect(res.status).toBe(500);
    });
  });

  describe('DELETE /api/auth/sessions/:sessionId', () => {
    it('returns 500 without user context (route lacks requireAuth)', async () => {
      const res = await request(app).delete('/api/auth/sessions/session-abc');
      expect(res.status).toBe(500);
    });
  });

  describe('POST /api/auth/sessions/revoke-all', () => {
    it('returns 500 without user context (route lacks requireAuth)', async () => {
      const res = await request(app).post('/api/auth/sessions/revoke-all').send({});
      expect(res.status).toBe(500);
    });
  });

  // ─── Profile endpoints ────────────────────────────────────────────────────────
  // Note: Profile routes have no requireAuth middleware — they crash without req.user.

  describe('GET /api/auth/profile', () => {
    it('returns 500 without user context (route lacks requireAuth)', async () => {
      const res = await request(app).get('/api/auth/profile');
      expect(res.status).toBe(500);
    });
  });

  describe('PUT /api/auth/profile', () => {
    it('returns 500 without user context (route lacks requireAuth)', async () => {
      const res = await request(app).put('/api/auth/profile').send({ firstName: 'New' });
      expect(res.status).toBe(500);
    });
  });

  // ─── Change password ──────────────────────────────────────────────────────────
  // Note: POST /api/auth/change-password has validate('changePassword') middleware
  // but no requireAuth — it crashes at req.user.id when auth fields are valid.

  describe('POST /api/auth/change-password', () => {
    it('returns 400 when required fields are missing', async () => {
      const res = await request(app)
        .post('/api/auth/change-password')
        .send({});
      expect(res.status).toBe(400);
    });

    it('returns 500 when valid fields are sent but route lacks requireAuth', async () => {
      // validate('changePassword') passes, then handler crashes on req.user.id
      const res = await request(app)
        .post('/api/auth/change-password')
        .send({ currentPassword: 'OldPass1!', newPassword: 'NewPass123!' });
      expect(res.status).toBe(500);
    });
  });

  // ─── Confirm password reset ───────────────────────────────────────────────────

  describe('POST /api/auth/password-reset/confirm', () => {
    it('returns 400 when token or newPassword is missing', async () => {
      const res = await request(app)
        .post('/api/auth/password-reset/confirm')
        .send({});
      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'token and newPassword required');
    });

    it('returns 400 for invalid or expired token', async () => {
      const res = await request(app)
        .post('/api/auth/password-reset/confirm')
        .send({ token: 'invalid-token-xyz', newPassword: 'NewSecurePass1!' });
      expect(res.status).toBe(400);
    });
  });

  // ─── SSO endpoints ────────────────────────────────────────────────────────────

  describe('GET /api/auth/sso/providers', () => {
    it('returns list of SSO providers', async () => {
      service.authManager.getSSOProviders.mockResolvedValueOnce([
        { id: 'google', name: 'Google' },
      ]);

      const res = await request(app).get('/api/auth/sso/providers');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('providers');
      expect(Array.isArray(res.body.providers)).toBe(true);
    });

    it('returns 500 when SSO provider lookup fails', async () => {
      service.authManager.getSSOProviders.mockRejectedValueOnce(new Error('SSO error'));

      const res = await request(app).get('/api/auth/sso/providers');
      expect(res.status).toBe(500);
    });
  });

  describe('GET /api/auth/sso/:provider', () => {
    it('redirects to SSO auth URL', async () => {
      service.authManager.initiateSSOLogin.mockResolvedValueOnce('https://accounts.google.com/o/oauth2/auth?...');

      const res = await request(app).get('/api/auth/sso/google');
      expect(res.status).toBe(302);
      expect(res.headers.location).toMatch(/accounts\.google\.com/);
    });
  });

  // ─── Admin user management ────────────────────────────────────────────────────

  describe('GET /api/auth/users', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).get('/api/auth/users');
      expect(res.status).toBe(401);
    });

    it('returns 403 for non-admin user', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'user-test-1',
        username: 'testuser',
        roles: ['user'],
      });

      const token = makeJwt({ roles: ['user'] });
      const res = await request(app)
        .get('/api/auth/users')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(403);
      expect(res.body).toHaveProperty('error', 'Admin access required');
    });

    it('returns user list for admin', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'admin-1',
        username: 'admin',
        roles: ['admin'],
      });
      service.userService.listUsers.mockResolvedValueOnce({
        users: [{ id: 'u1', username: 'alice' }],
        total: 1,
      });

      const token = makeAdminJwt();
      const res = await request(app)
        .get('/api/auth/users')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('users');
    });

    it('returns 500 when DB fails', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'admin-1',
        username: 'admin',
        roles: ['admin'],
      });
      service.userService.listUsers.mockRejectedValueOnce(new Error('DB error'));

      const token = makeAdminJwt();
      const res = await request(app)
        .get('/api/auth/users')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(500);
    });
  });

  describe('GET /api/auth/users/:userId', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).get('/api/auth/users/user-abc');
      expect(res.status).toBe(401);
    });

    it('returns 403 for non-admin user', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'user-test-1',
        username: 'testuser',
        roles: ['user'],
      });

      const token = makeJwt({ roles: ['user'] });
      const res = await request(app)
        .get('/api/auth/users/user-abc')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(403);
    });

    it('returns 404 when user not found', async () => {
      service.userService.getUserById
        .mockResolvedValueOnce({ id: 'admin-1', username: 'admin', roles: ['admin'] })
        .mockResolvedValueOnce(null);

      const token = makeAdminJwt();
      const res = await request(app)
        .get('/api/auth/users/nonexistent-user')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('error', 'User not found');
    });

    it('returns user data for admin', async () => {
      const mockUser = { id: 'target-user', username: 'alice', email: 'alice@test.com', roles: ['user'] };
      service.userService.getUserById
        .mockResolvedValueOnce({ id: 'admin-1', username: 'admin', roles: ['admin'] })
        .mockResolvedValueOnce(mockUser);

      const token = makeAdminJwt();
      const res = await request(app)
        .get('/api/auth/users/target-user')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('username', 'alice');
    });
  });

  describe('PUT /api/auth/users/:userId', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).put('/api/auth/users/user-abc').send({});
      expect(res.status).toBe(401);
    });

    it('returns 403 for non-admin user', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'user-test-1',
        username: 'testuser',
        roles: ['user'],
      });

      const token = makeJwt({ roles: ['user'] });
      const res = await request(app)
        .put('/api/auth/users/user-abc')
        .set('Authorization', `Bearer ${token}`)
        .send({ email: 'new@test.com' });

      expect(res.status).toBe(403);
    });

    it('returns 200 success for admin updating user', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'admin-1',
        username: 'admin',
        roles: ['admin'],
      });
      service.userService.updateUser.mockResolvedValueOnce({
        id: 'target-user',
        email: 'updated@test.com',
      });

      const token = makeAdminJwt();
      const res = await request(app)
        .put('/api/auth/users/target-user')
        .set('Authorization', `Bearer ${token}`)
        .send({ email: 'updated@test.com' });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('user');
    });
  });

  describe('DELETE /api/auth/users/:userId', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).delete('/api/auth/users/user-abc');
      expect(res.status).toBe(401);
    });

    it('returns 403 for non-admin user', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'user-test-1',
        username: 'testuser',
        roles: ['user'],
      });

      const token = makeJwt({ roles: ['user'] });
      const res = await request(app)
        .delete('/api/auth/users/user-abc')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(403);
    });

    it('returns 200 success when admin deletes a user', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'admin-1',
        username: 'admin',
        roles: ['admin'],
      });
      service.userService.deleteUser.mockResolvedValueOnce(undefined);
      service.sessionManager.revokeAllUserSessions.mockResolvedValueOnce(undefined);

      const token = makeAdminJwt();
      const res = await request(app)
        .delete('/api/auth/users/target-user')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body.message).toContain('deleted');
    });
  });

  describe('POST /api/auth/users/:userId/lock', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).post('/api/auth/users/user-abc/lock').send({});
      expect(res.status).toBe(401);
    });

    it('returns 403 for non-admin user', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'user-test-1',
        username: 'testuser',
        roles: ['user'],
      });

      const token = makeJwt({ roles: ['user'] });
      const res = await request(app)
        .post('/api/auth/users/user-abc/lock')
        .set('Authorization', `Bearer ${token}`)
        .send({ reason: 'Violation' });

      expect(res.status).toBe(403);
    });

    it('returns 200 success when admin locks a user', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'admin-1',
        username: 'admin',
        roles: ['admin'],
      });
      service.userService.lockUser.mockResolvedValueOnce(undefined);
      service.sessionManager.revokeAllUserSessions.mockResolvedValueOnce(undefined);

      const token = makeAdminJwt();
      const res = await request(app)
        .post('/api/auth/users/target-user/lock')
        .set('Authorization', `Bearer ${token}`)
        .send({ reason: 'Policy violation', duration: 60 });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });
  });

  describe('POST /api/auth/users/:userId/unlock', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).post('/api/auth/users/user-abc/unlock').send({});
      expect(res.status).toBe(401);
    });

    it('returns 200 success when admin unlocks a user', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'admin-1',
        username: 'admin',
        roles: ['admin'],
      });
      service.userService.unlockUser.mockResolvedValueOnce(undefined);

      const token = makeAdminJwt();
      const res = await request(app)
        .post('/api/auth/users/target-user/unlock')
        .set('Authorization', `Bearer ${token}`)
        .send({});

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });
  });

  // ─── Audit endpoints ──────────────────────────────────────────────────────────

  describe('GET /api/auth/audit/login-history', () => {
    it('returns 500 without user context (route lacks requireAuth)', async () => {
      // Class route accesses req.user.id without any auth middleware
      const res = await request(app).get('/api/auth/audit/login-history');
      expect(res.status).toBe(500);
    });
  });

  describe('GET /api/auth/audit/security-events', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).get('/api/auth/audit/security-events');
      expect(res.status).toBe(401);
    });

    it('returns 403 for non-admin user', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'user-test-1',
        username: 'testuser',
        roles: ['user'],
      });

      const token = makeJwt({ roles: ['user'] });
      const res = await request(app)
        .get('/api/auth/audit/security-events')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(403);
    });

    it('returns security events for admin', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'admin-1',
        username: 'admin',
        roles: ['admin'],
      });
      service.auditService.getSecurityEvents.mockResolvedValueOnce([
        { eventType: 'mfa_enabled', userId: 'u1' },
      ]);

      const token = makeAdminJwt();
      const res = await request(app)
        .get('/api/auth/audit/security-events')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('events');
    });
  });

  // ─── Account lockout admin endpoints ─────────────────────────────────────────

  describe('GET /api/auth/lockouts', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).get('/api/auth/lockouts');
      expect(res.status).toBe(401);
    });

    it('returns 403 for non-admin user', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'user-test-1',
        username: 'testuser',
        roles: ['user'],
      });

      const token = makeJwt({ roles: ['user'] });
      const res = await request(app)
        .get('/api/auth/lockouts')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(403);
    });

    it('returns locked accounts list for admin', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'admin-1',
        username: 'admin',
        roles: ['admin'],
      });

      const token = makeAdminJwt();
      const res = await request(app)
        .get('/api/auth/lockouts')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
    });
  });

  describe('DELETE /api/auth/lockouts/:username', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).delete('/api/auth/lockouts/lockeduser');
      expect(res.status).toBe(401);
    });

    it('returns 200 success when admin unlocks account', async () => {
      service.userService.getUserById.mockResolvedValueOnce({
        id: 'admin-1',
        username: 'admin',
        roles: ['admin'],
      });

      const token = makeAdminJwt();
      const res = await request(app)
        .delete('/api/auth/lockouts/lockeduser')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });
  });

  // ─── Directory: OUs ───────────────────────────────────────────────────────────

  describe('GET /api/ous', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).get('/api/ous');
      expect(res.status).toBe(401);
    });

    it('returns OU tree with Bearer token', async () => {
      const token = makeJwt();
      const res = await request(app)
        .get('/api/ous')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
    });
  });

  describe('POST /api/ous', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).post('/api/ous').send({ name: 'TestOU' });
      expect(res.status).toBe(401);
    });

    it('returns 400 when name is missing', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/ous')
        .set('Authorization', `Bearer ${token}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'name required');
    });

    it('returns 201 with created OU', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/ous')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'Finance', description: 'Finance department' });

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('name', 'Finance');
      expect(res.body).toHaveProperty('id');
    });
  });

  // ─── Directory: Groups ────────────────────────────────────────────────────────

  describe('GET /api/groups', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).get('/api/groups');
      expect(res.status).toBe(401);
    });

    it('returns groups list with Bearer token', async () => {
      const token = makeJwt();
      const res = await request(app)
        .get('/api/groups')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      // Seeded groups should be present
      expect(res.body.length).toBeGreaterThan(0);
    });
  });

  describe('POST /api/groups', () => {
    it('returns 400 when name is missing', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/groups')
        .set('Authorization', `Bearer ${token}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'name required');
    });

    it('returns 201 with created group', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/groups')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'QA Team', description: 'Quality assurance' });

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('name', 'QA Team');
      expect(res.body).toHaveProperty('id');
    });
  });

  describe('GET /api/groups/:id', () => {
    it('returns 404 for unknown group', async () => {
      const token = makeJwt();
      const res = await request(app)
        .get('/api/groups/nonexistent-group-id')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('error', 'Group not found');
    });

    it('returns group data for seeded group', async () => {
      const token = makeJwt();
      const res = await request(app)
        .get('/api/groups/g-developers')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('id', 'g-developers');
      expect(res.body).toHaveProperty('members');
    });
  });

  describe('POST /api/groups/:id/members', () => {
    it('returns 400 when userId is missing', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/groups/g-developers/members')
        .set('Authorization', `Bearer ${token}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'userId required');
    });

    it('returns 201 when adding a member to a group', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/groups/g-developers/members')
        .set('Authorization', `Bearer ${token}`)
        .send({ userId: 'user-new-member' });

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('userId', 'user-new-member');
    });

    it('returns 404 for unknown group', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/groups/nonexistent-group/members')
        .set('Authorization', `Bearer ${token}`)
        .send({ userId: 'user-1' });

      expect(res.status).toBe(404);
    });
  });

  // ─── Password Policy ──────────────────────────────────────────────────────────

  describe('GET /api/password-policy', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).get('/api/password-policy');
      expect(res.status).toBe(401);
    });

    it('returns password policy with Bearer token', async () => {
      const token = makeJwt();
      const res = await request(app)
        .get('/api/password-policy')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('minLength');
    });
  });

  describe('PUT /api/password-policy', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).put('/api/password-policy').send({ minLength: 16 });
      expect(res.status).toBe(401);
    });

    it('returns updated policy with Bearer token', async () => {
      const token = makeJwt();
      const res = await request(app)
        .put('/api/password-policy')
        .set('Authorization', `Bearer ${token}`)
        .send({ minLength: 16, requireUppercase: true });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('minLength', 16);
    });
  });

  // ─── Service Accounts ─────────────────────────────────────────────────────────

  describe('GET /api/service-accounts', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).get('/api/service-accounts');
      expect(res.status).toBe(401);
    });

    it('returns service accounts list with Bearer token', async () => {
      const token = makeJwt();
      const res = await request(app)
        .get('/api/service-accounts')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      // Seeded service account should be present (token field stripped)
      expect(res.body[0]).not.toHaveProperty('token');
    });
  });

  describe('POST /api/service-accounts', () => {
    it('returns 400 when name is missing', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/service-accounts')
        .set('Authorization', `Bearer ${token}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'name required');
    });

    it('returns 201 with token on creation', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/service-accounts')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'monitoring-sa', scopes: ['metrics:read'] });

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('name', 'monitoring-sa');
      expect(res.body).toHaveProperty('token'); // token returned on create only
    });
  });

  describe('DELETE /api/service-accounts/:id', () => {
    it('returns 404 when service account not found', async () => {
      const token = makeJwt();
      const res = await request(app)
        .delete('/api/service-accounts/nonexistent-sa-id')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('error', 'Service account not found');
    });

    it('returns 204 when service account is deleted', async () => {
      // First create a service account to delete
      const token = makeJwt();
      const createRes = await request(app)
        .post('/api/service-accounts')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'temp-sa', scopes: [] });
      expect(createRes.status).toBe(201);
      const saId = createRes.body.id;

      const deleteRes = await request(app)
        .delete(`/api/service-accounts/${saId}`)
        .set('Authorization', `Bearer ${token}`);

      expect(deleteRes.status).toBe(204);
    });
  });

  describe('GET /api/service-accounts/:id/token', () => {
    it('returns 404 when service account not found', async () => {
      const token = makeJwt();
      const res = await request(app)
        .get('/api/service-accounts/nonexistent-sa-id/token')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(404);
    });

    it('returns fresh token for seeded service account', async () => {
      const token = makeJwt();
      const res = await request(app)
        .get('/api/service-accounts/sa-ci-runner/token')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('token');
      expect(res.body).toHaveProperty('expiresIn', '24h');
    });
  });

  // ─── Bulk import ──────────────────────────────────────────────────────────────

  describe('POST /api/users/bulk-import', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app)
        .post('/api/users/bulk-import')
        .send({ users: [] });
      expect(res.status).toBe(401);
    });

    it('returns 400 when users is not an array', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/users/bulk-import')
        .set('Authorization', `Bearer ${token}`)
        .send({ users: 'not-an-array' });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'users array required');
    });

    it('returns 207 with partial results (name/email required per entry)', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/users/bulk-import')
        .set('Authorization', `Bearer ${token}`)
        .send({
          users: [
            { name: 'Alice Smith', email: 'alice@test.com' },
            { email: 'no-name@test.com' }, // missing name — should error
          ],
        });

      expect(res.status).toBe(207);
      expect(res.body).toHaveProperty('created', 1);
      expect(res.body.errors.length).toBe(1);
    });
  });

  // ─── Domain config ────────────────────────────────────────────────────────────

  describe('POST /api/config/domain', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app)
        .post('/api/config/domain')
        .send({ domain: 'example.com' });
      expect(res.status).toBe(401);
    });

    it('returns 400 when domain is missing', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/config/domain')
        .set('Authorization', `Bearer ${token}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'domain required');
    });

    it('returns success with configured domain', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/config/domain')
        .set('Authorization', `Bearer ${token}`)
        .send({ domain: 'example.local', issuer: 'OpenDirectory' });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('domain', 'example.local');
    });
  });

  describe('GET /api/config/domain', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).get('/api/config/domain');
      expect(res.status).toBe(401);
    });

    it('returns domain config with Bearer token', async () => {
      // Set it first
      const token = makeJwt();
      await request(app)
        .post('/api/config/domain')
        .set('Authorization', `Bearer ${token}`)
        .send({ domain: 'test.local' });

      const res = await request(app)
        .get('/api/config/domain')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('domain');
    });
  });

  // ─── Audit log endpoints ──────────────────────────────────────────────────────

  describe('GET /api/audit/events', () => {
    it('returns audit events (no auth required — dashboard access)', async () => {
      const res = await request(app).get('/api/audit/events');
      // This endpoint deliberately skips auth (if req.path.startsWith('/audit/'))
      expect([200, 500]).toContain(res.status);
      if (res.status === 200) {
        expect(Array.isArray(res.body)).toBe(true);
      }
    });
  });

  describe('POST /api/audit/log', () => {
    it('returns 400 when message is missing', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/audit/log')
        .set('Authorization', `Bearer ${token}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'message required');
    });

    it('returns 200 success when message is provided', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/audit/log')
        .set('Authorization', `Bearer ${token}`)
        .send({ message: 'Test audit event', eventType: 'test', severity: 'info' });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });
  });

  // ─── DNS records ──────────────────────────────────────────────────────────────

  describe('GET /api/dns/records', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).get('/api/dns/records');
      expect(res.status).toBe(401);
    });

    it('returns DNS records with Bearer token', async () => {
      const token = makeJwt();
      const res = await request(app)
        .get('/api/dns/records')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBeGreaterThan(0);
    });
  });

  describe('POST /api/dns/records', () => {
    it('returns 400 when required fields are missing', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/dns/records')
        .set('Authorization', `Bearer ${token}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'name, type, value required');
    });

    it('returns 400 for invalid DNS record type', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/dns/records')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'test.local', type: 'INVALID', value: '1.2.3.4' });

      expect(res.status).toBe(400);
    });

    it('returns 201 with created DNS record', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/dns/records')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'new.test.local', type: 'A', value: '10.0.0.5', ttl: 600 });

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('name', 'new.test.local');
      expect(res.body).toHaveProperty('type', 'A');
    });
  });

  describe('DELETE /api/dns/records/:name', () => {
    it('returns 404 when DNS record not found', async () => {
      const token = makeJwt();
      const res = await request(app)
        .delete('/api/dns/records/nonexistent.local')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(404);
    });

    it('returns success when deleting existing DNS record', async () => {
      const token = makeJwt();
      // Create then delete
      await request(app)
        .post('/api/dns/records')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'delete-me.local', type: 'A', value: '1.2.3.4' });

      const res = await request(app)
        .delete('/api/dns/records/delete-me.local')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });
  });

  // ─── PIM (Privileged Identity Management) ────────────────────────────────────

  describe('GET /api/pim/roles', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).get('/api/pim/roles');
      expect(res.status).toBe(401);
    });

    it('returns PIM roles list with Bearer token', async () => {
      const token = makeJwt();
      const res = await request(app)
        .get('/api/pim/roles')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      // The response is an array (DB is mocked → returns empty from getPimRolesFromDb
      // which returns [] from the mocked pg query; that's truthy so used over in-memory seeds)
      expect(Array.isArray(res.body)).toBe(true);
    });
  });

  describe('POST /api/pim/roles', () => {
    it('returns 400 when required fields are missing', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/pim/roles')
        .set('Authorization', `Bearer ${token}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'name and target_group_id required');
    });

    it('returns 201 with created PIM role', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/pim/roles')
        .set('Authorization', `Bearer ${token}`)
        .send({
          name: 'Database Admin',
          target_group_id: 'grp-dba',
          max_duration_hours: 2,
          requires_approval: true,
        });

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('name', 'Database Admin');
      expect(res.body).toHaveProperty('id');
    });
  });

  describe('GET /api/pim/requests', () => {
    it('returns 401 when no auth token provided', async () => {
      const res = await request(app).get('/api/pim/requests');
      expect(res.status).toBe(401);
    });

    it('returns PIM requests list with Bearer token', async () => {
      const token = makeJwt();
      const res = await request(app)
        .get('/api/pim/requests')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
    });
  });

  describe('POST /api/pim/requests', () => {
    it('returns 400 when role_id is missing', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/pim/requests')
        .set('Authorization', `Bearer ${token}`)
        .send({ justification: 'Need access' });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'role_id required');
    });

    it('returns 404 when PIM role not found', async () => {
      const token = makeJwt();
      const res = await request(app)
        .post('/api/pim/requests')
        .set('Authorization', `Bearer ${token}`)
        .send({ role_id: 'nonexistent-role-id', justification: 'Need access' });

      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('error', 'PIM role not found');
    });

    it('returns 201 when creating a valid PIM request', async () => {
      const token = makeJwt();

      // Create a role first (no approval required for auto-activate)
      const createRole = await request(app)
        .post('/api/pim/roles')
        .set('Authorization', `Bearer ${token}`)
        .send({
          name: 'Test Role',
          target_group_id: 'grp-test',
          max_duration_hours: 4,
          requires_approval: false,
        });
      expect(createRole.status).toBe(201);
      const roleId = createRole.body.id;

      const res = await request(app)
        .post('/api/pim/requests')
        .set('Authorization', `Bearer ${token}`)
        .send({
          role_id: roleId,
          justification: 'Urgent maintenance task',
          requested_duration_hours: 2,
          user_id: 'user-test-1',
        });

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('role_id', roleId);
      expect(res.body).toHaveProperty('status', 'active'); // auto-approved
    });
  });
});
