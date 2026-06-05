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
    // The module already called `new UnifiedAuthenticationService()` and `start()`.
    // We create a fresh instance for our tests. The IIFE routes are registered on the
    // module-level authService.app, not on our test instance, so we also need those routes.
    // Since both share the same mocked service constructors, we use a new instance.
    service = new UnifiedAuthenticationService();
    app = service.app;

    // Give any async initialization (DB, bus) a tick to settle/fail gracefully
    await new Promise(resolve => setTimeout(resolve, 20));
  });

  afterAll(async () => {
    await new Promise(resolve => setTimeout(resolve, 10));
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
});
