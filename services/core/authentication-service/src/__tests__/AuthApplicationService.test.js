'use strict';

// Mock jsonwebtoken to avoid needing real secrets
jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(() => 'mocked.jwt.token'),
  verify: jest.fn((token, secret) => {
    if (token === 'valid-token') return { userId: 'user-1', username: 'alice', roles: ['user'], exp: Math.floor(Date.now() / 1000) + 3600 };
    throw new Error('invalid token');
  }),
}));

const AuthApplicationService = require('../application/AuthApplicationService');
const UserAggregate = require('../domain/aggregates/UserAggregate');
const SessionAggregate = require('../domain/aggregates/SessionAggregate');

function makeUser(overrides = {}) {
  return new UserAggregate({
    id: 'user-1',
    username: 'alice',
    email: 'alice@example.com',
    passwordHash: 'somehash',
    roles: ['user'],
    mfaEnabled: false,
    locked: false,
    lockUntil: null,
    loginAttempts: 0,
    ...overrides,
  });
}

function makeMockBus(connected = true) {
  return {
    isConnected: jest.fn(() => connected),
    publish: jest.fn(),
  };
}

function makeService(overrides = {}) {
  const userRepo = {
    findByUsername: jest.fn(),
    findById: jest.fn(),
    save: jest.fn().mockResolvedValue(undefined),
  };
  const sessionRepo = {
    findByToken: jest.fn(),
    save: jest.fn().mockResolvedValue(undefined),
  };
  const bus = makeMockBus();
  const config = { jwtSecret: 'test-secret' };
  const logger = { warn: jest.fn(), info: jest.fn(), error: jest.fn() };
  const svc = new AuthApplicationService({
    userRepository: userRepo,
    sessionRepository: sessionRepo,
    messageBus: bus,
    config,
    logger,
    ...overrides,
  });
  return { svc, userRepo, sessionRepo, bus, logger };
}

describe('AuthApplicationService', () => {
  describe('login()', () => {
    it('throws 401 when user is not found', async () => {
      const { svc, userRepo } = makeService();
      userRepo.findByUsername.mockResolvedValue(null);

      await expect(svc.login({ username: 'ghost', password: 'pw', ip: '1.1.1.1' }))
        .rejects.toMatchObject({ message: 'Invalid credentials', status: 401 });
    });

    it('throws 403 when user account is locked', async () => {
      const { svc, userRepo } = makeService();
      const lockedUser = makeUser({ locked: true, lockUntil: new Date(Date.now() + 60000) });
      userRepo.findByUsername.mockResolvedValue(lockedUser);

      await expect(svc.login({ username: 'alice', password: 'pw', ip: '1.1.1.1' }))
        .rejects.toMatchObject({ status: 403 });
    });

    it('throws 401 and records failure when password is wrong (scrypt-shaped hash, no bcrypt prefix)', async () => {
      const { svc, userRepo } = makeService();
      // Not a $2*$-prefixed hash, so login() takes the scrypt/Password-VO
      // branch directly (see BUG FIX note below) rather than the bcrypt one.
      const user = makeUser({ passwordHash: 'invalid:hash:nomatchwillhappen' });
      userRepo.findByUsername.mockResolvedValue(user);

      await expect(svc.login({ username: 'alice', password: 'wrongpass', ip: '1.1.1.1' }))
        .rejects.toMatchObject({ status: 401 });
      expect(userRepo.save).toHaveBeenCalled();
    });

    // BUG FIX — this test used to pin buggy behavior. AuthApplicationService
    // used to do `const { Password } = require('../domain/value-objects/Password')`,
    // but that module does `module.exports = Password` (the class directly),
    // so the destructure always produced `undefined`. `Password.fromHash(...)`
    // therefore always THREW, which was silently swallowed by a catch-block
    // that fell back to bcryptjs — meaning the DDD Password value object was
    // NEVER actually exercised in production; every login secretly went
    // through the bcrypt fallback, and this test only passed because it
    // mocked bcryptjs.compare() to return true.
    //
    // The fix is not just "remove the destructure", though: Password VO's
    // verify() does NOT throw on a bcrypt-formatted hash — it just returns
    // false (there's no ':' to split cleanly) — so naively trying the VO
    // first for every hash would silently break login for the (overwhelming
    // majority) of real bcrypt-hashed users, with no fallback ever firing.
    // login() now branches explicitly on hash format ($2[aby]$ prefix =>
    // bcrypt, else => Password VO) instead of relying on a thrown exception.
    // These two tests demonstrate both branches now genuinely work.
    it('returns token and mfaRequired=false on successful login via the Password VO (scrypt hash)', async () => {
      const PasswordClass = require('../domain/value-objects/Password');
      const plaintext = 'TestPassword1';
      const pwObj = await PasswordClass.fromPlaintext(plaintext);
      expect(pwObj.hash).not.toMatch(/^\$2[aby]?\$/); // sanity: genuinely a scrypt hash, not bcrypt

      // If the buggy fallback-to-bcrypt path were still active, this would
      // be the *only* way password verification could succeed — so proving
      // it is NOT called demonstrates the real VO path is what verified the
      // password below.
      const bcryptjs = require('bcryptjs');
      const compareSpy = jest.spyOn(bcryptjs, 'compare');

      const { svc, userRepo } = makeService();
      const user = makeUser({ passwordHash: pwObj.hash });
      userRepo.findByUsername.mockResolvedValue(user);

      const result = await svc.login({ username: 'alice', password: plaintext, ip: '127.0.0.1', userAgent: 'test' });
      expect(result).toHaveProperty('token');
      expect(result).toHaveProperty('mfaRequired', false);
      expect(result.user.username).toBe('alice');
      expect(compareSpy).not.toHaveBeenCalled();

      compareSpy.mockRestore();
    });

    it('returns token on successful login via bcrypt (production UserService hash format)', async () => {
      // UserService.createUser()/changePassword() only ever produce bcrypt
      // ($2a$/$2b$/$2y$-prefixed) hashes — this is the hash format the
      // overwhelming majority of real users have, so it must keep working
      // after the Password-VO destructuring fix.
      const bcryptjs = require('bcryptjs');
      const plaintext = 'RealUserPassword1';
      const bcryptHash = await bcryptjs.hash(plaintext, 4);
      expect(bcryptHash).toMatch(/^\$2[aby]?\$/);

      const { svc, userRepo } = makeService();
      const user = makeUser({ passwordHash: bcryptHash });
      userRepo.findByUsername.mockResolvedValue(user);

      const result = await svc.login({ username: 'alice', password: plaintext, ip: '127.0.0.1', userAgent: 'test' });
      expect(result).toHaveProperty('token');
      expect(result.user.username).toBe('alice');
    });
  });

  describe('logout()', () => {
    it('revokes the session when token is found', async () => {
      const { svc, sessionRepo } = makeService();
      const futureDate = new Date(Date.now() + 3600000);
      const session = new SessionAggregate({
        sessionId: 'sess-1',
        userId: 'user-1',
        token: 'some-token',
        expiresAt: futureDate,
      });
      sessionRepo.findByToken.mockResolvedValue(session);

      await svc.logout('some-token');
      expect(sessionRepo.save).toHaveBeenCalledWith(expect.objectContaining({ _revokedAt: expect.any(Date) }));
    });

    it('does nothing when session is not found', async () => {
      const { svc, sessionRepo } = makeService();
      sessionRepo.findByToken.mockResolvedValue(null);
      await expect(svc.logout('nonexistent')).resolves.toBeUndefined();
    });

    it('does nothing when no session repo is provided', async () => {
      const { svc } = makeService();
      // Override the service without session repo
      svc._sessionRepo = null;
      await expect(svc.logout('token')).resolves.toBeUndefined();
    });
  });

  describe('validateToken()', () => {
    it('returns null for an invalid token', async () => {
      const { svc } = makeService();
      const result = await svc.validateToken('bad-token');
      expect(result).toBeNull();
    });

    it('returns null when user is not found', async () => {
      const { svc, userRepo } = makeService();
      userRepo.findById.mockResolvedValue(null);
      const result = await svc.validateToken('valid-token');
      expect(result).toBeNull();
    });

    it('returns null when user is locked', async () => {
      const { svc, userRepo } = makeService();
      const user = makeUser({ locked: true, lockUntil: new Date(Date.now() + 60000) });
      userRepo.findById.mockResolvedValue(user);
      const result = await svc.validateToken('valid-token');
      expect(result).toBeNull();
    });

    it('returns valid payload for a good token and active user', async () => {
      const { svc, userRepo } = makeService();
      const user = makeUser();
      userRepo.findById.mockResolvedValue(user);
      const result = await svc.validateToken('valid-token');
      expect(result).toMatchObject({ valid: true, userId: 'user-1' });
    });
  });

  describe('_publishDomainEvents()', () => {
    it('publishes events when bus is connected', async () => {
      const { svc, bus } = makeService();
      const user = UserAggregate.create({ id: 'u1', username: 'u', email: 'u@x.com', passwordHash: 'h' });
      await svc._publishDomainEvents(user);
      expect(bus.publish).toHaveBeenCalled();
    });

    it('does not publish when bus is not connected', async () => {
      const bus = makeMockBus(false);
      const { svc } = makeService();
      svc._bus = bus;
      const user = UserAggregate.create({ id: 'u1', username: 'u', email: 'u@x.com', passwordHash: 'h' });
      await svc._publishDomainEvents(user);
      expect(bus.publish).not.toHaveBeenCalled();
    });
  });
});
