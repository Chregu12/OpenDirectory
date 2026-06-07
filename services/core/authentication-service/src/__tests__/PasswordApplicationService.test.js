'use strict';

const PasswordApplicationService = require('../application/PasswordApplicationService');
const { AuthEvents } = require('../domain/events/AuthEvents');
const UserAggregate = require('../domain/aggregates/UserAggregate');

function makeUser(overrides = {}) {
  return new UserAggregate({
    id: 'user-1',
    username: 'alice',
    email: 'alice@example.com',
    passwordHash: 'salt:hash',
    roles: ['user'],
    ...overrides,
  });
}

function makeCache(storedValue = null) {
  const store = {};
  if (storedValue) store['pwd_reset:valid-token'] = JSON.stringify(storedValue);
  return {
    get: jest.fn(key => Promise.resolve(store[key] || null)),
    set: jest.fn((key, val) => { store[key] = val; return Promise.resolve('OK'); }),
    del: jest.fn(key => { delete store[key]; return Promise.resolve(1); }),
  };
}

function makeService({ userRepo, cache, bus } = {}) {
  const defaultUserRepo = {
    findByEmail: jest.fn(),
    findById: jest.fn(),
    save: jest.fn().mockResolvedValue(undefined),
  };
  const defaultBus = {
    isConnected: jest.fn(() => true),
    publish: jest.fn(),
  };
  return new PasswordApplicationService({
    userRepository: userRepo || defaultUserRepo,
    cache: cache !== undefined ? cache : makeCache(),
    messageBus: bus || defaultBus,
    logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn() },
  });
}

describe('PasswordApplicationService', () => {
  describe('requestReset()', () => {
    it('returns null silently when user is not found', async () => {
      const userRepo = { findByEmail: jest.fn().mockResolvedValue(null), save: jest.fn() };
      const svc = makeService({ userRepo });
      const result = await svc.requestReset('unknown@example.com');
      expect(result).toBeNull();
    });

    it('returns a token and expiry when user exists', async () => {
      const user = makeUser();
      const userRepo = { findByEmail: jest.fn().mockResolvedValue(user), save: jest.fn() };
      const cache = makeCache();
      const svc = makeService({ userRepo, cache });
      const result = await svc.requestReset('alice@example.com');
      expect(result).not.toBeNull();
      expect(result).toHaveProperty('token');
      expect(result).toHaveProperty('expiry');
      expect(result.userId).toBe('user-1');
      expect(typeof result.token).toBe('string');
      expect(result.token.length).toBeGreaterThan(10);
    });

    it('stores the token in cache with 1h TTL', async () => {
      const user = makeUser();
      const userRepo = { findByEmail: jest.fn().mockResolvedValue(user), save: jest.fn() };
      const cache = makeCache();
      const svc = makeService({ userRepo, cache });
      await svc.requestReset('alice@example.com');
      expect(cache.set).toHaveBeenCalledWith(
        expect.stringMatching(/^pwd_reset:/),
        expect.any(String),
        'EX',
        3600,
      );
    });

    it('works without a cache (no-op)', async () => {
      const user = makeUser();
      const userRepo = { findByEmail: jest.fn().mockResolvedValue(user), save: jest.fn() };
      const svc = makeService({ userRepo, cache: null });
      const result = await svc.requestReset('alice@example.com');
      expect(result).toHaveProperty('token');
    });
  });

  describe('resetWithToken()', () => {
    it('throws when cache is not available', async () => {
      const svc = makeService({ cache: null });
      await expect(svc.resetWithToken('tok', 'NewPassword1')).rejects.toThrow('Cache not available');
    });

    it('throws 400 when token is not found in cache', async () => {
      const cache = makeCache(); // empty cache
      const svc = makeService({ cache });
      await expect(svc.resetWithToken('no-such-token', 'NewPassword1'))
        .rejects.toMatchObject({ status: 400 });
    });

    it('throws 400 when token is expired (expiry in the past)', async () => {
      const expiredData = { userId: 'user-1', expiry: Date.now() - 1000 };
      const cache = makeCache();
      cache.get.mockResolvedValueOnce(JSON.stringify(expiredData));
      const svc = makeService({ cache });
      await expect(svc.resetWithToken('some-token', 'NewPassword1'))
        .rejects.toMatchObject({ status: 400 });
    });

    it('throws 404 when user is not found', async () => {
      const validData = { userId: 'user-1', expiry: Date.now() + 60000 };
      const cache = makeCache();
      cache.get.mockResolvedValueOnce(JSON.stringify(validData));
      const userRepo = {
        findByEmail: jest.fn(),
        findById: jest.fn().mockResolvedValue(null),
        save: jest.fn(),
      };
      const svc = makeService({ userRepo, cache });
      await expect(svc.resetWithToken('some-token', 'NewPassword1'))
        .rejects.toMatchObject({ status: 404 });
    });

    it('resets password and deletes token on success', async () => {
      // PasswordApplicationService uses `const { Password } = require(...)` which gets
      // undefined because the module exports the class directly. We must patch it.
      const PasswordClass = require('../domain/value-objects/Password');
      const fakePw = { hash: 'new-salt:new-hash' };
      jest.spyOn(PasswordClass, 'fromPlaintext').mockResolvedValueOnce(fakePw);

      const validData = { userId: 'user-1', expiry: Date.now() + 60000 };
      const cache = makeCache();
      cache.get.mockResolvedValueOnce(JSON.stringify(validData));
      const user = makeUser();
      const userRepo = {
        findByEmail: jest.fn(),
        findById: jest.fn().mockResolvedValue(user),
        save: jest.fn().mockResolvedValue(undefined),
      };
      const svc = makeService({ userRepo, cache });

      // The service destructures { Password } — which is undefined — so fromPlaintext
      // will throw. We need to override the internal require by patching the module cache.
      const Module = require('module');
      const pwModPath = require.resolve('../domain/value-objects/Password');
      const origExports = require.cache[pwModPath].exports;
      require.cache[pwModPath].exports = { Password: PasswordClass };

      try {
        const result = await svc.resetWithToken('some-token', 'NewPassword1!');
        expect(result).toEqual({ success: true });
        expect(userRepo.save).toHaveBeenCalled();
        expect(cache.del).toHaveBeenCalled();
      } finally {
        require.cache[pwModPath].exports = origExports;
        jest.restoreAllMocks();
      }
    });

    it('emits PASSWORD_RESET domain event via message bus on success', async () => {
      const PasswordClass = require('../domain/value-objects/Password');
      const fakePw = { hash: 'new-salt:new-hash' };

      const validData = { userId: 'user-1', expiry: Date.now() + 60000 };
      const cache = makeCache();
      cache.get.mockResolvedValueOnce(JSON.stringify(validData));
      const user = makeUser();
      const userRepo = {
        findByEmail: jest.fn(),
        findById: jest.fn().mockResolvedValue(user),
        save: jest.fn().mockResolvedValue(undefined),
      };
      const bus = { isConnected: jest.fn(() => true), publish: jest.fn() };
      const svc = makeService({ userRepo, cache, bus });

      const pwModPath = require.resolve('../domain/value-objects/Password');
      const origExports = require.cache[pwModPath].exports;
      require.cache[pwModPath].exports = { Password: { fromPlaintext: jest.fn().mockResolvedValue(fakePw) } };

      try {
        await svc.resetWithToken('some-token', 'NewPassword1!');
        expect(bus.publish).toHaveBeenCalledWith(
          AuthEvents.PASSWORD_RESET,
          expect.objectContaining({ _source: 'auth-service' }),
        );
      } finally {
        require.cache[pwModPath].exports = origExports;
      }
    });
  });

  describe('_publishDomainEvents()', () => {
    it('publishes events when bus is connected', async () => {
      const bus = { isConnected: jest.fn(() => true), publish: jest.fn() };
      const svc = makeService({ bus });
      const user = UserAggregate.create({ id: 'u1', username: 'u', email: 'u@x.com', passwordHash: 'h' });
      await svc._publishDomainEvents(user);
      expect(bus.publish).toHaveBeenCalledWith(
        AuthEvents.USER_CREATED,
        expect.objectContaining({ _source: 'auth-service' }),
      );
    });

    it('does not publish when bus is disconnected', async () => {
      const bus = { isConnected: jest.fn(() => false), publish: jest.fn() };
      const svc = makeService({ bus });
      const user = UserAggregate.create({ id: 'u1', username: 'u', email: 'u@x.com', passwordHash: 'h' });
      await svc._publishDomainEvents(user);
      expect(bus.publish).not.toHaveBeenCalled();
    });

    it('does not publish when bus is null', async () => {
      const svc = new PasswordApplicationService({
        userRepository: { findByEmail: jest.fn(), findById: jest.fn(), save: jest.fn() },
        cache: null,
        messageBus: null,
        logger: console,
      });
      const user = UserAggregate.create({ id: 'u1', username: 'u', email: 'u@x.com', passwordHash: 'h' });
      await expect(svc._publishDomainEvents(user)).resolves.toBeUndefined();
    });
  });
});
