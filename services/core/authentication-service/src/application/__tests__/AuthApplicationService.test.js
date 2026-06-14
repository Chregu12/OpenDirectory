'use strict';

// Mock the Password value object so tests don't need real scrypt hashes
jest.mock('../../domain/value-objects/Password', () => {
  return {
    Password: {
      fromHash: jest.fn(),
    },
  };
});

const AuthApplicationService = require('../AuthApplicationService');
const { Password } = require('../../domain/value-objects/Password');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeUser({
  id = 'user-1',
  username = 'alice',
  passwordHash = 'hash:stored',
  roles = ['user'],
  mfaEnabled = false,
  locked = false,
  lockUntil = null,
} = {}) {
  return {
    id,
    username,
    passwordHash,
    roles,
    mfaEnabled,
    isLocked: jest.fn().mockReturnValue(locked),
    recordLoginSuccess: jest.fn(),
    recordLoginFailure: jest.fn(),
    getAndClearDomainEvents: jest.fn().mockReturnValue([]),
    toJSON: jest.fn().mockReturnValue({ id, username, roles, mfaEnabled }),
  };
}

function makeSession(token = 'tok-abc') {
  return {
    revoke: jest.fn(),
    getAndClearDomainEvents: jest.fn().mockReturnValue([]),
  };
}

// ---------------------------------------------------------------------------
// Mock repositories & bus
// ---------------------------------------------------------------------------

const mockUserRepo = {
  findByUsername: jest.fn(),
  findById: jest.fn(),
  save: jest.fn(),
};

const mockSessionRepo = {
  save: jest.fn(),
  findByToken: jest.fn(),
};

const mockBus = {
  isConnected: jest.fn().mockReturnValue(false), // no event dispatching by default
  publish: jest.fn(),
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AuthApplicationService', () => {
  let svc;

  beforeEach(() => {
    jest.clearAllMocks();
    mockBus.isConnected.mockReturnValue(false);

    svc = new AuthApplicationService({
      userRepository: mockUserRepo,
      sessionRepository: mockSessionRepo,
      messageBus: mockBus,
      config: { jwtSecret: 'test-secret' },
      logger: { warn: jest.fn(), info: jest.fn(), error: jest.fn() },
    });
  });

  // ── login — happy path ─────────────────────────────────────────────────────

  describe('login()', () => {
    it('returns user object and token on successful login', async () => {
      const user = makeUser();
      mockUserRepo.findByUsername.mockResolvedValue(user);
      mockUserRepo.save.mockResolvedValue(user);

      // Password.fromHash returns an object whose verify resolves true
      const mockPw = { verify: jest.fn().mockResolvedValue(true) };
      Password.fromHash.mockReturnValue(mockPw);

      const result = await svc.login({ username: 'alice', password: 'correct' });

      expect(mockUserRepo.findByUsername).toHaveBeenCalledWith('alice');
      expect(mockPw.verify).toHaveBeenCalledWith('correct');
      expect(user.recordLoginSuccess).toHaveBeenCalled();
      expect(mockUserRepo.save).toHaveBeenCalledWith(user);
      expect(result).toHaveProperty('token');
      expect(result).toHaveProperty('user');
      expect(result.user.username).toBe('alice');
    });

    // ── user not found ─────────────────────────────────────────────────────

    it('throws 401 when user is not found', async () => {
      mockUserRepo.findByUsername.mockResolvedValue(null);

      await expect(
        svc.login({ username: 'nobody', password: 'pass' })
      ).rejects.toMatchObject({ message: 'Invalid credentials', status: 401 });

      expect(mockUserRepo.findByUsername).toHaveBeenCalledWith('nobody');
    });

    // ── wrong password ────────────────────────────────────────────────────

    it('throws 401 and records login failure when password is wrong', async () => {
      const user = makeUser();
      mockUserRepo.findByUsername.mockResolvedValue(user);
      mockUserRepo.save.mockResolvedValue(user);

      const mockPw = { verify: jest.fn().mockResolvedValue(false) };
      Password.fromHash.mockReturnValue(mockPw);

      await expect(
        svc.login({ username: 'alice', password: 'wrong' })
      ).rejects.toMatchObject({ message: 'Invalid credentials', status: 401 });

      expect(user.recordLoginFailure).toHaveBeenCalled();
      expect(mockUserRepo.save).toHaveBeenCalledWith(user);
    });

    // ── account locked ────────────────────────────────────────────────────

    it('throws 403 when user account is locked', async () => {
      const user = makeUser({ locked: true });
      mockUserRepo.findByUsername.mockResolvedValue(user);

      await expect(
        svc.login({ username: 'alice', password: 'any' })
      ).rejects.toMatchObject({ message: 'Account is locked', status: 403 });

      // Should not attempt password verification
      expect(Password.fromHash).not.toHaveBeenCalled();
    });

    // ── domain events dispatched ──────────────────────────────────────────

    it('dispatches domain events after successful login when bus is connected', async () => {
      mockBus.isConnected.mockReturnValue(true);

      const domainEvent = { type: 'auth.login_success', payload: { userId: 'user-1' } };
      const user = makeUser();
      user.getAndClearDomainEvents.mockReturnValueOnce([domainEvent]).mockReturnValue([]);
      mockUserRepo.findByUsername.mockResolvedValue(user);
      mockUserRepo.save.mockResolvedValue(user);
      mockSessionRepo.save.mockResolvedValue({});

      const mockPw = { verify: jest.fn().mockResolvedValue(true) };
      Password.fromHash.mockReturnValue(mockPw);

      await svc.login({ username: 'alice', password: 'correct' });

      expect(mockBus.publish).toHaveBeenCalledWith(
        domainEvent.type,
        expect.objectContaining({ userId: 'user-1', _source: 'auth-service' })
      );
    });
  });

  // ── logout ─────────────────────────────────────────────────────────────────

  describe('logout()', () => {
    it('revokes the session and saves it when token is found', async () => {
      const session = makeSession();
      mockSessionRepo.findByToken.mockResolvedValue(session);
      mockSessionRepo.save.mockResolvedValue(session);

      await svc.logout('tok-abc');

      expect(mockSessionRepo.findByToken).toHaveBeenCalledWith('tok-abc');
      expect(session.revoke).toHaveBeenCalled();
      expect(mockSessionRepo.save).toHaveBeenCalledWith(session);
    });

    it('does nothing when token is not found (no error)', async () => {
      mockSessionRepo.findByToken.mockResolvedValue(null);

      await expect(svc.logout('tok-unknown')).resolves.toBeUndefined();
      expect(mockSessionRepo.save).not.toHaveBeenCalled();
    });
  });
});
