'use strict';

const MFAApplicationService = require('../application/MFAApplicationService');
const UserAggregate = require('../domain/aggregates/UserAggregate');

function makeUser(overrides = {}) {
  return new UserAggregate({
    id: 'user-1',
    username: 'alice',
    email: 'alice@example.com',
    passwordHash: 'hash',
    roles: ['user'],
    mfaEnabled: false,
    ...overrides,
  });
}

function makeService(busConnected = true) {
  const userRepo = {
    findById: jest.fn(),
    save: jest.fn().mockResolvedValue(undefined),
  };
  const bus = {
    isConnected: jest.fn(() => busConnected),
    publish: jest.fn(),
  };
  const logger = { warn: jest.fn(), info: jest.fn(), error: jest.fn() };
  const svc = new MFAApplicationService({ userRepository: userRepo, messageBus: bus, logger });
  return { svc, userRepo, bus, logger };
}

describe('MFAApplicationService', () => {
  describe('enableMFA()', () => {
    it('throws 404 when user not found', async () => {
      const { svc, userRepo } = makeService();
      userRepo.findById.mockResolvedValue(null);
      await expect(svc.enableMFA('missing-user', 'SECRET')).rejects.toMatchObject({ status: 404 });
    });

    it('enables MFA, saves user, returns result', async () => {
      const { svc, userRepo } = makeService();
      const user = makeUser();
      userRepo.findById.mockResolvedValue(user);

      const result = await svc.enableMFA('user-1', 'TOTP_SECRET', ['rc1', 'rc2']);
      expect(result).toEqual({ mfaEnabled: true, recoveryCodes: ['rc1', 'rc2'] });
      expect(userRepo.save).toHaveBeenCalledWith(user);
      expect(user.mfaEnabled).toBe(true);
      expect(user.mfaSecret).toBe('TOTP_SECRET');
    });

    it('publishes domain events when bus is connected', async () => {
      const { svc, userRepo, bus } = makeService(true);
      const user = makeUser();
      userRepo.findById.mockResolvedValue(user);
      await svc.enableMFA('user-1', 'SECRET', []);
      expect(bus.publish).toHaveBeenCalled();
    });

    it('does not publish events when bus is not connected', async () => {
      const { svc, userRepo, bus } = makeService(false);
      const user = makeUser();
      userRepo.findById.mockResolvedValue(user);
      await svc.enableMFA('user-1', 'SECRET', []);
      expect(bus.publish).not.toHaveBeenCalled();
    });
  });

  describe('disableMFA()', () => {
    it('throws 404 when user not found', async () => {
      const { svc, userRepo } = makeService();
      userRepo.findById.mockResolvedValue(null);
      await expect(svc.disableMFA('missing')).rejects.toMatchObject({ status: 404 });
    });

    it('disables MFA, saves user, returns result', async () => {
      const { svc, userRepo } = makeService();
      const user = makeUser({ mfaEnabled: true, mfaSecret: 'S' });
      userRepo.findById.mockResolvedValue(user);

      const result = await svc.disableMFA('user-1');
      expect(result).toEqual({ mfaEnabled: false });
      expect(userRepo.save).toHaveBeenCalledWith(user);
      expect(user.mfaEnabled).toBe(false);
    });
  });

  describe('verifyMFA()', () => {
    it('throws 404 when user not found', async () => {
      const { svc, userRepo } = makeService();
      userRepo.findById.mockResolvedValue(null);
      await expect(svc.verifyMFA('missing', '123456', null)).rejects.toMatchObject({ status: 404 });
    });

    it('throws 400 when MFA is not enabled', async () => {
      const { svc, userRepo } = makeService();
      const user = makeUser({ mfaEnabled: false });
      userRepo.findById.mockResolvedValue(user);
      await expect(svc.verifyMFA('user-1', '123456', null)).rejects.toMatchObject({ status: 400 });
    });

    it('throws 401 when TOTP code is invalid', async () => {
      const { svc, userRepo } = makeService();
      const user = makeUser({ mfaEnabled: true, mfaSecret: 'SECRET' });
      userRepo.findById.mockResolvedValue(user);
      const totpLib = { verify: jest.fn(() => false) };

      await expect(svc.verifyMFA('user-1', 'wrong-code', totpLib))
        .rejects.toMatchObject({ status: 401 });
    });

    it('returns { verified: true } when code is valid', async () => {
      const { svc, userRepo, bus } = makeService(true);
      const user = makeUser({ mfaEnabled: true, mfaSecret: 'SECRET' });
      userRepo.findById.mockResolvedValue(user);
      const totpLib = { verify: jest.fn(() => true) };

      const result = await svc.verifyMFA('user-1', '123456', totpLib);
      expect(result).toEqual({ verified: true });
      expect(bus.publish).toHaveBeenCalled();
    });

    it('returns verified:true and does not throw when no totpLib provided but user has no MFA enabled', async () => {
      const { svc, userRepo } = makeService();
      const user = makeUser({ mfaEnabled: false });
      userRepo.findById.mockResolvedValue(user);
      await expect(svc.verifyMFA('user-1', '000000', null))
        .rejects.toMatchObject({ status: 400 });
    });
  });
});
