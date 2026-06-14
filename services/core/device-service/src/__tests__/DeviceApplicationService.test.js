'use strict';

const DeviceApplicationService = require('../application/DeviceApplicationService');
const DeviceAggregate = require('../domain/aggregates/DeviceAggregate');

function makeDevice(overrides = {}) {
  return new DeviceAggregate({
    id: 'device-1',
    hostname: 'MacBook-Alice',
    platform: 'macos',
    status: 'active',
    isCompliant: true,
    complianceViolations: [],
    ...overrides,
  });
}

function makeService(busConnected = true) {
  const deviceRepo = {
    exists: jest.fn(),
    findById: jest.fn(),
    findAll: jest.fn(),
    save: jest.fn().mockResolvedValue(undefined),
  };
  const bus = {
    isConnected: jest.fn(() => busConnected),
    publish: jest.fn(),
  };
  const logger = { warn: jest.fn(), info: jest.fn() };
  const svc = new DeviceApplicationService({ deviceRepository: deviceRepo, messageBus: bus, logger });
  return { svc, deviceRepo, bus, logger };
}

describe('DeviceApplicationService', () => {
  describe('enrollDevice()', () => {
    it('throws for invalid platform', async () => {
      const { svc } = makeService();
      await expect(svc.enrollDevice({ id: 'd1', hostname: 'h', platform: 'dos', orgId: 'o1' }))
        .rejects.toThrow('Invalid platform');
    });

    it('creates a new device when it does not exist', async () => {
      const { svc, deviceRepo, bus } = makeService(true);
      deviceRepo.exists.mockResolvedValue(false);
      deviceRepo.save.mockResolvedValue(undefined);

      const result = await svc.enrollDevice({ id: 'dev-new', hostname: 'PC1', platform: 'windows' });
      expect(result).toBeInstanceOf(DeviceAggregate);
      expect(deviceRepo.save).toHaveBeenCalled();
      expect(bus.publish).toHaveBeenCalled();
    });

    it('updates lastSeen for re-enrollment when device already exists', async () => {
      const { svc, deviceRepo } = makeService(false);
      const existing = makeDevice();
      deviceRepo.exists.mockResolvedValue(true);
      deviceRepo.findById.mockResolvedValue(existing);

      const result = await svc.enrollDevice({ id: 'device-1', hostname: 'MacBook', platform: 'macos' });
      expect(result).toBe(existing);
      expect(deviceRepo.save).toHaveBeenCalled();
    });
  });

  describe('markDeviceSeen()', () => {
    it('throws when device not found', async () => {
      const { svc, deviceRepo } = makeService();
      deviceRepo.findById.mockResolvedValue(null);
      await expect(svc.markDeviceSeen('missing')).rejects.toThrow('Device not found');
    });

    it('updates lastSeen and saves', async () => {
      const { svc, deviceRepo } = makeService();
      const device = makeDevice();
      deviceRepo.findById.mockResolvedValue(device);

      const result = await svc.markDeviceSeen('device-1');
      expect(result).toBe(device);
      expect(result.lastSeen).toBeInstanceOf(Date);
      expect(deviceRepo.save).toHaveBeenCalledWith(device);
    });
  });

  describe('updateCompliance()', () => {
    it('throws when device not found', async () => {
      const { svc, deviceRepo } = makeService();
      deviceRepo.findById.mockResolvedValue(null);
      await expect(svc.updateCompliance('missing', { isCompliant: true })).rejects.toThrow('Device not found');
    });

    it('marks device compliant when isCompliant=true', async () => {
      const { svc, deviceRepo } = makeService(false);
      const device = makeDevice({ isCompliant: false, complianceViolations: ['old-violation'] });
      deviceRepo.findById.mockResolvedValue(device);

      const result = await svc.updateCompliance('device-1', { isCompliant: true });
      expect(result.isCompliant).toBe(true);
      expect(result.complianceViolations).toEqual([]);
      expect(deviceRepo.save).toHaveBeenCalled();
    });

    it('marks device non-compliant with violations', async () => {
      const { svc, deviceRepo } = makeService(false);
      const device = makeDevice({ isCompliant: true });
      deviceRepo.findById.mockResolvedValue(device);

      const result = await svc.updateCompliance('device-1', {
        isCompliant: false,
        violations: ['no-antivirus', 'disk-unencrypted'],
      });
      expect(result.isCompliant).toBe(false);
      expect(result.complianceViolations).toEqual(['no-antivirus', 'disk-unencrypted']);
    });

    it('publishes domain events when bus is connected', async () => {
      const { svc, deviceRepo, bus } = makeService(true);
      const device = makeDevice({ isCompliant: false });
      deviceRepo.findById.mockResolvedValue(device);

      await svc.updateCompliance('device-1', { isCompliant: true });
      expect(bus.publish).toHaveBeenCalled();
    });
  });

  describe('retireDevice()', () => {
    it('throws when device not found', async () => {
      const { svc, deviceRepo } = makeService();
      deviceRepo.findById.mockResolvedValue(null);
      await expect(svc.retireDevice('missing')).rejects.toThrow('Device not found');
    });

    it('retires device and saves', async () => {
      const { svc, deviceRepo } = makeService(false);
      const device = makeDevice();
      deviceRepo.findById.mockResolvedValue(device);

      const result = await svc.retireDevice('device-1');
      expect(result.status).toBe('retired');
      expect(deviceRepo.save).toHaveBeenCalled();
    });
  });

  describe('getDevice()', () => {
    it('delegates to repository findById', async () => {
      const { svc, deviceRepo } = makeService();
      const device = makeDevice();
      deviceRepo.findById.mockResolvedValue(device);
      const result = await svc.getDevice('device-1');
      expect(result).toBe(device);
    });
  });

  describe('listDevices()', () => {
    it('delegates to repository findAll with filters', async () => {
      const { svc, deviceRepo } = makeService();
      deviceRepo.findAll.mockResolvedValue([makeDevice()]);
      const result = await svc.listDevices({ platform: 'macos' });
      expect(result).toHaveLength(1);
      expect(deviceRepo.findAll).toHaveBeenCalledWith({ platform: 'macos' });
    });
  });
});
