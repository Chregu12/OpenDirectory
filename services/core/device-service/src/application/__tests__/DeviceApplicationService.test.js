'use strict';

const DeviceApplicationService = require('../DeviceApplicationService');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDevice({
  id = 'dev-1',
  hostname = 'mac-pro.local',
  platform = 'macos',
  isCompliant = true,
  status = 'active',
} = {}) {
  return {
    id,
    hostname,
    platform,
    isCompliant,
    status,
    markCompliant: jest.fn().mockReturnThis(),
    markNonCompliant: jest.fn().mockReturnThis(),
    updateLastSeen: jest.fn().mockReturnThis(),
    retire: jest.fn().mockReturnThis(),
    getAndClearDomainEvents: jest.fn().mockReturnValue([]),
    toJSON: jest.fn().mockReturnValue({ id, hostname, platform, isCompliant, status }),
  };
}

// ---------------------------------------------------------------------------
// Mock repository & bus
// ---------------------------------------------------------------------------

const mockDeviceRepo = {
  findById: jest.fn(),
  findAll: jest.fn(),
  save: jest.fn(),
  exists: jest.fn(),
};

const mockBus = {
  isConnected: jest.fn().mockReturnValue(false),
  publish: jest.fn(),
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('DeviceApplicationService', () => {
  let svc;

  beforeEach(() => {
    jest.clearAllMocks();
    mockBus.isConnected.mockReturnValue(false);

    svc = new DeviceApplicationService({
      deviceRepository: mockDeviceRepo,
      messageBus: mockBus,
      logger: { warn: jest.fn(), info: jest.fn(), error: jest.fn() },
    });
  });

  // ── enrollDevice / createDevice ────────────────────────────────────────────

  describe('enrollDevice()', () => {
    it('creates and saves a new DeviceAggregate for a new device', async () => {
      mockDeviceRepo.exists.mockResolvedValue(false);
      mockDeviceRepo.save.mockResolvedValue(undefined);

      const result = await svc.enrollDevice({
        id: 'dev-1',
        hostname: 'mac-pro.local',
        platform: 'macos',
        orgId: 'org-1',
        userId: 'user-1',
      });

      expect(mockDeviceRepo.exists).toHaveBeenCalledWith('dev-1');
      expect(mockDeviceRepo.save).toHaveBeenCalledTimes(1);
      // The saved argument should be a DeviceAggregate
      const savedDevice = mockDeviceRepo.save.mock.calls[0][0];
      expect(savedDevice.id).toBe('dev-1');
      expect(savedDevice.hostname).toBe('mac-pro.local');
      expect(savedDevice.platform).toBe('macos');
      expect(result).toBeDefined();
    });

    it('throws for an invalid platform', async () => {
      await expect(
        svc.enrollDevice({ id: 'dev-1', hostname: 'x', platform: 'dos', orgId: 'o', userId: 'u' })
      ).rejects.toThrow(/Invalid platform/);

      expect(mockDeviceRepo.save).not.toHaveBeenCalled();
    });

    it('updates lastSeen when re-enrolling an existing device', async () => {
      const existing = makeDevice();
      mockDeviceRepo.exists.mockResolvedValue(true);
      mockDeviceRepo.findById.mockResolvedValue(existing);
      mockDeviceRepo.save.mockResolvedValue(undefined);

      await svc.enrollDevice({ id: 'dev-1', hostname: 'mac-pro.local', platform: 'macos', orgId: 'o', userId: 'u' });

      expect(existing.updateLastSeen).toHaveBeenCalled();
      expect(mockDeviceRepo.save).toHaveBeenCalledWith(existing);
    });
  });

  // ── getDevice ──────────────────────────────────────────────────────────────

  describe('getDevice()', () => {
    it('calls deviceRepository.findById with the given id', async () => {
      const device = makeDevice();
      mockDeviceRepo.findById.mockResolvedValue(device);

      const result = await svc.getDevice('dev-1');

      expect(mockDeviceRepo.findById).toHaveBeenCalledWith('dev-1');
      expect(result).toBe(device);
    });

    it('returns null when device does not exist', async () => {
      mockDeviceRepo.findById.mockResolvedValue(null);

      const result = await svc.getDevice('non-existent');

      expect(result).toBeNull();
    });
  });

  // ── markDeviceCompliant (via updateCompliance) ─────────────────────────────

  describe('updateCompliance() — mark compliant', () => {
    it('loads aggregate, calls markCompliant(), saves, and returns device', async () => {
      const device = makeDevice({ isCompliant: false });
      mockDeviceRepo.findById.mockResolvedValue(device);
      mockDeviceRepo.save.mockResolvedValue(undefined);

      const result = await svc.updateCompliance('dev-1', { isCompliant: true });

      expect(mockDeviceRepo.findById).toHaveBeenCalledWith('dev-1');
      expect(device.markCompliant).toHaveBeenCalled();
      expect(device.markNonCompliant).not.toHaveBeenCalled();
      expect(mockDeviceRepo.save).toHaveBeenCalledWith(device);
      expect(result).toBe(device);
    });

    it('throws when device is not found', async () => {
      mockDeviceRepo.findById.mockResolvedValue(null);

      await expect(
        svc.updateCompliance('missing', { isCompliant: true })
      ).rejects.toThrow('Device not found: missing');
    });
  });

  // ── markDeviceNonCompliant (via updateCompliance) ──────────────────────────

  describe('updateCompliance() — mark non-compliant', () => {
    it('loads aggregate, calls markNonCompliant() with violations, saves, and dispatches events', async () => {
      mockBus.isConnected.mockReturnValue(true);
      const violations = [{ rule: 'disk-encryption', severity: 'high' }];
      const nonCompliantEvent = { type: 'device.non_compliant', payload: { deviceId: 'dev-1', violations } };
      const device = makeDevice({ isCompliant: true });
      device.getAndClearDomainEvents.mockReturnValue([nonCompliantEvent]);
      mockDeviceRepo.findById.mockResolvedValue(device);
      mockDeviceRepo.save.mockResolvedValue(undefined);

      const result = await svc.updateCompliance('dev-1', { isCompliant: false, violations });

      expect(device.markNonCompliant).toHaveBeenCalledWith(violations);
      expect(device.markCompliant).not.toHaveBeenCalled();
      expect(mockDeviceRepo.save).toHaveBeenCalledWith(device);
      expect(result).toBe(device);

      // Domain events should be dispatched
      expect(mockBus.publish).toHaveBeenCalledWith(
        nonCompliantEvent.type,
        expect.objectContaining({ deviceId: 'dev-1', _source: 'device-service' })
      );
    });
  });
});
