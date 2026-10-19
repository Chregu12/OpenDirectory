'use strict';

const InstallApplicationService = require('../application/InstallApplicationService');
const DeviceAggregate = require('../domain/aggregates/DeviceAggregate');
const InstallJobAggregate = require('../domain/aggregates/InstallJobAggregate');

function makeDevice() {
  return new DeviceAggregate({ id: 'device-1', hostname: 'h', platform: 'macos' });
}

function makeJob(overrides = {}) {
  return new InstallJobAggregate({
    jobId: 'job-1',
    deviceId: 'device-1',
    appId: 'app-chrome',
    appName: 'Chrome',
    packageId: 'com.google.chrome',
    format: 'pkg',
    version: '120.0',
    ...overrides,
  });
}

function makeService(busConnected = true) {
  const deviceRepo = { findById: jest.fn() };
  const jobRepo = {
    findById: jest.fn(),
    findByDevice: jest.fn(),
    save: jest.fn().mockResolvedValue(undefined),
  };
  const bus = {
    isConnected: jest.fn(() => busConnected),
    publish: jest.fn(),
  };
  const logger = { warn: jest.fn(), info: jest.fn() };
  const svc = new InstallApplicationService({
    deviceRepository: deviceRepo,
    installJobRepository: jobRepo,
    messageBus: bus,
    logger,
  });
  return { svc, deviceRepo, jobRepo, bus };
}

describe('InstallApplicationService', () => {
  describe('createInstallJob()', () => {
    it('throws when device not found', async () => {
      const { svc, deviceRepo } = makeService();
      deviceRepo.findById.mockResolvedValue(null);
      await expect(svc.createInstallJob({ deviceId: 'missing', appId: 'x' }))
        .rejects.toThrow('Device not found');
    });

    it('creates a job and returns jobId with command', async () => {
      const { svc, deviceRepo, jobRepo, bus } = makeService(true);
      deviceRepo.findById.mockResolvedValue(makeDevice());
      jobRepo.save.mockResolvedValue(undefined);

      const result = await svc.createInstallJob({
        deviceId: 'device-1',
        appId: 'app-chrome',
        appName: 'Chrome',
        packageId: 'com.google.chrome',
        format: 'pkg',
        version: '120.0',
        downloadUrl: 'https://example.com/chrome.pkg',
        checksum: 'abc123',
      });

      expect(result).toHaveProperty('jobId');
      expect(result).toHaveProperty('command');
      expect(result.command.type).toBe('store_install');
      expect(result.command.appId).toBe('app-chrome');
      expect(jobRepo.save).toHaveBeenCalled();
      expect(bus.publish).toHaveBeenCalled();
    });
  });

  describe('completeJob()', () => {
    it('throws when job not found', async () => {
      const { svc, jobRepo } = makeService();
      jobRepo.findById.mockResolvedValue(null);
      await expect(svc.completeJob('missing', { success: true })).rejects.toThrow('Install job not found');
    });

    it('marks job complete on success=true', async () => {
      const { svc, jobRepo } = makeService(false);
      const job = makeJob();
      jobRepo.findById.mockResolvedValue(job);

      const result = await svc.completeJob('job-1', { success: true, version: '121.0' });
      expect(result.status).toBe('completed');
      expect(jobRepo.save).toHaveBeenCalledWith(job);
    });

    it('marks job failed on success=false', async () => {
      const { svc, jobRepo } = makeService(false);
      const job = makeJob();
      jobRepo.findById.mockResolvedValue(job);

      const result = await svc.completeJob('job-1', { success: false, error: 'timeout' });
      expect(result.status).toBe('failed');
      expect(result._error).toBe('timeout');
    });

    it('publishes domain events when bus is connected', async () => {
      const { svc, jobRepo, bus } = makeService(true);
      const job = makeJob();
      jobRepo.findById.mockResolvedValue(job);

      await svc.completeJob('job-1', { success: true, version: '1.0' });
      expect(bus.publish).toHaveBeenCalled();
    });
  });

  describe('getJobsForDevice()', () => {
    it('delegates to jobRepo.findByDevice', async () => {
      const { svc, jobRepo } = makeService();
      const jobs = [makeJob()];
      jobRepo.findByDevice.mockResolvedValue(jobs);
      const result = await svc.getJobsForDevice('device-1');
      expect(result).toBe(jobs);
      expect(jobRepo.findByDevice).toHaveBeenCalledWith('device-1');
    });
  });
});
