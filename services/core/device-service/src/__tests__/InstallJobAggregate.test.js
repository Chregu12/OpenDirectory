'use strict';

const InstallJobAggregate = require('../domain/aggregates/InstallJobAggregate');
const { DeviceEvents } = require('../domain/events/DeviceEvents');

describe('InstallJobAggregate', () => {
  const baseProps = {
    jobId: 'job-1',
    deviceId: 'device-1',
    appId: 'app-chrome',
    appName: 'Google Chrome',
    packageId: 'com.google.chrome',
    format: 'pkg',
    version: '120.0',
  };

  describe('constructor', () => {
    it('defaults status to queued', () => {
      const job = new InstallJobAggregate(baseProps);
      expect(job.status).toBe('queued');
    });

    it('exposes jobId, deviceId, status', () => {
      const job = new InstallJobAggregate(baseProps);
      expect(job.jobId).toBe('job-1');
      expect(job.deviceId).toBe('device-1');
    });
  });

  describe('static create()', () => {
    it('creates a job and emits INSTALL_JOB_CREATED', () => {
      const job = InstallJobAggregate.create(baseProps);
      expect(job.status).toBe('queued');
      const events = job.getAndClearDomainEvents();
      expect(events).toHaveLength(1);
      expect(events[0].type).toBe(DeviceEvents.INSTALL_JOB_CREATED);
      expect(events[0].payload.jobId).toBe('job-1');
      expect(events[0].payload.deviceId).toBe('device-1');
      expect(events[0].payload.appId).toBe('app-chrome');
    });
  });

  describe('markDelivered()', () => {
    it('sets status to delivered and does not emit an event', () => {
      const job = new InstallJobAggregate(baseProps);
      job.markDelivered();
      expect(job.status).toBe('delivered');
      expect(job.getAndClearDomainEvents()).toHaveLength(0);
    });

    it('returns job for chaining', () => {
      const job = new InstallJobAggregate(baseProps);
      expect(job.markDelivered()).toBe(job);
    });
  });

  describe('complete()', () => {
    it('sets status to completed and emits INSTALL_JOB_COMPLETED', () => {
      const job = new InstallJobAggregate(baseProps);
      job.complete('121.0');
      expect(job.status).toBe('completed');
      expect(job._completedAt).toBeInstanceOf(Date);
      const events = job.getAndClearDomainEvents();
      expect(events[0].type).toBe(DeviceEvents.INSTALL_JOB_COMPLETED);
      expect(events[0].payload.version).toBe('121.0');
    });

    it('updates version when provided', () => {
      const job = new InstallJobAggregate(baseProps);
      job.complete('999.0');
      expect(job._version).toBe('999.0');
    });

    it('keeps original version when none provided', () => {
      const job = new InstallJobAggregate(baseProps);
      job.complete(null);
      expect(job._version).toBe('120.0');
    });

    it('returns job for chaining', () => {
      const job = new InstallJobAggregate(baseProps);
      expect(job.complete('1.0')).toBe(job);
    });
  });

  describe('fail()', () => {
    it('sets status to failed and emits INSTALL_JOB_FAILED', () => {
      const job = new InstallJobAggregate(baseProps);
      job.fail('Package corrupted');
      expect(job.status).toBe('failed');
      expect(job._completedAt).toBeInstanceOf(Date);
      expect(job._error).toBe('Package corrupted');
      const events = job.getAndClearDomainEvents();
      expect(events[0].type).toBe(DeviceEvents.INSTALL_JOB_FAILED);
      expect(events[0].payload.error).toBe('Package corrupted');
    });

    it('returns job for chaining', () => {
      const job = new InstallJobAggregate(baseProps);
      expect(job.fail('err')).toBe(job);
    });
  });

  describe('getAndClearDomainEvents()', () => {
    it('clears events after first call', () => {
      const job = InstallJobAggregate.create(baseProps);
      const events = job.getAndClearDomainEvents();
      expect(events).toHaveLength(1);
      expect(job.getAndClearDomainEvents()).toHaveLength(0);
    });
  });

  describe('toJSON()', () => {
    it('returns plain object with expected fields', () => {
      const job = new InstallJobAggregate(baseProps);
      const json = job.toJSON();
      expect(json).toMatchObject({
        jobId: 'job-1',
        deviceId: 'device-1',
        appId: 'app-chrome',
        appName: 'Google Chrome',
        format: 'pkg',
        status: 'queued',
      });
    });

    it('includes completedAt and error after failure', () => {
      const job = new InstallJobAggregate(baseProps);
      job.fail('disk full');
      const json = job.toJSON();
      expect(json.status).toBe('failed');
      expect(json.error).toBe('disk full');
      expect(json.completedAt).toBeInstanceOf(Date);
    });

    it('includes completedAt after successful completion', () => {
      const job = new InstallJobAggregate(baseProps);
      job.complete('121.0');
      const json = job.toJSON();
      expect(json.status).toBe('completed');
      expect(json.completedAt).toBeInstanceOf(Date);
    });

    it('does not expose internal domain events', () => {
      const job = InstallJobAggregate.create(baseProps);
      const json = job.toJSON();
      expect(json).not.toHaveProperty('_domainEvents');
    });
  });

  describe('invalid state transitions', () => {
    it('calling complete() on an already-failed job overwrites status (no guard)', () => {
      // InstallJobAggregate does not enforce state guards — document actual behaviour.
      const job = new InstallJobAggregate(baseProps);
      job.fail('some error');
      job.getAndClearDomainEvents();
      // complete() does not throw; it simply transitions (library choice)
      expect(() => job.complete('1.0')).not.toThrow();
    });

    it('calling fail() on an already-completed job does not throw', () => {
      const job = new InstallJobAggregate(baseProps);
      job.complete('1.0');
      job.getAndClearDomainEvents();
      expect(() => job.fail('late error')).not.toThrow();
    });
  });

  describe('fail() — additional edge cases', () => {
    it('stores the error reason on the job', () => {
      const job = new InstallJobAggregate(baseProps);
      job.fail('network timeout');
      expect(job._error).toBe('network timeout');
    });

    it('emits event with deviceId and appId in payload', () => {
      const job = new InstallJobAggregate(baseProps);
      job.fail('reason');
      const events = job.getAndClearDomainEvents();
      expect(events[0].payload.deviceId).toBe('device-1');
      expect(events[0].payload.appId).toBe('app-chrome');
    });
  });

  describe('complete() — additional edge cases', () => {
    it('emits event with deviceId and appId in payload', () => {
      const job = new InstallJobAggregate(baseProps);
      job.complete('1.0');
      const events = job.getAndClearDomainEvents();
      expect(events[0].payload.deviceId).toBe('device-1');
      expect(events[0].payload.appId).toBe('app-chrome');
    });
  });
});
