'use strict';

const DriverAggregate = require('../DriverAggregate');
const { DeviceEvents } = require('../../events/DeviceEvents');

describe('DriverAggregate', () => {
  const validProps = {
    id: 'driver-1',
    name: 'Intel Chipset Driver',
    version: '1.2.3',
    vendor: 'Intel',
    os: ['windows'],
    deviceType: 'chipset',
    format: 'exe',
    architecture: 'x64',
    checksum: 'a'.repeat(64),
    fileSize: 1024,
    filename: 'chipset.exe',
    filePath: '/var/lib/opendirectory/device-drivers/files/driver-1-chipset.exe',
  };

  // ── create() ───────────────────────────────────────────────────────────────

  describe('create()', () => {
    it('returns a DriverAggregate with the given props', () => {
      const driver = DriverAggregate.create(validProps);

      expect(driver).toBeInstanceOf(DriverAggregate);
      expect(driver.id).toBe('driver-1');
      expect(driver.name).toBe('Intel Chipset Driver');
      expect(driver.version).toBe('1.2.3');
      expect(driver.vendor).toBe('Intel');
      expect(driver.os).toEqual(['windows']);
      expect(driver.deviceType).toBe('chipset');
      expect(driver.format).toBe('exe');
      expect(driver.architecture).toBe('x64');
      expect(driver.checksum).toBe('a'.repeat(64));
      expect(driver.fileSize).toBe(1024);
      expect(driver.deployments).toEqual([]);
    });

    it('defaults description to an empty string and tags to []', () => {
      const driver = DriverAggregate.create(validProps);
      expect(driver.description).toBe('');
      expect(driver.tags).toEqual([]);
    });

    it('normalizes a comma-separated tags string into an array', () => {
      const driver = DriverAggregate.create({ ...validProps, tags: 'network, wifi , intel' });
      expect(driver.tags).toEqual(['network', 'wifi', 'intel']);
    });

    it('sets uploadedAt', () => {
      const driver = DriverAggregate.create(validProps);
      expect(driver.uploadedAt).toBeTruthy();
    });

    it('emits a DRIVER_IMPORTED event with occurredAt and eventId', () => {
      const driver = DriverAggregate.create(validProps);
      const events = driver.getAndClearDomainEvents();

      expect(events).toHaveLength(1);
      const [evt] = events;
      expect(evt.type).toBe(DeviceEvents.DRIVER_IMPORTED);
      expect(evt.occurredAt).toBeInstanceOf(Date);
      expect(typeof evt.eventId).toBe('string');
      expect(evt.eventId).toBeTruthy();
      expect(evt.payload.driverId).toBe('driver-1');
      expect(evt.payload.name).toBe('Intel Chipset Driver');
      expect(evt.payload.vendor).toBe('Intel');
    });

    it.each(['id', 'name', 'version', 'vendor', 'deviceType', 'architecture', 'checksum', 'fileSize', 'filename', 'filePath'])(
      'throws when %s is missing',
      (field) => {
        const props = { ...validProps };
        delete props[field];
        expect(() => DriverAggregate.create(props)).toThrow();
      }
    );

    it('throws when os is missing or empty', () => {
      expect(() => DriverAggregate.create({ ...validProps, os: [] })).toThrow();
      expect(() => DriverAggregate.create({ ...validProps, os: undefined })).toThrow();
    });

    it('throws when fileSize is negative', () => {
      expect(() => DriverAggregate.create({ ...validProps, fileSize: -1 })).toThrow();
    });

    it('throws when format is not a valid DriverFormat', () => {
      expect(() => DriverAggregate.create({ ...validProps, format: 'not-a-real-format' })).toThrow();
    });
  });

  // ── addDeployment() ────────────────────────────────────────────────────────

  describe('addDeployment(deviceId)', () => {
    it('adds a deployment entity with status "pending"', () => {
      const driver = DriverAggregate.create(validProps);
      driver.getAndClearDomainEvents();

      const deployment = driver.addDeployment('device-42');

      expect(deployment.driverId).toBe('driver-1');
      expect(deployment.deviceId).toBe('device-42');
      expect(deployment.status).toBe('pending');
      expect(deployment.error).toBeNull();
      expect(driver.deployments).toHaveLength(1);
    });

    it('assigns a unique id per deployment', () => {
      const driver = DriverAggregate.create(validProps);
      const d1 = driver.addDeployment('device-1');
      const d2 = driver.addDeployment('device-2');
      expect(d1.id).not.toBe(d2.id);
    });

    it('emits a DRIVER_DEPLOYED event with occurredAt and eventId', () => {
      const driver = DriverAggregate.create(validProps);
      driver.getAndClearDomainEvents();

      driver.addDeployment('device-42');
      const events = driver.getAndClearDomainEvents();

      const evt = events.find(e => e.type === DeviceEvents.DRIVER_DEPLOYED);
      expect(evt).toBeDefined();
      expect(evt.occurredAt).toBeInstanceOf(Date);
      expect(evt.eventId).toBeTruthy();
      expect(evt.payload.driverId).toBe('driver-1');
      expect(evt.payload.deviceId).toBe('device-42');
    });

    it('throws when deviceId is missing', () => {
      const driver = DriverAggregate.create(validProps);
      expect(() => driver.addDeployment()).toThrow();
    });
  });

  // ── updateDeploymentStatus() — status transitions ─────────────────────────

  describe('updateDeploymentStatus(deploymentId, status, error)', () => {
    it('allows pending -> deploying', () => {
      const driver = DriverAggregate.create(validProps);
      const deployment = driver.addDeployment('device-1');

      const updated = driver.updateDeploymentStatus(deployment.id, 'deploying');

      expect(updated.status).toBe('deploying');
    });

    it('allows deploying -> success', () => {
      const driver = DriverAggregate.create(validProps);
      const deployment = driver.addDeployment('device-1');
      driver.updateDeploymentStatus(deployment.id, 'deploying');

      const updated = driver.updateDeploymentStatus(deployment.id, 'success');

      expect(updated.status).toBe('success');
    });

    it('allows deploying -> failed with an error message', () => {
      const driver = DriverAggregate.create(validProps);
      const deployment = driver.addDeployment('device-1');
      driver.updateDeploymentStatus(deployment.id, 'deploying');

      const updated = driver.updateDeploymentStatus(deployment.id, 'failed', 'disk full');

      expect(updated.status).toBe('failed');
      expect(updated.error).toBe('disk full');
    });

    it('allows pending -> failed directly (e.g. device rejects the deployment)', () => {
      const driver = DriverAggregate.create(validProps);
      const deployment = driver.addDeployment('device-1');

      const updated = driver.updateDeploymentStatus(deployment.id, 'failed', 'rejected');

      expect(updated.status).toBe('failed');
    });

    it('rejects pending -> success (must pass through deploying)', () => {
      const driver = DriverAggregate.create(validProps);
      const deployment = driver.addDeployment('device-1');

      expect(() => driver.updateDeploymentStatus(deployment.id, 'success')).toThrow(
        /Invalid deployment status transition/
      );
    });

    it('rejects transitions out of a terminal state (success -> deploying)', () => {
      const driver = DriverAggregate.create(validProps);
      const deployment = driver.addDeployment('device-1');
      driver.updateDeploymentStatus(deployment.id, 'deploying');
      driver.updateDeploymentStatus(deployment.id, 'success');

      expect(() => driver.updateDeploymentStatus(deployment.id, 'deploying')).toThrow(
        /Invalid deployment status transition/
      );
    });

    it('rejects transitions out of a terminal state (failed -> deploying)', () => {
      const driver = DriverAggregate.create(validProps);
      const deployment = driver.addDeployment('device-1');
      driver.updateDeploymentStatus(deployment.id, 'failed', 'nope');

      expect(() => driver.updateDeploymentStatus(deployment.id, 'deploying')).toThrow(
        /Invalid deployment status transition/
      );
    });

    it('rejects an unknown status value', () => {
      const driver = DriverAggregate.create(validProps);
      const deployment = driver.addDeployment('device-1');

      expect(() => driver.updateDeploymentStatus(deployment.id, 'bogus')).toThrow(
        /Invalid deployment status/
      );
    });

    it('returns null when the deployment id is unknown', () => {
      const driver = DriverAggregate.create(validProps);
      driver.addDeployment('device-1');

      expect(driver.updateDeploymentStatus('does-not-exist', 'deploying')).toBeNull();
    });

    it('preserves the previous error when none is provided', () => {
      const driver = DriverAggregate.create(validProps);
      const deployment = driver.addDeployment('device-1');
      driver.updateDeploymentStatus(deployment.id, 'deploying');
      driver.updateDeploymentStatus(deployment.id, 'failed', 'boom');

      const updated = driver.findDeployment(deployment.id);
      expect(updated.error).toBe('boom');
    });
  });

  // ── getDeployments() / findDeployment() ────────────────────────────────────

  describe('getDeployments() / findDeployment()', () => {
    it('returns copies so external mutation does not affect internal state', () => {
      const driver = DriverAggregate.create(validProps);
      driver.addDeployment('device-1');

      const deployments = driver.getDeployments();
      deployments[0].status = 'tampered';

      expect(driver.getDeployments()[0].status).toBe('pending');
    });

    it('findDeployment returns null for an unknown id', () => {
      const driver = DriverAggregate.create(validProps);
      expect(driver.findDeployment('nope')).toBeNull();
    });
  });

  // ── getAndClearDomainEvents() ──────────────────────────────────────────────

  describe('getAndClearDomainEvents()', () => {
    it('returns events and clears them — subsequent call returns []', () => {
      const driver = DriverAggregate.create(validProps);

      const firstCall = driver.getAndClearDomainEvents();
      expect(firstCall.length).toBeGreaterThan(0);

      const secondCall = driver.getAndClearDomainEvents();
      expect(secondCall).toHaveLength(0);
    });
  });

  // ── toJSON() / fromJSON() ──────────────────────────────────────────────────

  describe('toJSON() / fromJSON()', () => {
    it('round-trips through toJSON/fromJSON preserving state and deployments', () => {
      const driver = DriverAggregate.create(validProps);
      driver.addDeployment('device-1');
      driver.getAndClearDomainEvents();

      const restored = DriverAggregate.fromJSON(driver.toJSON());

      expect(restored.id).toBe(driver.id);
      expect(restored.name).toBe(driver.name);
      expect(restored.format).toBe(driver.format);
      expect(restored.deployments).toEqual(driver.deployments);
    });

    it('does not expose internal domain events', () => {
      const driver = DriverAggregate.create(validProps);
      const json = driver.toJSON();
      expect(json).not.toHaveProperty('_domainEvents');
      expect(json).not.toHaveProperty('domainEvents');
    });

    it('fromJSON does not replay domain events', () => {
      const driver = DriverAggregate.create(validProps);
      const restored = DriverAggregate.fromJSON(driver.toJSON());
      expect(restored.getAndClearDomainEvents()).toHaveLength(0);
    });
  });
});
