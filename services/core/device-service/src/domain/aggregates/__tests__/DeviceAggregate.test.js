'use strict';

const DeviceAggregate = require('../DeviceAggregate');
const { DeviceEvents } = require('../../events/DeviceEvents');

describe('DeviceAggregate', () => {
  const validProps = {
    id:       'device-1',
    hostname: 'MacBook-Pro-Jane',
    platform: 'macos'
  };

  // ── create() ───────────────────────────────────────────────────────────────

  describe('create()', () => {
    it('returns a DeviceAggregate with status "active"', () => {
      const device = DeviceAggregate.create(validProps);

      expect(device).toBeInstanceOf(DeviceAggregate);
      expect(device.id).toBe('device-1');
      expect(device.hostname).toBe('MacBook-Pro-Jane');
      expect(device.platform).toBe('macos');
      expect(device.status).toBe('active');
      expect(device.isCompliant).toBe(true);
    });

    it('emits a DEVICE_ENROLLED event with occurredAt and eventId', () => {
      const device = DeviceAggregate.create(validProps);
      const events = device.getAndClearDomainEvents();

      expect(events).toHaveLength(1);
      const [evt] = events;
      expect(evt.type).toBe(DeviceEvents.DEVICE_ENROLLED);
      expect(evt.occurredAt).toBeInstanceOf(Date);
      expect(typeof evt.eventId).toBe('string');
      expect(evt.eventId).toBeTruthy();
      expect(evt.payload.deviceId).toBe('device-1');
      expect(evt.payload.hostname).toBe('MacBook-Pro-Jane');
    });
  });

  // ── markNonCompliant() ─────────────────────────────────────────────────────

  describe('markNonCompliant(violations)', () => {
    it('sets isCompliant to false and stores violations', () => {
      const device = DeviceAggregate.create(validProps);
      device.getAndClearDomainEvents();

      device.markNonCompliant(['screen-lock-disabled', 'outdated-os']);

      expect(device.isCompliant).toBe(false);
      expect(device.complianceViolations).toEqual(['screen-lock-disabled', 'outdated-os']);
    });

    it('emits a DEVICE_NON_COMPLIANT event with occurredAt and eventId', () => {
      const device = DeviceAggregate.create(validProps);
      device.getAndClearDomainEvents();

      device.markNonCompliant(['firewall-off']);
      const events = device.getAndClearDomainEvents();

      const evt = events.find(e => e.type === DeviceEvents.DEVICE_NON_COMPLIANT);
      expect(evt).toBeDefined();
      expect(evt.occurredAt).toBeInstanceOf(Date);
      expect(evt.eventId).toBeTruthy();
      expect(evt.payload.violations).toEqual(['firewall-off']);
    });
  });

  // ── markCompliant() ────────────────────────────────────────────────────────

  describe('markCompliant()', () => {
    it('sets isCompliant to true and clears violations', () => {
      const device = DeviceAggregate.create(validProps);
      device.markNonCompliant(['firewall-off']);
      device.getAndClearDomainEvents();

      device.markCompliant();

      expect(device.isCompliant).toBe(true);
      expect(device.complianceViolations).toHaveLength(0);
    });

    it('emits a DEVICE_COMPLIANT event with occurredAt and eventId', () => {
      const device = DeviceAggregate.create(validProps);
      device.markNonCompliant(['issue']);
      device.getAndClearDomainEvents();

      device.markCompliant();
      const events = device.getAndClearDomainEvents();

      const evt = events.find(e => e.type === DeviceEvents.DEVICE_COMPLIANT);
      expect(evt).toBeDefined();
      expect(evt.occurredAt).toBeInstanceOf(Date);
      expect(evt.eventId).toBeTruthy();
    });

    it('is a no-op when device is already compliant', () => {
      const device = DeviceAggregate.create(validProps);
      device.getAndClearDomainEvents();

      device.markCompliant(); // already compliant
      const events = device.getAndClearDomainEvents();
      expect(events.some(e => e.type === DeviceEvents.DEVICE_COMPLIANT)).toBe(false);
    });
  });

  // ── retire() ───────────────────────────────────────────────────────────────

  describe('retire()', () => {
    it('sets status to "retired"', () => {
      const device = DeviceAggregate.create(validProps);
      device.getAndClearDomainEvents();

      device.retire();

      expect(device.status).toBe('retired');
    });

    it('emits a DEVICE_RETIRED event with occurredAt and eventId', () => {
      const device = DeviceAggregate.create(validProps);
      device.getAndClearDomainEvents();

      device.retire();
      const events = device.getAndClearDomainEvents();

      const evt = events.find(e => e.type === DeviceEvents.DEVICE_RETIRED);
      expect(evt).toBeDefined();
      expect(evt.occurredAt).toBeInstanceOf(Date);
      expect(evt.eventId).toBeTruthy();
    });
  });

  // ── lock() ─────────────────────────────────────────────────────────────────

  describe('lock(reason)', () => {
    it('sets status to "locked"', () => {
      const device = DeviceAggregate.create(validProps);
      device.getAndClearDomainEvents();

      device.lock('Lost device');

      expect(device.status).toBe('locked');
    });

    it('emits a DEVICE_LOCKED event with reason, occurredAt, and eventId', () => {
      const device = DeviceAggregate.create(validProps);
      device.getAndClearDomainEvents();

      device.lock('Theft reported');
      const events = device.getAndClearDomainEvents();

      const evt = events.find(e => e.type === DeviceEvents.DEVICE_LOCKED);
      expect(evt).toBeDefined();
      expect(evt.occurredAt).toBeInstanceOf(Date);
      expect(evt.eventId).toBeTruthy();
      expect(evt.payload.reason).toBe('Theft reported');
    });
  });

  // ── getAndClearDomainEvents() ──────────────────────────────────────────────

  describe('getAndClearDomainEvents()', () => {
    it('returns events and clears them — subsequent call returns []', () => {
      const device = DeviceAggregate.create(validProps);

      const firstCall = device.getAndClearDomainEvents();
      expect(firstCall.length).toBeGreaterThan(0);

      const secondCall = device.getAndClearDomainEvents();
      expect(secondCall).toHaveLength(0);
    });
  });

  // ── system info fields (os, osVersion, ipAddress, kernel, packageManager) ──

  describe('system info fields', () => {
    it('default to null when not provided', () => {
      const device = new DeviceAggregate(validProps);
      expect(device.os).toBeNull();
      expect(device.osVersion).toBeNull();
      expect(device.ipAddress).toBeNull();
      expect(device.kernel).toBeNull();
      expect(device.packageManager).toBeNull();
    });

    it('are settable via constructor props', () => {
      const device = new DeviceAggregate({
        ...validProps,
        os: 'linux',
        osVersion: '22.04',
        ipAddress: '10.0.0.5',
        kernel: '5.15.0',
        packageManager: 'apt',
      });
      expect(device.os).toBe('linux');
      expect(device.osVersion).toBe('22.04');
      expect(device.ipAddress).toBe('10.0.0.5');
      expect(device.kernel).toBe('5.15.0');
      expect(device.packageManager).toBe('apt');
    });

    it('round-trip through toJSON()', () => {
      const device = new DeviceAggregate({
        ...validProps,
        os: 'macos',
        osVersion: '14.4',
        ipAddress: '192.168.1.10',
        kernel: 'Darwin 23.4.0',
        packageManager: 'brew',
      });
      const json = device.toJSON();
      expect(json.os).toBe('macos');
      expect(json.osVersion).toBe('14.4');
      expect(json.ipAddress).toBe('192.168.1.10');
      expect(json.kernel).toBe('Darwin 23.4.0');
      expect(json.packageManager).toBe('brew');
    });

    it('round-trip through toJSON()/fromJSON()', () => {
      const device = new DeviceAggregate({
        ...validProps,
        os: 'windows',
        osVersion: '11',
        ipAddress: '172.16.0.1',
        kernel: '10.0.22631',
        packageManager: 'winget',
      });
      const restored = DeviceAggregate.fromJSON(device.toJSON());
      expect(restored.os).toBe('windows');
      expect(restored.osVersion).toBe('11');
      expect(restored.ipAddress).toBe('172.16.0.1');
      expect(restored.kernel).toBe('10.0.22631');
      expect(restored.packageManager).toBe('winget');
    });

    it('updateSystemInfo() updates only the provided fields', () => {
      const device = new DeviceAggregate({ ...validProps, os: 'linux', osVersion: '20.04' });
      device.updateSystemInfo({ osVersion: '22.04', ipAddress: '10.0.0.1' });
      expect(device.os).toBe('linux');
      expect(device.osVersion).toBe('22.04');
      expect(device.ipAddress).toBe('10.0.0.1');
    });

    it('updateSystemInfo() returns device for chaining', () => {
      const device = new DeviceAggregate(validProps);
      expect(device.updateSystemInfo({ os: 'linux' })).toBe(device);
    });
  });

  // ── complianceScore ──────────────────────────────────────────────────────

  describe('complianceScore', () => {
    it('is 100 when the device is compliant', () => {
      const device = new DeviceAggregate({ ...validProps, isCompliant: true, complianceViolations: [] });
      expect(device.complianceScore).toBe(100);
    });

    it('is 75 when non-compliant with 1 violation', () => {
      const device = new DeviceAggregate({ ...validProps, isCompliant: false, complianceViolations: ['v1'] });
      expect(device.complianceScore).toBe(75);
    });

    it('is 0 when non-compliant with 5 (or more) violations', () => {
      const device = new DeviceAggregate({
        ...validProps,
        isCompliant: false,
        complianceViolations: ['v1', 'v2', 'v3', 'v4', 'v5'],
      });
      expect(device.complianceScore).toBe(0);
    });

    it('is included in toJSON()', () => {
      const device = new DeviceAggregate({ ...validProps, isCompliant: false, complianceViolations: ['v1', 'v2'] });
      expect(device.toJSON().complianceScore).toBe(50);
    });

    it('updates dynamically after markNonCompliant()/markCompliant()', () => {
      const device = DeviceAggregate.create(validProps);
      expect(device.complianceScore).toBe(100);

      device.markNonCompliant(['v1', 'v2', 'v3']);
      expect(device.complianceScore).toBe(25);

      device.markCompliant();
      expect(device.complianceScore).toBe(100);
    });
  });
});
