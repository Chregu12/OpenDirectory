'use strict';

const DeviceAggregate = require('../domain/aggregates/DeviceAggregate');
const { DeviceEvents } = require('../domain/events/DeviceEvents');

describe('DeviceAggregate', () => {
  const baseProps = {
    id: 'device-1',
    hostname: 'MacBook-Alice',
    platform: 'macos',
  };

  describe('constructor', () => {
    it('sets status to active by default', () => {
      const device = new DeviceAggregate(baseProps);
      expect(device.status).toBe('active');
    });

    it('sets isCompliant to true by default', () => {
      const device = new DeviceAggregate(baseProps);
      expect(device.isCompliant).toBe(true);
    });

    it('sets complianceViolations to [] by default', () => {
      const device = new DeviceAggregate(baseProps);
      expect(device.complianceViolations).toEqual([]);
    });

    it('exposes id, hostname, platform', () => {
      const device = new DeviceAggregate(baseProps);
      expect(device.id).toBe('device-1');
      expect(device.hostname).toBe('MacBook-Alice');
      expect(device.platform).toBe('macos');
    });
  });

  describe('static create()', () => {
    it('creates device with status active and emits DEVICE_ENROLLED', () => {
      const device = DeviceAggregate.create(baseProps);
      expect(device.status).toBe('active');
      const events = device.getAndClearDomainEvents();
      expect(events).toHaveLength(1);
      expect(events[0].type).toBe(DeviceEvents.DEVICE_ENROLLED);
      expect(events[0].payload.deviceId).toBe('device-1');
      expect(events[0].payload.hostname).toBe('MacBook-Alice');
    });
  });

  describe('markCompliant()', () => {
    it('marks device compliant when it was non-compliant and emits DEVICE_COMPLIANT', () => {
      const device = new DeviceAggregate({ ...baseProps, isCompliant: false, complianceViolations: ['disk-encryption'] });
      device.markCompliant();
      expect(device.isCompliant).toBe(true);
      expect(device.complianceViolations).toEqual([]);
      const events = device.getAndClearDomainEvents();
      expect(events[0].type).toBe(DeviceEvents.DEVICE_COMPLIANT);
    });

    it('is a no-op (no event) when already compliant', () => {
      const device = new DeviceAggregate({ ...baseProps, isCompliant: true });
      device.markCompliant();
      expect(device.getAndClearDomainEvents()).toHaveLength(0);
    });

    it('returns device for chaining', () => {
      const device = new DeviceAggregate({ ...baseProps, isCompliant: false });
      expect(device.markCompliant()).toBe(device);
    });
  });

  describe('markNonCompliant()', () => {
    it('sets isCompliant to false with violations and emits DEVICE_NON_COMPLIANT', () => {
      const violations = ['no-antivirus', 'disk-not-encrypted'];
      const device = new DeviceAggregate(baseProps);
      device.markNonCompliant(violations);
      expect(device.isCompliant).toBe(false);
      expect(device.complianceViolations).toEqual(violations);
      const events = device.getAndClearDomainEvents();
      expect(events[0].type).toBe(DeviceEvents.DEVICE_NON_COMPLIANT);
      expect(events[0].payload.violations).toEqual(violations);
    });

    it('always emits event even if already non-compliant', () => {
      const device = new DeviceAggregate({ ...baseProps, isCompliant: false });
      device.markNonCompliant(['v1']);
      expect(device.getAndClearDomainEvents()).toHaveLength(1);
    });
  });

  describe('updateLastSeen()', () => {
    it('updates lastSeen timestamp', () => {
      const device = new DeviceAggregate(baseProps);
      expect(device.lastSeen).toBeNull();
      device.updateLastSeen();
      expect(device.lastSeen).toBeInstanceOf(Date);
    });

    it('returns device for chaining', () => {
      const device = new DeviceAggregate(baseProps);
      expect(device.updateLastSeen()).toBe(device);
    });
  });

  describe('retire()', () => {
    it('sets status to retired and emits DEVICE_RETIRED', () => {
      const device = new DeviceAggregate(baseProps);
      device.retire();
      expect(device.status).toBe('retired');
      const events = device.getAndClearDomainEvents();
      expect(events[0].type).toBe(DeviceEvents.DEVICE_RETIRED);
    });

    it('returns device for chaining', () => {
      const device = new DeviceAggregate(baseProps);
      expect(device.retire()).toBe(device);
    });
  });

  describe('getAndClearDomainEvents()', () => {
    it('returns events then clears them', () => {
      const device = DeviceAggregate.create(baseProps);
      const events = device.getAndClearDomainEvents();
      expect(events).toHaveLength(1);
      expect(device.getAndClearDomainEvents()).toHaveLength(0);
    });
  });

  describe('toJSON()', () => {
    it('returns a plain object with all expected fields', () => {
      const device = new DeviceAggregate({ ...baseProps, status: 'active', isCompliant: true });
      const json = device.toJSON();
      expect(json).toMatchObject({
        id: 'device-1',
        hostname: 'MacBook-Alice',
        platform: 'macos',
        status: 'active',
        isCompliant: true,
      });
    });

    it('includes complianceViolations, lastSeen, and enrolledAt fields', () => {
      const device = new DeviceAggregate({
        ...baseProps,
        isCompliant: false,
        complianceViolations: ['no-antivirus'],
      });
      const json = device.toJSON();
      expect(json).toHaveProperty('complianceViolations');
      expect(json).toHaveProperty('lastSeen');
      expect(json).toHaveProperty('enrolledAt');
    });

    it('does not expose internal domain events', () => {
      const device = DeviceAggregate.create(baseProps);
      const json = device.toJSON();
      expect(json).not.toHaveProperty('_domainEvents');
      expect(json).not.toHaveProperty('domainEvents');
    });

    it('reflects updated state after mutations', () => {
      const device = new DeviceAggregate(baseProps);
      device.retire();
      device.getAndClearDomainEvents(); // clear
      const json = device.toJSON();
      expect(json.status).toBe('retired');
    });
  });

  describe('retire() — additional edge cases', () => {
    it('is callable a second time without throwing (idempotent status)', () => {
      const device = new DeviceAggregate(baseProps);
      device.retire();
      device.getAndClearDomainEvents();
      expect(() => device.retire()).not.toThrow();
      expect(device.status).toBe('retired');
    });

    it('emits DEVICE_RETIRED event on each call', () => {
      const device = new DeviceAggregate(baseProps);
      device.retire();
      device.getAndClearDomainEvents();
      device.retire();
      const events = device.getAndClearDomainEvents();
      expect(events[0].type).toBe(DeviceEvents.DEVICE_RETIRED);
    });

    it('event payload contains deviceId', () => {
      const device = new DeviceAggregate(baseProps);
      device.retire();
      const events = device.getAndClearDomainEvents();
      expect(events[0].payload).toHaveProperty('deviceId', 'device-1');
    });
  });

  describe('markNonCompliant() — additional edge cases', () => {
    it('updates violations when called multiple times', () => {
      const device = new DeviceAggregate(baseProps);
      device.markNonCompliant(['v1']);
      device.getAndClearDomainEvents();
      device.markNonCompliant(['v2', 'v3']);
      expect(device.complianceViolations).toEqual(['v2', 'v3']);
    });

    it('defaults to empty array when called without argument', () => {
      const device = new DeviceAggregate(baseProps);
      device.markNonCompliant();
      expect(device.isCompliant).toBe(false);
      expect(device.complianceViolations).toEqual([]);
    });

    it('returns device for chaining', () => {
      const device = new DeviceAggregate(baseProps);
      expect(device.markNonCompliant(['v1'])).toBe(device);
    });
  });

  describe('complianceViolations getter', () => {
    it('returns a copy so mutations do not affect internal state', () => {
      const device = new DeviceAggregate({
        ...baseProps,
        complianceViolations: ['original'],
      });
      const violations = device.complianceViolations;
      violations.push('injected');
      expect(device.complianceViolations).toEqual(['original']);
    });
  });
});
