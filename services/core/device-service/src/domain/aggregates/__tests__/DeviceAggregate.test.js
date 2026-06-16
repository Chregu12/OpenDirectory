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
});
