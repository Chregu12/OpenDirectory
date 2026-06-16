'use strict';

const DeviceAggregate = require('../DeviceAggregate');
const { DeviceEvents } = DeviceAggregate;

describe('DeviceAggregate', () => {
  const validProps = {
    id:           'device-1',
    name:         'MacBook Pro — Jane',
    platform:     'macos',
    serialNumber: 'C02ABC123',
    ownerId:      'user-42'
  };

  // ── create() ───────────────────────────────────────────────────────────────

  describe('create()', () => {
    it('returns a DeviceAggregate with status "active"', () => {
      const device = DeviceAggregate.create(validProps);

      expect(device).toBeInstanceOf(DeviceAggregate);
      expect(device.id).toBe('device-1');
      expect(device.name).toBe('MacBook Pro — Jane');
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
    });

    it('throws when name is missing', () => {
      expect(() => DeviceAggregate.create({ platform: 'macos' })).toThrow('name');
    });

    it('throws when platform is missing', () => {
      expect(() => DeviceAggregate.create({ name: 'My Device' })).toThrow('platform');
    });
  });

  // ── markNonCompliant() ─────────────────────────────────────────────────────

  describe('markNonCompliant(violations)', () => {
    it('sets isCompliant to false and stores violations', () => {
      const device = DeviceAggregate.create(validProps);
      device.getAndClearDomainEvents();

      device.markNonCompliant(['screen-lock-disabled', 'outdated-os']);

      expect(device.isCompliant).toBe(false);
      expect(device.violations).toEqual(['screen-lock-disabled', 'outdated-os']);
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
      expect(device.violations).toHaveLength(0);
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
  });

  // ── retire() ───────────────────────────────────────────────────────────────

  describe('retire()', () => {
    it('sets status to "retired"', () => {
      const device = DeviceAggregate.create(validProps);
      device.getAndClearDomainEvents();

      device.retire();

      expect(device.status).toBe('retired');
    });

    it('emits a DEVICE_RETIRED event', () => {
      const device = DeviceAggregate.create(validProps);
      device.getAndClearDomainEvents();

      device.retire();
      const events = device.getAndClearDomainEvents();

      const evt = events.find(e => e.type === DeviceEvents.DEVICE_RETIRED);
      expect(evt).toBeDefined();
      expect(evt.occurredAt).toBeInstanceOf(Date);
      expect(evt.eventId).toBeTruthy();
    });

    it('is idempotent — second call produces no event', () => {
      const device = DeviceAggregate.create(validProps);
      device.retire();
      device.getAndClearDomainEvents();

      device.retire(); // second call
      const events = device.getAndClearDomainEvents();
      expect(events.some(e => e.type === DeviceEvents.DEVICE_RETIRED)).toBe(false);
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

    it('is idempotent — second call produces no event', () => {
      const device = DeviceAggregate.create(validProps);
      device.lock('reason');
      device.getAndClearDomainEvents();

      device.lock('another reason');
      const events = device.getAndClearDomainEvents();
      expect(events.some(e => e.type === DeviceEvents.DEVICE_LOCKED)).toBe(false);
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
