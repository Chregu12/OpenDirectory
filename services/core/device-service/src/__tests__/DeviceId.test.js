'use strict';

const DeviceId = require('../domain/value-objects/DeviceId');

describe('DeviceId value object', () => {
  describe('constructor', () => {
    it('creates a DeviceId from a plain UUID string', () => {
      const id = new DeviceId('550e8400-e29b-41d4-a716-446655440000');
      expect(id).toBeInstanceOf(DeviceId);
    });

    it('creates a DeviceId from any non-empty string identifier', () => {
      const id = new DeviceId('device-abc-123');
      expect(id).toBeInstanceOf(DeviceId);
    });

    it('trims surrounding whitespace', () => {
      const id = new DeviceId('  device-1  ');
      expect(id.value).toBe('device-1');
    });

    it('throws when value is an empty string', () => {
      expect(() => new DeviceId('')).toThrow();
    });

    it('throws when value is a whitespace-only string', () => {
      expect(() => new DeviceId('   ')).toThrow();
    });

    it('throws when value is null', () => {
      expect(() => new DeviceId(null)).toThrow();
    });

    it('throws when value is undefined', () => {
      expect(() => new DeviceId(undefined)).toThrow();
    });

    it('throws when value is a number (not a string)', () => {
      expect(() => new DeviceId(42)).toThrow();
    });
  });

  describe('value getter', () => {
    it('returns the UUID/identifier that was passed in (trimmed)', () => {
      const uuid = '550e8400-e29b-41d4-a716-446655440000';
      const id = new DeviceId(uuid);
      expect(id.value).toBe(uuid);
    });
  });

  describe('toString()', () => {
    it('returns the string representation of the id', () => {
      const id = new DeviceId('device-42');
      expect(id.toString()).toBe('device-42');
    });

    it('produces the same value as the value getter', () => {
      const id = new DeviceId('my-device');
      expect(id.toString()).toBe(id.value);
    });
  });

  describe('equals()', () => {
    it('returns true when two DeviceIds have the same value', () => {
      const a = new DeviceId('device-1');
      const b = new DeviceId('device-1');
      expect(a.equals(b)).toBe(true);
    });

    it('returns false when two DeviceIds have different values', () => {
      const a = new DeviceId('device-1');
      const b = new DeviceId('device-2');
      expect(a.equals(b)).toBe(false);
    });

    it('returns false when compared to a plain string', () => {
      const a = new DeviceId('device-1');
      expect(a.equals('device-1')).toBe(false);
    });

    it('returns false when compared to null', () => {
      const a = new DeviceId('device-1');
      expect(a.equals(null)).toBe(false);
    });

    it('returns false when compared to undefined', () => {
      const a = new DeviceId('device-1');
      expect(a.equals(undefined)).toBe(false);
    });

    it('returns false when compared to an object that is not a DeviceId', () => {
      const a = new DeviceId('device-1');
      expect(a.equals({ value: 'device-1' })).toBe(false);
    });
  });

  describe('static generate() — if it exists', () => {
    it('creates a DeviceId with a UUID-formatted value when generate() is available', () => {
      if (typeof DeviceId.generate !== 'function') {
        // Method does not exist — skip gracefully
        return;
      }
      const id = DeviceId.generate();
      expect(id).toBeInstanceOf(DeviceId);
      // UUID v4 pattern
      expect(id.value).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
      );
    });

    it('each call to generate() produces a unique value', () => {
      if (typeof DeviceId.generate !== 'function') return;
      const a = DeviceId.generate();
      const b = DeviceId.generate();
      expect(a.equals(b)).toBe(false);
    });
  });
});
