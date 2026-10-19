'use strict';

const UserId = require('../domain/value-objects/UserId');

describe('UserId value object', () => {
  const validUUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';

  describe('constructor', () => {
    it('creates a UserId from a valid UUID string', () => {
      const id = new UserId(validUUID);
      expect(id.value).toBe(validUUID);
    });

    it('throws when value is an empty string', () => {
      expect(() => new UserId('')).toThrow('UserId value is required');
    });

    it('throws when value is undefined', () => {
      expect(() => new UserId(undefined)).toThrow('UserId value is required');
    });

    it('throws when value is null', () => {
      expect(() => new UserId(null)).toThrow('UserId value is required');
    });

    it('throws when value is 0 (falsy non-string)', () => {
      expect(() => new UserId(0)).toThrow('UserId value is required');
    });
  });

  describe('value getter', () => {
    it('returns the original string passed at construction', () => {
      const id = new UserId(validUUID);
      expect(id.value).toBe(validUUID);
    });
  });

  describe('toString()', () => {
    it('returns the UUID string', () => {
      const id = new UserId(validUUID);
      expect(id.toString()).toBe(validUUID);
    });

    it('works correctly in template literals', () => {
      const id = new UserId(validUUID);
      expect(`${id}`).toBe(validUUID);
    });
  });

  describe('equals()', () => {
    it('returns true when two UserId instances have the same value', () => {
      const a = new UserId(validUUID);
      const b = new UserId(validUUID);
      expect(a.equals(b)).toBe(true);
    });

    it('returns false when two UserId instances have different values', () => {
      const a = new UserId(validUUID);
      const b = new UserId('00000000-0000-0000-0000-000000000000');
      expect(a.equals(b)).toBe(false);
    });

    it('returns false when compared to a plain string', () => {
      const id = new UserId(validUUID);
      expect(id.equals(validUUID)).toBe(false);
    });

    it('returns false when compared to null', () => {
      const id = new UserId(validUUID);
      expect(id.equals(null)).toBe(false);
    });

    it('is reflexively equal to itself', () => {
      const id = new UserId(validUUID);
      expect(id.equals(id)).toBe(true);
    });
  });

  describe('static generate()', () => {
    it('returns a UserId instance', () => {
      const id = UserId.generate();
      expect(id).toBeInstanceOf(UserId);
    });

    it('generates a non-empty string value', () => {
      const id = UserId.generate();
      expect(typeof id.value).toBe('string');
      expect(id.value.length).toBeGreaterThan(0);
    });

    it('generates unique IDs on each call', () => {
      const a = UserId.generate();
      const b = UserId.generate();
      expect(a.equals(b)).toBe(false);
    });

    it('generates a UUID-formatted string (8-4-4-4-12)', () => {
      const id = UserId.generate();
      expect(id.value).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    });
  });
});
