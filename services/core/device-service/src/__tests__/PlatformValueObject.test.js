'use strict';

const { Platform, VALID_PLATFORMS } = require('../domain/value-objects/Platform');

describe('Platform value object', () => {
  describe('valid platforms', () => {
    VALID_PLATFORMS.forEach(p => {
      it(`accepts '${p}'`, () => {
        const platform = new Platform(p);
        expect(platform.value).toBe(p.toLowerCase());
      });
    });

    it('normalises to lowercase', () => {
      const platform = new Platform('Windows');
      expect(platform.value).toBe('windows');
    });

    it('accepts uppercase MACOS', () => {
      const platform = new Platform('MACOS');
      expect(platform.value).toBe('macos');
    });
  });

  describe('invalid platforms', () => {
    it('throws for unknown platform', () => {
      expect(() => new Platform('solaris')).toThrow('Invalid platform');
    });

    it('throws for empty string', () => {
      expect(() => new Platform('')).toThrow('Invalid platform');
    });

    it('throws for null', () => {
      expect(() => new Platform(null)).toThrow('Invalid platform');
    });

    it('throws for undefined', () => {
      expect(() => new Platform(undefined)).toThrow('Invalid platform');
    });
  });

  describe('accessors', () => {
    it('value getter returns normalised string', () => {
      const p = new Platform('linux');
      expect(p.value).toBe('linux');
    });

    it('toString() returns the value', () => {
      const p = new Platform('ios');
      expect(p.toString()).toBe('ios');
    });
  });

  describe('equals()', () => {
    it('returns true for same platforms', () => {
      const a = new Platform('windows');
      const b = new Platform('WINDOWS');
      expect(a.equals(b)).toBe(true);
    });

    it('returns false for different platforms', () => {
      const a = new Platform('windows');
      const b = new Platform('macos');
      expect(a.equals(b)).toBe(false);
    });

    it('returns false when compared with non-Platform', () => {
      const a = new Platform('linux');
      expect(a.equals('linux')).toBe(false);
      expect(a.equals(null)).toBe(false);
    });
  });

  describe('static isValid()', () => {
    it('returns true for valid platform strings', () => {
      expect(Platform.isValid('windows')).toBe(true);
      expect(Platform.isValid('MACOS')).toBe(true);
    });

    it('returns false for invalid strings', () => {
      expect(Platform.isValid('bsd')).toBe(false);
      expect(Platform.isValid('')).toBe(false);
      expect(Platform.isValid(null)).toBe(false);
    });
  });
});
