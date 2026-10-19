'use strict';

const Email = require('../domain/value-objects/Email');

describe('Email value object', () => {
  describe('valid emails', () => {
    it('creates an Email for a standard address', () => {
      const email = new Email('user@example.com');
      expect(email.value).toBe('user@example.com');
    });

    it('normalises to lowercase', () => {
      const email = new Email('User@EXAMPLE.COM');
      expect(email.value).toBe('user@example.com');
    });

    it('accepts subdomains', () => {
      const email = new Email('user@mail.example.co.uk');
      expect(email.value).toBe('user@mail.example.co.uk');
    });

    it('accepts + in local part', () => {
      const email = new Email('user+tag@example.com');
      expect(email.value).toBe('user+tag@example.com');
    });
  });

  describe('invalid emails', () => {
    it('throws for empty string', () => {
      expect(() => new Email('')).toThrow('Invalid email address');
    });

    it('throws for null', () => {
      expect(() => new Email(null)).toThrow('Invalid email address');
    });

    it('throws for undefined', () => {
      expect(() => new Email(undefined)).toThrow('Invalid email address');
    });

    it('throws for missing @', () => {
      expect(() => new Email('userexample.com')).toThrow('Invalid email address');
    });

    it('throws for missing domain', () => {
      expect(() => new Email('user@')).toThrow('Invalid email address');
    });

    it('throws for missing TLD', () => {
      expect(() => new Email('user@example')).toThrow('Invalid email address');
    });

    it('throws for address with spaces', () => {
      expect(() => new Email('user @example.com')).toThrow('Invalid email address');
    });
  });

  describe('value accessors', () => {
    it('toString() returns the value', () => {
      const email = new Email('test@test.com');
      expect(email.toString()).toBe('test@test.com');
    });
  });

  describe('equals()', () => {
    it('returns true for two equal emails', () => {
      const a = new Email('user@example.com');
      const b = new Email('USER@EXAMPLE.COM');
      expect(a.equals(b)).toBe(true);
    });

    it('returns false for different emails', () => {
      const a = new Email('a@example.com');
      const b = new Email('b@example.com');
      expect(a.equals(b)).toBe(false);
    });

    it('returns false when comparing with non-Email', () => {
      const a = new Email('user@example.com');
      expect(a.equals('user@example.com')).toBe(false);
      expect(a.equals(null)).toBe(false);
    });
  });
});
