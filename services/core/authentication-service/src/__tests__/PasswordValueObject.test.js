'use strict';

const Password = require('../domain/value-objects/Password');

describe('Password value object', () => {
  describe('fromPlaintext()', () => {
    it('creates a Password from a valid plaintext', async () => {
      const pw = await Password.fromPlaintext('SecurePass1');
      expect(pw).toBeInstanceOf(Password);
      expect(typeof pw.hash).toBe('string');
      expect(pw.hash).toContain(':'); // salt:hash format
    });

    it('throws for plaintext shorter than 8 characters', async () => {
      await expect(Password.fromPlaintext('short')).rejects.toThrow('at least 8 characters');
    });

    it('throws for empty string', async () => {
      await expect(Password.fromPlaintext('')).rejects.toThrow('at least 8 characters');
    });

    it('throws for null', async () => {
      await expect(Password.fromPlaintext(null)).rejects.toThrow('at least 8 characters');
    });

    it('produces different hashes for the same plaintext (salt is random)', async () => {
      const pw1 = await Password.fromPlaintext('SamePassword!');
      const pw2 = await Password.fromPlaintext('SamePassword!');
      expect(pw1.hash).not.toBe(pw2.hash);
    });
  });

  describe('fromHash()', () => {
    it('wraps an existing hash string', () => {
      const pw = Password.fromHash('salt:hashedvalue');
      expect(pw).toBeInstanceOf(Password);
      expect(pw.hash).toBe('salt:hashedvalue');
    });
  });

  describe('verify()', () => {
    it('returns true for matching plaintext', async () => {
      const pw = await Password.fromPlaintext('CorrectPassword!');
      const result = await pw.verify('CorrectPassword!');
      expect(result).toBe(true);
    });

    it('returns false for wrong plaintext', async () => {
      const pw = await Password.fromPlaintext('CorrectPassword!');
      const result = await pw.verify('WrongPassword!');
      expect(result).toBe(false);
    });
  });

  describe('hash getter', () => {
    it('exposes the hash string', async () => {
      const pw = await Password.fromPlaintext('TestPassword');
      expect(pw.hash).toBeTruthy();
    });
  });
});
