'use strict';
const crypto = require('crypto');

class Password {
  constructor(hashedValue) {
    this._hash = hashedValue;
  }
  get hash() { return this._hash; }

  static async fromPlaintext(plaintext) {
    if (!plaintext || plaintext.length < 8) throw new Error('Password must be at least 8 characters');
    // Use crypto.scrypt for hashing — no external deps
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = await new Promise((resolve, reject) => {
      crypto.scrypt(plaintext, salt, 64, (err, derived) => {
        if (err) reject(err);
        else resolve(`${salt}:${derived.toString('hex')}`);
      });
    });
    return new Password(hash);
  }

  async verify(plaintext) {
    const [salt, stored] = this._hash.split(':');
    const derived = await new Promise((resolve, reject) => {
      crypto.scrypt(plaintext, salt, 64, (err, d) => {
        if (err) reject(err);
        else resolve(d.toString('hex'));
      });
    });
    return derived === stored;
  }

  static fromHash(hash) { return new Password(hash); }
}
module.exports = Password;
