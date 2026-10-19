'use strict';
const { randomUUID } = require('crypto');

class UserId {
  constructor(value) {
    if (!value) throw new Error('UserId value is required');
    this._value = value;
  }

  static generate() {
    return new UserId(randomUUID());
  }

  get value() { return this._value; }
  toString() { return this._value; }
  equals(other) { return other instanceof UserId && other._value === this._value; }
}
module.exports = UserId;
