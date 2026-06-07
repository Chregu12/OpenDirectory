'use strict';

class DeviceId {
  constructor(value) {
    if (!value || typeof value !== 'string' || value.trim().length === 0) {
      throw new Error('DeviceId must be a non-empty string');
    }
    this._value = value.trim();
  }
  get value() { return this._value; }
  toString() { return this._value; }
  equals(other) { return other instanceof DeviceId && other._value === this._value; }
}

module.exports = DeviceId;
