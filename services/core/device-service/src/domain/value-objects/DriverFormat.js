'use strict';

const VALID_FORMATS = [
  'inf', 'exe', 'msi', 'deb', 'rpm', 'run', 'dmg', 'pkg',
  'zip', 'cab', 'ppd', 'bin', 'sys', 'ko', 'tar', 'gz',
];

class DriverFormat {
  constructor(value) {
    const normalized = String(value || '').trim().toLowerCase().replace(/^\./, '');
    if (!VALID_FORMATS.includes(normalized)) {
      throw new Error(`Invalid driver format: ${value}. Must be one of: ${VALID_FORMATS.join(', ')}`);
    }
    this._value = normalized;
  }
  get value() { return this._value; }
  toString() { return this._value; }
  equals(other) { return other instanceof DriverFormat && other._value === this._value; }
  static isValid(value) {
    const normalized = String(value || '').trim().toLowerCase().replace(/^\./, '');
    return VALID_FORMATS.includes(normalized);
  }
}

module.exports = { DriverFormat, VALID_FORMATS };
