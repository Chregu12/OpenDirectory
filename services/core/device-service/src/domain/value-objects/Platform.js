'use strict';

const VALID_PLATFORMS = ['windows', 'macos', 'linux', 'ios', 'android', 'all'];

class Platform {
  constructor(value) {
    const normalized = (value || '').toLowerCase();
    if (!VALID_PLATFORMS.includes(normalized)) {
      throw new Error(`Invalid platform: ${value}. Must be one of: ${VALID_PLATFORMS.join(', ')}`);
    }
    this._value = normalized;
  }
  get value() { return this._value; }
  toString() { return this._value; }
  equals(other) { return other instanceof Platform && other._value === this._value; }
  static isValid(value) { return VALID_PLATFORMS.includes((value || '').toLowerCase()); }
}

module.exports = { Platform, VALID_PLATFORMS };
