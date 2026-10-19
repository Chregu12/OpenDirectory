'use strict';

// Sanitizes a raw identifier (hostname or deviceId) into a safe cache/file key.
// Moved from deviceDetectionRoutes.js — same behaviour, lowercase + [a-z0-9_-] only.
function sanitizeKey(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9_-]/g, '_');
}

class HardwareProfile {
  constructor(props = {}) {
    this._hostname = props.hostname || null;
    this._deviceId = props.deviceId || null;
    this._manufacturer = props.manufacturer || null;
    this._model = props.model || null;
    this._os = props.os || null;
    this._osVersion = props.osVersion || null;
    this._hardwareIds = Array.isArray(props.hardwareIds) ? [...props.hardwareIds] : [];

    const rawKey = this._deviceId || this._hostname;
    if (!rawKey) {
      throw new Error('HardwareProfile requires a hostname or deviceId');
    }
    this._key = sanitizeKey(rawKey);
    if (!this._key) {
      throw new Error('HardwareProfile requires a hostname or deviceId');
    }
  }

  get key() { return this._key; }
  get hostname() { return this._hostname; }
  get deviceId() { return this._deviceId; }
  get manufacturer() { return this._manufacturer; }
  get model() { return this._model; }
  get os() { return this._os; }
  get osVersion() { return this._osVersion; }
  get hardwareIds() { return [...this._hardwareIds]; }

  toJSON() {
    return {
      hostname: this._hostname,
      deviceId: this._deviceId,
      manufacturer: this._manufacturer,
      model: this._model,
      os: this._os,
      osVersion: this._osVersion,
      hardwareIds: this._hardwareIds,
    };
  }

  static sanitizeKey(value) { return sanitizeKey(value); }
}

module.exports = { HardwareProfile, sanitizeKey };
