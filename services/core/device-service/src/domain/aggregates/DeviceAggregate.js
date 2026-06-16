'use strict';

const { randomUUID } = require('crypto');

/**
 * Domain event type constants for the device service.
 */
const DeviceEvents = {
  DEVICE_ENROLLED:      'device.enrolled',
  DEVICE_UPDATED:       'device.updated',
  DEVICE_RETIRED:       'device.retired',
  DEVICE_LOCKED:        'device.locked',
  DEVICE_COMPLIANT:     'device.compliant',
  DEVICE_NON_COMPLIANT: 'device.non_compliant',
};

/**
 * DeviceAggregate — Aggregate Root for a managed device.
 *
 * Encapsulates all state transitions and domain events for a device.
 * Consumers must always go through public command methods rather than
 * mutating properties directly.
 */
class DeviceAggregate {
  /**
   * @param {object} data
   */
  constructor(data) {
    this._validate(data);
    this.id           = data.id || null;
    this.name         = data.name;
    this.platform     = data.platform;            // 'macos' | 'windows' | 'linux' | 'ios' | 'android'
    this.serialNumber = data.serialNumber || null;
    this.status       = data.status || 'active';  // 'active' | 'retired' | 'locked'
    this.isCompliant  = data.isCompliant !== undefined ? !!data.isCompliant : true;
    this.violations   = Array.isArray(data.violations) ? [...data.violations] : [];
    this.ownerId      = data.ownerId || null;
    this.enrolledAt   = data.enrolledAt ? new Date(data.enrolledAt) : new Date();
    this.updatedAt    = data.updatedAt  ? new Date(data.updatedAt)  : new Date();
    this._domainEvents = [];
  }

  // ── Factory ────────────────────────────────────────────────────────────────

  /**
   * Enroll a new device and record a DEVICE_ENROLLED domain event.
   * @param {object} props
   * @returns {DeviceAggregate}
   */
  static create(props) {
    const device = new DeviceAggregate(props);
    device._addDomainEvent(DeviceEvents.DEVICE_ENROLLED, {
      deviceId:     device.id,
      name:         device.name,
      platform:     device.platform,
      serialNumber: device.serialNumber,
      ownerId:      device.ownerId
    });
    return device;
  }

  /**
   * Reconstitute a device from a persisted row (no domain event emitted).
   * @param {object} row
   * @returns {DeviceAggregate}
   */
  static fromRow(row) {
    return new DeviceAggregate({
      id:           row.id,
      name:         row.name,
      platform:     row.platform,
      serialNumber: row.serial_number || row.serialNumber,
      status:       row.status,
      isCompliant:  row.is_compliant !== undefined ? row.is_compliant : row.isCompliant,
      violations:   row.violations || [],
      ownerId:      row.owner_id || row.ownerId,
      enrolledAt:   row.enrolled_at || row.enrolledAt,
      updatedAt:    row.updated_at  || row.updatedAt
    });
  }

  // ── Commands ───────────────────────────────────────────────────────────────

  /**
   * Mark the device as non-compliant with a list of policy violations.
   * @param {string[]} violations
   */
  markNonCompliant(violations) {
    this.isCompliant = false;
    this.violations  = Array.isArray(violations) ? [...violations] : [];
    this.updatedAt   = new Date();

    this._addDomainEvent(DeviceEvents.DEVICE_NON_COMPLIANT, {
      deviceId:   this.id,
      violations: this.violations
    });
  }

  /**
   * Mark the device as compliant and clear violations.
   */
  markCompliant() {
    this.isCompliant = true;
    this.violations  = [];
    this.updatedAt   = new Date();

    this._addDomainEvent(DeviceEvents.DEVICE_COMPLIANT, {
      deviceId: this.id
    });
  }

  /**
   * Retire the device (end-of-life / decommission).
   */
  retire() {
    if (this.status === 'retired') return;
    this.status    = 'retired';
    this.updatedAt = new Date();

    this._addDomainEvent(DeviceEvents.DEVICE_RETIRED, {
      deviceId: this.id,
      retiredAt: this.updatedAt
    });
  }

  /**
   * Lock the device (e.g. remote lock on loss/theft).
   * @param {string} [reason]
   */
  lock(reason) {
    if (this.status === 'locked') return;
    this.status    = 'locked';
    this.updatedAt = new Date();

    this._addDomainEvent(DeviceEvents.DEVICE_LOCKED, {
      deviceId: this.id,
      reason:   reason || 'Administrative lock',
      lockedAt: this.updatedAt
    });
  }

  // ── Domain events ──────────────────────────────────────────────────────────

  /**
   * Return and clear all pending domain events.
   * @returns {Array<{type: string, payload: object, occurredAt: Date, eventId: string}>}
   */
  getAndClearDomainEvents() {
    const events = [...this._domainEvents];
    this._domainEvents = [];
    return events;
  }

  // ── Serialisation ──────────────────────────────────────────────────────────

  toJSON() {
    return {
      id:           this.id,
      name:         this.name,
      platform:     this.platform,
      serialNumber: this.serialNumber,
      status:       this.status,
      isCompliant:  this.isCompliant,
      violations:   this.violations,
      ownerId:      this.ownerId,
      enrolledAt:   this.enrolledAt,
      updatedAt:    this.updatedAt
    };
  }

  // ── Private ────────────────────────────────────────────────────────────────

  _validate(data) {
    if (!data || typeof data !== 'object') throw new Error('Device data must be an object');
    if (!data.name || typeof data.name !== 'string' || !data.name.trim()) {
      throw new Error('Device name is required');
    }
    if (!data.platform || typeof data.platform !== 'string' || !data.platform.trim()) {
      throw new Error('Device platform is required');
    }
  }

  _addDomainEvent(type, payload) {
    this._domainEvents.push({
      type,
      payload,
      occurredAt: new Date(),
      eventId:    randomUUID()
    });
  }
}

DeviceAggregate.DeviceEvents = DeviceEvents;

module.exports = DeviceAggregate;
