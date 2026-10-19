'use strict';
const { DeviceEvents } = require('../events/DeviceEvents');
const { randomUUID } = require('crypto');

class DeviceAggregate {
  constructor(props) {
    this._id = props.id;
    this._hostname = props.hostname;
    this._platform = props.platform;
    this._status = props.status || 'active';
    this._isCompliant = props.isCompliant !== undefined ? props.isCompliant : true;
    this._complianceViolations = props.complianceViolations || [];
    this._lastSeen = props.lastSeen || null;
    this._enrolledAt = props.enrolledAt || new Date();
    this._os = props.os !== undefined ? props.os : null;
    this._osVersion = props.osVersion !== undefined ? props.osVersion : null;
    this._ipAddress = props.ipAddress !== undefined ? props.ipAddress : null;
    this._kernel = props.kernel !== undefined ? props.kernel : null;
    this._packageManager = props.packageManager !== undefined ? props.packageManager : null;
    this._domainEvents = [];
  }

  static create(props) {
    const device = new DeviceAggregate({ ...props, status: 'active', enrolledAt: new Date() });
    device._domainEvents.push({ type: DeviceEvents.DEVICE_ENROLLED, payload: { deviceId: props.id, hostname: props.hostname, platform: props.platform }, occurredAt: new Date(), eventId: randomUUID() });
    return device;
  }

  markCompliant() {
    if (!this._isCompliant) {
      this._isCompliant = true;
      this._complianceViolations = [];
      this._domainEvents.push({ type: DeviceEvents.DEVICE_COMPLIANT, payload: { deviceId: this._id }, occurredAt: new Date(), eventId: randomUUID() });
    }
    return this;
  }

  markNonCompliant(violations = []) {
    this._isCompliant = false;
    this._complianceViolations = violations;
    this._domainEvents.push({ type: DeviceEvents.DEVICE_NON_COMPLIANT, payload: { deviceId: this._id, violations }, occurredAt: new Date(), eventId: randomUUID() });
    return this;
  }

  updateLastSeen() {
    this._lastSeen = new Date();
    return this;
  }

  updateSystemInfo({ os, osVersion, ipAddress, kernel, packageManager } = {}) {
    if (os !== undefined) this._os = os;
    if (osVersion !== undefined) this._osVersion = osVersion;
    if (ipAddress !== undefined) this._ipAddress = ipAddress;
    if (kernel !== undefined) this._kernel = kernel;
    if (packageManager !== undefined) this._packageManager = packageManager;
    return this;
  }

  retire() {
    this._status = 'retired';
    this._domainEvents.push({ type: DeviceEvents.DEVICE_RETIRED, payload: { deviceId: this._id }, occurredAt: new Date(), eventId: randomUUID() });
    return this;
  }

  lock(reason) {
    this._status = 'locked';
    this._domainEvents.push({ type: DeviceEvents.DEVICE_LOCKED, payload: { deviceId: this._id, reason }, occurredAt: new Date(), eventId: randomUUID() });
    return this;
  }

  wipe(reason) {
    this._status = 'wiped';
    this._domainEvents.push({ type: DeviceEvents.DEVICE_WIPED, payload: { deviceId: this._id, reason }, occurredAt: new Date(), eventId: randomUUID() });
    return this;
  }

  isolate(reason) {
    this._status = 'isolated';
    this._domainEvents.push({ type: DeviceEvents.DEVICE_ISOLATED, payload: { deviceId: this._id, reason }, occurredAt: new Date(), eventId: randomUUID() });
    return this;
  }

  reconnect() {
    this._status = 'active';
    this._domainEvents.push({ type: DeviceEvents.DEVICE_RECONNECTED, payload: { deviceId: this._id }, occurredAt: new Date(), eventId: randomUUID() });
    return this;
  }

  get id() { return this._id; }
  get hostname() { return this._hostname; }
  get platform() { return this._platform; }
  get status() { return this._status; }
  get isCompliant() { return this._isCompliant; }
  get complianceViolations() { return [...this._complianceViolations]; }
  get lastSeen() { return this._lastSeen; }
  get enrolledAt() { return this._enrolledAt; }
  get os() { return this._os; }
  get osVersion() { return this._osVersion; }
  get ipAddress() { return this._ipAddress; }
  get kernel() { return this._kernel; }
  get packageManager() { return this._packageManager; }

  /**
   * Derived compliance score (0-100).
   * Fully compliant devices score 100; each recorded violation deducts 25,
   * floored at 0.
   */
  get complianceScore() {
    if (this._isCompliant === true) return 100;
    return Math.max(0, 100 - 25 * this._complianceViolations.length);
  }

  getAndClearDomainEvents() {
    const events = [...this._domainEvents];
    this._domainEvents = [];
    return events;
  }

  toJSON() {
    return {
      id: this._id, hostname: this._hostname, platform: this._platform,
      status: this._status, isCompliant: this._isCompliant,
      complianceViolations: this._complianceViolations,
      lastSeen: this._lastSeen, enrolledAt: this._enrolledAt,
      os: this._os, osVersion: this._osVersion, ipAddress: this._ipAddress,
      kernel: this._kernel, packageManager: this._packageManager,
      complianceScore: this.complianceScore,
    };
  }

  static fromJSON(json) {
    return new DeviceAggregate(json);
  }
}

module.exports = DeviceAggregate;
