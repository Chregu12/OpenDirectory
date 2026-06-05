'use strict';
const { DeviceEvents } = require('../events/DeviceEvents');

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
    this._domainEvents = [];
  }

  static create(props) {
    const device = new DeviceAggregate({ ...props, status: 'active', enrolledAt: new Date() });
    device._domainEvents.push({ type: DeviceEvents.DEVICE_ENROLLED, payload: { deviceId: props.id, hostname: props.hostname, platform: props.platform } });
    return device;
  }

  markCompliant() {
    if (!this._isCompliant) {
      this._isCompliant = true;
      this._complianceViolations = [];
      this._domainEvents.push({ type: DeviceEvents.DEVICE_COMPLIANT, payload: { deviceId: this._id } });
    }
    return this;
  }

  markNonCompliant(violations = []) {
    this._isCompliant = false;
    this._complianceViolations = violations;
    this._domainEvents.push({ type: DeviceEvents.DEVICE_NON_COMPLIANT, payload: { deviceId: this._id, violations } });
    return this;
  }

  updateLastSeen() {
    this._lastSeen = new Date();
    return this;
  }

  retire() {
    this._status = 'retired';
    this._domainEvents.push({ type: DeviceEvents.DEVICE_RETIRED, payload: { deviceId: this._id } });
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
    };
  }
}

module.exports = DeviceAggregate;
