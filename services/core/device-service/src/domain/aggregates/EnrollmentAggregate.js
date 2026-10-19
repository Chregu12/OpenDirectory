'use strict';
const { randomUUID } = require('crypto');

class EnrollmentAggregate {
  constructor(props) {
    this._id = props.id;
    this._deviceId = props.deviceId || null;
    this._hostname = props.hostname;
    this._platform = props.platform;
    this._status = props.status || 'pending';
    this._requestedBy = props.requestedBy || null;
    this._initiatedAt = props.initiatedAt || new Date();
    this._completedAt = props.completedAt || null;
    this._metadata = props.metadata || {};
    this._domainEvents = [];
  }

  static create(props) {
    const enrollment = new EnrollmentAggregate({ ...props, status: 'pending', initiatedAt: new Date() });
    enrollment._domainEvents.push({ type: 'enrollment.initiated', payload: { enrollmentId: enrollment._id, hostname: props.hostname, platform: props.platform }, occurredAt: new Date(), eventId: randomUUID() });
    return enrollment;
  }

  approve() {
    this._status = 'approved';
    this._domainEvents.push({ type: 'enrollment.approved', payload: { enrollmentId: this._id }, occurredAt: new Date(), eventId: randomUUID() });
    return this;
  }

  complete(deviceId) {
    this._status = 'completed';
    this._deviceId = deviceId;
    this._completedAt = new Date();
    this._domainEvents.push({ type: 'enrollment.completed', payload: { enrollmentId: this._id, deviceId }, occurredAt: new Date(), eventId: randomUUID() });
    return this;
  }

  reject(reason) {
    this._status = 'rejected';
    this._domainEvents.push({ type: 'enrollment.rejected', payload: { enrollmentId: this._id, reason }, occurredAt: new Date(), eventId: randomUUID() });
    return this;
  }

  get id() { return this._id; }
  get deviceId() { return this._deviceId; }
  get hostname() { return this._hostname; }
  get platform() { return this._platform; }
  get status() { return this._status; }
  get requestedBy() { return this._requestedBy; }
  get initiatedAt() { return this._initiatedAt; }
  get completedAt() { return this._completedAt; }
  get metadata() { return { ...this._metadata }; }

  getAndClearDomainEvents() {
    const events = [...this._domainEvents];
    this._domainEvents = [];
    return events;
  }

  toJSON() {
    return { id: this._id, deviceId: this._deviceId, hostname: this._hostname, platform: this._platform, status: this._status, requestedBy: this._requestedBy, initiatedAt: this._initiatedAt, completedAt: this._completedAt, metadata: this._metadata };
  }
}

module.exports = EnrollmentAggregate;
