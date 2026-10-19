'use strict';
const { DeviceEvents } = require('../events/DeviceEvents');

class InstallJobAggregate {
  constructor(props) {
    this._jobId = props.jobId;
    this._deviceId = props.deviceId;
    this._appId = props.appId;
    this._appName = props.appName;
    this._packageId = props.packageId;
    this._format = props.format;
    this._version = props.version;
    this._status = props.status || 'queued';
    this._queuedAt = props.queuedAt || new Date();
    this._completedAt = props.completedAt || null;
    this._error = props.error || null;
    this._domainEvents = [];
  }

  static create(props) {
    const job = new InstallJobAggregate({ ...props, status: 'queued', queuedAt: new Date() });
    job._domainEvents.push({ type: DeviceEvents.INSTALL_JOB_CREATED, payload: { jobId: job._jobId, deviceId: job._deviceId, appId: job._appId } });
    return job;
  }

  markDelivered() {
    this._status = 'delivered';
    return this;
  }

  complete(version) {
    this._status = 'completed';
    this._completedAt = new Date();
    if (version) this._version = version;
    this._domainEvents.push({ type: DeviceEvents.INSTALL_JOB_COMPLETED, payload: { jobId: this._jobId, deviceId: this._deviceId, appId: this._appId, version: this._version } });
    return this;
  }

  fail(error) {
    this._status = 'failed';
    this._completedAt = new Date();
    this._error = error;
    this._domainEvents.push({ type: DeviceEvents.INSTALL_JOB_FAILED, payload: { jobId: this._jobId, deviceId: this._deviceId, appId: this._appId, error } });
    return this;
  }

  get jobId() { return this._jobId; }
  get deviceId() { return this._deviceId; }
  get status() { return this._status; }

  getAndClearDomainEvents() {
    const events = [...this._domainEvents];
    this._domainEvents = [];
    return events;
  }

  toJSON() {
    return { jobId: this._jobId, deviceId: this._deviceId, appId: this._appId, appName: this._appName, packageId: this._packageId, format: this._format, version: this._version, status: this._status, queuedAt: this._queuedAt, completedAt: this._completedAt, error: this._error };
  }
}

module.exports = InstallJobAggregate;
