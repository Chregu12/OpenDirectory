'use strict';
const { randomUUID } = require('crypto');
const { DeviceEvents } = require('../events/DeviceEvents');
const { DriverFormat } = require('../value-objects/DriverFormat');

const VALID_DEPLOYMENT_STATUSES = ['pending', 'deploying', 'success', 'failed'];

// pending -> deploying -> success | failed. pending may also fail directly
// (e.g. the device rejects the deployment before it starts). success/failed
// are terminal.
const DEPLOYMENT_TRANSITIONS = {
  pending: ['deploying', 'failed'],
  deploying: ['success', 'failed'],
  success: [],
  failed: [],
};

function newDeploymentId() {
  return `${Date.now().toString(36)}-${randomUUID().slice(0, 8)}`;
}

/**
 * DriverAggregate — driver catalog entry as an Aggregate Root.
 * Deployments (driver -> device rollouts) are entities managed inside this
 * aggregate; they never exist independently of their driver.
 */
class DriverAggregate {
  constructor(props) {
    if (!props || !props.id) throw new Error('DriverAggregate requires an id');
    this._id = props.id;
    this._name = props.name;
    this._version = props.version;
    this._vendor = props.vendor;
    this._os = Array.isArray(props.os) ? [...props.os] : (props.os ? [props.os] : []);
    this._deviceType = props.deviceType;
    this._format = props.format instanceof DriverFormat ? props.format : new DriverFormat(props.format);
    this._architecture = props.architecture;
    this._description = props.description || '';
    this._checksum = props.checksum;
    this._fileSize = props.fileSize;
    this._filename = props.filename;
    this._filePath = props.filePath;
    this._tags = Array.isArray(props.tags)
      ? [...props.tags]
      : (props.tags ? String(props.tags).split(',').map(t => t.trim()).filter(Boolean) : []);
    this._uploadedAt = props.uploadedAt || new Date().toISOString();
    this._deployments = Array.isArray(props.deployments) ? props.deployments.map(d => ({ ...d })) : [];
    this._domainEvents = [];
  }

  static create(props) {
    const required = ['id', 'name', 'version', 'vendor', 'deviceType', 'architecture', 'checksum', 'fileSize', 'filename', 'filePath'];
    for (const field of required) {
      const value = props[field];
      const missing = value === undefined || value === null || value === '';
      if (missing) throw new Error(`DriverAggregate.create: '${field}' is required`);
    }
    if (!Array.isArray(props.os) || props.os.length === 0) {
      throw new Error("DriverAggregate.create: 'os' must be a non-empty array");
    }
    if (typeof props.fileSize !== 'number' || props.fileSize < 0) {
      throw new Error("DriverAggregate.create: 'fileSize' must be a non-negative number");
    }

    const driver = new DriverAggregate({ ...props, deployments: [], uploadedAt: new Date().toISOString() });
    driver._domainEvents.push({
      type: DeviceEvents.DRIVER_IMPORTED,
      payload: { driverId: driver._id, name: driver._name, version: driver._version, vendor: driver._vendor, format: driver._format.value },
      occurredAt: new Date(),
      eventId: randomUUID(),
    });
    return driver;
  }

  // ── deployment entities ────────────────────────────────────────────────────

  addDeployment(deviceId) {
    if (!deviceId) throw new Error('addDeployment: deviceId is required');
    const now = new Date().toISOString();
    const deployment = {
      id: newDeploymentId(),
      driverId: this._id,
      deviceId,
      status: 'pending',
      deployedAt: now,
      updatedAt: now,
      error: null,
    };
    this._deployments.push(deployment);
    this._domainEvents.push({
      type: DeviceEvents.DRIVER_DEPLOYED,
      payload: { driverId: this._id, deploymentId: deployment.id, deviceId },
      occurredAt: new Date(),
      eventId: randomUUID(),
    });
    return { ...deployment };
  }

  updateDeploymentStatus(deploymentId, status, error) {
    if (!VALID_DEPLOYMENT_STATUSES.includes(status)) {
      throw new Error(`Invalid deployment status: ${status}. Must be one of: ${VALID_DEPLOYMENT_STATUSES.join(', ')}`);
    }
    const deployment = this._deployments.find(d => d.id === deploymentId);
    if (!deployment) return null;

    const allowedNext = DEPLOYMENT_TRANSITIONS[deployment.status] || [];
    if (deployment.status !== status && !allowedNext.includes(status)) {
      throw new Error(`Invalid deployment status transition: ${deployment.status} -> ${status}`);
    }

    deployment.status = status;
    deployment.error = error !== undefined ? error : deployment.error;
    deployment.updatedAt = new Date().toISOString();
    return { ...deployment };
  }

  getDeployments() {
    return this._deployments.map(d => ({ ...d }));
  }

  findDeployment(deploymentId) {
    const deployment = this._deployments.find(d => d.id === deploymentId);
    return deployment ? { ...deployment } : null;
  }

  // ── accessors ──────────────────────────────────────────────────────────────

  get id() { return this._id; }
  get name() { return this._name; }
  get version() { return this._version; }
  get vendor() { return this._vendor; }
  get os() { return [...this._os]; }
  get deviceType() { return this._deviceType; }
  get format() { return this._format.value; }
  get architecture() { return this._architecture; }
  get description() { return this._description; }
  get checksum() { return this._checksum; }
  get fileSize() { return this._fileSize; }
  get filename() { return this._filename; }
  get filePath() { return this._filePath; }
  get tags() { return [...this._tags]; }
  get uploadedAt() { return this._uploadedAt; }
  get deployments() { return this.getDeployments(); }

  getAndClearDomainEvents() {
    const events = [...this._domainEvents];
    this._domainEvents = [];
    return events;
  }

  toJSON() {
    return {
      id: this._id,
      name: this._name,
      version: this._version,
      vendor: this._vendor,
      os: [...this._os],
      deviceType: this._deviceType,
      format: this._format.value,
      architecture: this._architecture,
      description: this._description,
      filename: this._filename,
      fileSize: this._fileSize,
      filePath: this._filePath,
      checksum: this._checksum,
      tags: [...this._tags],
      deployments: this.getDeployments(),
      uploadedAt: this._uploadedAt,
    };
  }

  static fromJSON(json) {
    return new DriverAggregate({ ...json });
  }
}

module.exports = DriverAggregate;
