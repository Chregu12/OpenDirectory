'use strict';
const DeviceAggregate = require('../domain/aggregates/DeviceAggregate');
const { Platform } = require('../domain/value-objects/Platform');
const ComplianceStatus = require('../domain/value-objects/ComplianceStatus');

class DeviceApplicationService {
  constructor({ deviceRepository, messageBus, logger }) {
    this._repo = deviceRepository;
    this._bus = messageBus;
    this._log = logger || console;
  }

  async enrollDevice({ id, hostname, platform, orgId, userId }) {
    // Validate platform value object
    new Platform(platform); // throws if invalid

    const existing = await this._repo.exists(id);
    if (existing) {
      // Re-enrollment: just update
      const device = await this._repo.findById(id);
      await this._repo.save(device.updateLastSeen());
      return device;
    }

    const device = DeviceAggregate.create({ id, hostname, platform, orgId, userId });
    await this._repo.save(device);
    await this._publishDomainEvents(device);
    return device;
  }

  async markDeviceSeen(deviceId) {
    const device = await this._repo.findById(deviceId);
    if (!device) throw new Error(`Device not found: ${deviceId}`);
    await this._repo.save(device.updateLastSeen());
    return device;
  }

  async updateCompliance(deviceId, { isCompliant, violations }) {
    const device = await this._repo.findById(deviceId);
    if (!device) throw new Error(`Device not found: ${deviceId}`);

    const status = isCompliant
      ? ComplianceStatus.compliant()
      : ComplianceStatus.nonCompliant(violations || []);

    if (status.isCompliant) {
      device.markCompliant();
    } else {
      device.markNonCompliant(status.violations);
    }

    await this._repo.save(device);
    await this._publishDomainEvents(device);
    return device;
  }

  async retireDevice(deviceId) {
    const device = await this._repo.findById(deviceId);
    if (!device) throw new Error(`Device not found: ${deviceId}`);
    device.retire();
    await this._repo.save(device);
    await this._publishDomainEvents(device);
    return device;
  }

  async getDevice(deviceId) {
    return this._repo.findById(deviceId);
  }

  async listDevices(filters) {
    return this._repo.findAll(filters);
  }

  async _publishDomainEvents(aggregate) {
    if (!this._bus || !this._bus.isConnected()) return;
    const events = aggregate.getAndClearDomainEvents();
    for (const event of events) {
      try {
        this._bus.publish(event.type, { ...event.payload, _source: 'device-service' });
      } catch (e) {
        this._log.warn(`Failed to publish domain event ${event.type}: ${e.message}`);
      }
    }
  }
}

module.exports = DeviceApplicationService;
