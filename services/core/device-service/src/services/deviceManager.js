'use strict';

const DeviceAggregate = require('../domain/aggregates/DeviceAggregate');
const logger = require('../utils/logger');

/**
 * DeviceManager — CRUD and lifecycle management for enrolled devices.
 *
 * Uses IDeviceRepository (via deviceRepository) for all device persistence.
 * The legacy db wrapper is kept only for compliance_results and device_history
 * tables which don't have their own repos yet.
 */
class DeviceManager {
  /**
   * @param {object} options
   * @param {object} options.db              - legacy db wrapper (for compliance_results / device_history)
   * @param {object} options.deviceRepository - IDeviceRepository implementation
   * @param {object} options.cache
   * @param {object} options.eventBus
   */
  constructor({ db, deviceRepository, cache, eventBus } = {}) {
    this.db = db;
    this.deviceRepository = deviceRepository || null;
    this.cache = cache;
    this.eventBus = eventBus;
  }

  async getDevices({ page = 1, limit = 50, search, status, platform, complianceStatus, sortBy = 'lastSeen', sortOrder = 'desc' } = {}) {
    let devices;

    if (this.deviceRepository) {
      // Use repo with server-side filtering where supported
      const filters = {};
      if (status) filters.status = status;
      if (platform) filters.platform = platform;
      const aggregates = await this.deviceRepository.findAll(filters);
      devices = aggregates.map(a => a.toJSON());
    } else {
      devices = await this.db.find('devices', {});
      if (status) devices = devices.filter(d => d.status === status);
      if (platform) devices = devices.filter(d => d.platform === platform);
    }

    if (complianceStatus) {
      devices = devices.filter(d => {
        const cs = d.complianceStatus || (d.isCompliant ? 'compliant' : 'non-compliant');
        return cs === complianceStatus;
      });
    }
    if (search) {
      const q = search.toLowerCase();
      devices = devices.filter(d =>
        (d.name || '').toLowerCase().includes(q) ||
        (d.hostname || '').toLowerCase().includes(q) ||
        (d.id || '').toLowerCase().includes(q)
      );
    }

    // Sort
    devices.sort((a, b) => {
      const va = a[sortBy] ?? '';
      const vb = b[sortBy] ?? '';
      return sortOrder === 'asc' ? (va < vb ? -1 : 1) : (va > vb ? -1 : 1);
    });

    const total = devices.length;
    const start = (page - 1) * limit;
    const paged = devices.slice(start, start + limit);

    return {
      devices: paged,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) }
    };
  }

  async getDevice(id, { includeCompliance = false, includeHistory = false } = {}) {
    let result;

    if (this.deviceRepository) {
      const aggregate = await this.deviceRepository.findById(id);
      if (!aggregate) return null;
      result = { ...aggregate.toJSON() };
    } else {
      const device = await this.db.findById('devices', id);
      if (!device) return null;
      result = { ...device };
    }

    // compliance_results and device_history still use the legacy db wrapper
    if (includeCompliance) result.compliance = await this.db.findOne('compliance_results', { deviceId: id });
    if (includeHistory) result.history = await this.db.find('device_history', { deviceId: id });
    return result;
  }

  async createDevice(data, user) {
    const id = data.id || `dev-${Date.now()}`;

    if (this.deviceRepository) {
      const aggregate = DeviceAggregate.create({
        ...data,
        id,
        enrolledBy: user?.id || 'system',
      });
      await this.deviceRepository.save(aggregate);
      const device = aggregate.toJSON();
      this.eventBus.emit('device:created', { device, user });
      logger.info('Device created', { deviceId: id });
      return device;
    }

    // Legacy fallback
    const device = await this.db.insert('devices', {
      ...data,
      id,
      status: data.status || 'active',
      complianceStatus: 'unknown',
      enrolledAt: new Date().toISOString(),
      enrolledBy: user?.id || 'system',
      lastSeen: new Date().toISOString()
    });
    this.eventBus.emit('device:created', { device, user });
    logger.info('Device created', { deviceId: id });
    return device;
  }

  async updateDevice(id, updates) {
    if (this.deviceRepository) {
      const aggregate = await this.deviceRepository.findById(id);
      if (!aggregate) return null;

      // Apply scalar updates to the aggregate's internal state
      if (updates.hostname !== undefined) aggregate._hostname = updates.hostname;
      if (updates.platform !== undefined) aggregate._platform = updates.platform;
      if (updates.status !== undefined) aggregate._status = updates.status;
      if (updates.lastSeen !== undefined) aggregate._lastSeen = updates.lastSeen;
      if (updates.isCompliant !== undefined) aggregate._isCompliant = updates.isCompliant;
      if (updates.complianceViolations !== undefined) aggregate._complianceViolations = updates.complianceViolations;

      await this.deviceRepository.save(aggregate);
      const device = aggregate.toJSON();
      this.eventBus.emit('device:updated', { device });
      return device;
    }

    // Legacy fallback
    const device = await this.db.update('devices', id, updates);
    if (device) this.eventBus.emit('device:updated', { device });
    return device;
  }

  async deleteDevice(id) {
    if (this.deviceRepository) {
      const exists = await this.deviceRepository.exists(id);
      if (!exists) return false;
      await this.deviceRepository.delete(id);
      this.eventBus.emit('device:deleted', { deviceId: id });
      logger.info('Device deleted', { deviceId: id });
      return true;
    }

    // Legacy fallback
    const device = await this.db.findById('devices', id);
    if (!device) return false;
    await this.db.delete('devices', id);
    this.eventBus.emit('device:deleted', { deviceId: id });
    logger.info('Device deleted', { deviceId: id });
    return true;
  }

  async updateLastSeen(deviceId) {
    if (this.deviceRepository) {
      const aggregate = await this.deviceRepository.findById(deviceId);
      if (aggregate) {
        aggregate.updateLastSeen();
        await this.deviceRepository.save(aggregate);
        return aggregate.toJSON();
      }
      return null;
    }
    return this.db.update('devices', deviceId, { lastSeen: new Date().toISOString() });
  }

  async getActiveDeviceCount() {
    if (this.deviceRepository) {
      const devices = await this.deviceRepository.findAll({ status: 'active' });
      return devices.length;
    }
    return this.db.count('devices', { status: 'active' });
  }

  async updateStatus(deviceId, status) {
    return this.updateDevice(deviceId, { status });
  }
}

module.exports = DeviceManager;
