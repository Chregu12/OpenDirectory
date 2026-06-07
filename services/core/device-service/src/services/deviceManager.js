'use strict';

const logger = require('../utils/logger');

/**
 * DeviceManager — CRUD and lifecycle management for enrolled devices.
 */
class DeviceManager {
  constructor(db, cache, eventBus) {
    this.db = db;
    this.cache = cache;
    this.eventBus = eventBus;
  }

  async getDevices({ page = 1, limit = 50, search, status, platform, complianceStatus, sortBy = 'lastSeen', sortOrder = 'desc' } = {}) {
    let devices = await this.db.find('devices', {});

    if (status) devices = devices.filter(d => d.status === status);
    if (platform) devices = devices.filter(d => d.platform === platform);
    if (complianceStatus) devices = devices.filter(d => d.complianceStatus === complianceStatus);
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
    const device = await this.db.findById('devices', id);
    if (!device) return null;
    const result = { ...device };
    if (includeCompliance) result.compliance = await this.db.findOne('compliance_results', { deviceId: id });
    if (includeHistory) result.history = await this.db.find('device_history', { deviceId: id });
    return result;
  }

  async createDevice(data, user) {
    const id = data.id || `dev-${Date.now()}`;
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
    const device = await this.db.update('devices', id, updates);
    if (device) this.eventBus.emit('device:updated', { device });
    return device;
  }

  async deleteDevice(id) {
    const device = await this.db.findById('devices', id);
    if (!device) return false;
    await this.db.delete('devices', id);
    this.eventBus.emit('device:deleted', { deviceId: id });
    logger.info('Device deleted', { deviceId: id });
    return true;
  }

  async updateLastSeen(deviceId) {
    return this.db.update('devices', deviceId, { lastSeen: new Date().toISOString() });
  }

  async getActiveDeviceCount() {
    return this.db.count('devices', { status: 'active' });
  }

  async updateStatus(deviceId, status) {
    return this.db.update('devices', deviceId, { status });
  }
}

module.exports = DeviceManager;
