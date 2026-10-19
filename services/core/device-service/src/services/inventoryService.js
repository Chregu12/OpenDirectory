'use strict';

const logger = require('../utils/logger');

class InventoryService {
  constructor(db, cache) {
    this.db = db;
    this.cache = cache;
  }

  async updateInventory(deviceId, inventory) {
    const existing = await this.db.findOne('inventory', { deviceId });
    if (existing) {
      return this.db.update('inventory', existing.id, { ...inventory, deviceId, updatedAt: new Date().toISOString() });
    }
    return this.db.insert('inventory', { id: `inv-${deviceId}`, deviceId, ...inventory, updatedAt: new Date().toISOString() });
  }

  async getInventory(deviceId) {
    return this.db.findOne('inventory', { deviceId });
  }

  async getFullInventory({ page = 1, limit = 50 } = {}) {
    const items = await this.db.find('inventory', {});
    const total = items.length;
    const start = (page - 1) * limit;
    return { items: items.slice(start, start + limit), pagination: { page, limit, total } };
  }
}

module.exports = InventoryService;
