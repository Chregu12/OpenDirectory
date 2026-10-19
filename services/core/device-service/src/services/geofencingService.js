'use strict';

const logger = require('../utils/logger');

class GeofencingService {
  constructor(db, eventBus) {
    this.db = db;
    this.eventBus = eventBus;
  }

  async getZones({ page = 1, limit = 50 } = {}) {
    const zones = await this.db.find('geofence_zones', {});
    const total = zones.length;
    const start = (page - 1) * limit;
    return { zones: zones.slice(start, start + limit), pagination: { page, limit, total } };
  }

  async createZone(data) {
    const id = `zone-${Date.now()}`;
    const zone = await this.db.insert('geofence_zones', { ...data, id });
    this.eventBus.emit('geofence:zone_created', { zone });
    return zone;
  }

  async updateZone(id, updates) {
    return this.db.update('geofence_zones', id, updates);
  }

  async deleteZone(id) {
    return this.db.delete('geofence_zones', id);
  }
}

module.exports = GeofencingService;
