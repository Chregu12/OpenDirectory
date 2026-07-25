'use strict';

// NOTE: This file was missing from the repo entirely — src/index.js has
// always `require('./services/vlanManager')`'d it, so the service could
// never actually load. This is a minimal in-memory implementation (mirrors
// the shape of dnsManager.js/dhcpManager.js's in-memory fallback) sufficient
// to satisfy the interface index.js calls: getVlans/createVlan/updateVlan/
// deleteVlan/getDevices/loadVlans. It is NOT the primary source of truth —
// src/index.js's VLAN routes are DB-first (see db.js getVlans/upsertVlan)
// and only fall back to this in-memory manager when db.isAvailable() is
// false. Found and stubbed out as plumbing needed to make the service
// (and therefore the auth fix) testable; not part of the auth work itself.

const EventEmitter = require('events');

class VLANManager extends EventEmitter {
  constructor() {
    super();
    this.vlans = new Map();
    this.devicesByVlan = new Map();
  }

  /** Pre-warm from PostgreSQL at startup (see index.js loadDbCacheIntoMemory). */
  loadVlans(records = []) {
    this.vlans.clear();
    for (const vlan of records) {
      this.vlans.set(vlan.id, vlan);
    }
  }

  async getVlans() {
    return Array.from(this.vlans.values());
  }

  async createVlan(data) {
    const vlan = { id: data.id ?? this.vlans.size + 1, ...data, createdAt: new Date().toISOString() };
    this.vlans.set(vlan.id, vlan);
    this.emit('vlanCreated', vlan);
    return vlan;
  }

  async updateVlan(id, data) {
    const key = Number.isNaN(Number(id)) ? id : Number(id);
    const existing = this.vlans.get(key) || {};
    const vlan = { ...existing, ...data, id: key };
    this.vlans.set(key, vlan);
    this.emit('vlanUpdated', vlan);
    return vlan;
  }

  async deleteVlan(id) {
    const key = Number.isNaN(Number(id)) ? id : Number(id);
    this.vlans.delete(key);
    this.devicesByVlan.delete(key);
    this.emit('vlanDeleted', { id: key });
    return true;
  }

  async getDevices(id) {
    const key = Number.isNaN(Number(id)) ? id : Number(id);
    return this.devicesByVlan.get(key) || [];
  }
}

module.exports = VLANManager;
