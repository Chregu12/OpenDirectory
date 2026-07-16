'use strict';
const DeviceAggregate = require('../domain/aggregates/DeviceAggregate');
const { Platform } = require('../domain/value-objects/Platform');
const ComplianceStatus = require('../domain/value-objects/ComplianceStatus');

// index.js wires the device CRUD/list/checkin routes (POST/GET/PUT/DELETE
// /api/devices[/:id], bulk import, WS/agent last-seen touches, health-check
// active count) to the "…Record"/"…Paginated"/touchLastSeen/countActiveDevices
// methods below. Those methods are ported 1:1 from the old transaction-script
// services/deviceManager.js so the swap is behavior-preserving — see
// src/__tests__/deviceInstallCharacterization.test.js for the golden-master
// coverage that pins the observable HTTP contract across the refactor.
//
// enrollDevice/updateCompliance/retireDevice/getDevice/listDevices (below)
// are a *separate*, stricter DDD-style contract (Platform validation,
// idempotent re-enrollment, raw-aggregate returns) that predates this wiring
// effort and is intentionally left untouched — swapping the live routes onto
// those methods instead would change observable behavior (e.g. enrollDevice
// throws on an invalid platform where the legacy createDevice route does
// not), which is exactly what this refactor must not do. They keep their own
// dedicated unit tests in application/__tests__/DeviceApplicationService.test.js.
class DeviceApplicationService {
  constructor({ deviceRepository, messageBus, logger, db, eventBus }) {
    this._repo = deviceRepository;
    this._bus = messageBus;
    this._log = logger || console;
    // Legacy dependencies, only needed by the ported CRUD methods below.
    this._db = db || null;           // legacy db wrapper (compliance_results / device_history)
    this._legacyEvents = eventBus || null; // EventEmitter-based bus (device:created/updated/deleted)
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

  // ── CRUD orchestration ported from services/deviceManager.js ─────────────
  // (see class-level note above for why these are separate from
  // enrollDevice/getDevice/listDevices)

  async listDevicesPaginated({ page = 1, limit = 50, search, status, platform, complianceStatus, sortBy = 'lastSeen', sortOrder = 'desc' } = {}) {
    const filters = {};
    if (status) filters.status = status;
    if (platform) filters.platform = platform;
    const aggregates = await this._repo.findAll(filters);
    let devices = aggregates.map(a => a.toJSON());

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
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    };
  }

  async getDeviceWithExtras(id, { includeCompliance = false, includeHistory = false } = {}) {
    const aggregate = await this._repo.findById(id);
    if (!aggregate) return null;
    const result = { ...aggregate.toJSON() };

    // compliance_results and device_history still use the legacy db wrapper
    // (unchanged from services/deviceManager.js — no dedicated repo yet).
    if (includeCompliance) result.compliance = await this._db.findOne('compliance_results', { deviceId: id });
    if (includeHistory) result.history = await this._db.find('device_history', { deviceId: id });
    return result;
  }

  async createDeviceRecord(data, user) {
    const id = data.id || `dev-${Date.now()}`;

    const aggregate = DeviceAggregate.create({
      ...data,
      id,
      enrolledBy: user?.id || 'system',
    });
    await this._repo.save(aggregate);
    const device = aggregate.toJSON();
    if (this._legacyEvents) this._legacyEvents.emit('device:created', { device, user });
    this._log.info('Device created', { deviceId: id });
    return device;
  }

  async updateDeviceRecord(id, updates) {
    const aggregate = await this._repo.findById(id);
    if (!aggregate) return null;

    // Apply scalar updates to the aggregate's internal state — same fixed
    // field allow-list as the old DeviceManager.updateDevice; unknown fields
    // (e.g. "name") are silently dropped, matching prior behavior exactly.
    if (updates.hostname !== undefined) aggregate._hostname = updates.hostname;
    if (updates.platform !== undefined) aggregate._platform = updates.platform;
    if (updates.status !== undefined) aggregate._status = updates.status;
    if (updates.lastSeen !== undefined) aggregate._lastSeen = updates.lastSeen;
    if (updates.isCompliant !== undefined) aggregate._isCompliant = updates.isCompliant;
    if (updates.complianceViolations !== undefined) aggregate._complianceViolations = updates.complianceViolations;
    if (updates.os !== undefined) aggregate._os = updates.os;
    if (updates.osVersion !== undefined) aggregate._osVersion = updates.osVersion;
    if (updates.ipAddress !== undefined) aggregate._ipAddress = updates.ipAddress;
    if (updates.kernel !== undefined) aggregate._kernel = updates.kernel;
    if (updates.packageManager !== undefined) aggregate._packageManager = updates.packageManager;

    await this._repo.save(aggregate);
    const device = aggregate.toJSON();
    if (this._legacyEvents) this._legacyEvents.emit('device:updated', { device });
    return device;
  }

  async deleteDeviceRecord(id) {
    const exists = await this._repo.exists(id);
    if (!exists) return false;
    await this._repo.delete(id);
    if (this._legacyEvents) this._legacyEvents.emit('device:deleted', { deviceId: id });
    this._log.info('Device deleted', { deviceId: id });
    return true;
  }

  // Non-throwing "touch" used by WS heartbeat/agent-register handlers and
  // the /checkin HTTP endpoint — deliberately distinct from markDeviceSeen()
  // above, which throws for an unknown device. The live checkin endpoint has
  // no try/catch around this call other than a generic 500 handler, and must
  // keep returning 200 "ok" for a device that was never enrolled.
  async touchLastSeen(deviceId) {
    const aggregate = await this._repo.findById(deviceId);
    if (!aggregate) return null;
    aggregate.updateLastSeen();
    await this._repo.save(aggregate);
    return aggregate.toJSON();
  }

  async countActiveDevices() {
    const devices = await this._repo.findAll({ status: 'active' });
    return devices.length;
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
