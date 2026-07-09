'use strict';

const fsp = require('fs').promises;
const path = require('path');

const IHardwareReportRepository = require('../../domain/repositories/IHardwareReportRepository');

// Caps in-memory caches so a stream of distinct hostnames/deviceIds can't
// grow these maps without bound; evicts the oldest entry (FIFO) once full.
const MAX_CACHE_ENTRIES = 500;
function cacheSet(map, key, value) {
  if (!map.has(key) && map.size >= MAX_CACHE_ENTRIES) {
    const oldestKey = map.keys().next().value;
    map.delete(oldestKey);
  }
  map.set(key, value);
}

/**
 * FileHardwareReportRepository
 *
 * Persists hardware reports as one JSON file per key (DEVICE_HARDWARE_DIR),
 * fronted by an in-memory FIFO cache for both hardware reports and their
 * matched driver recommendations — moved here unchanged from
 * routes/deviceDetectionRoutes.js.
 */
class FileHardwareReportRepository extends IHardwareReportRepository {
  constructor(reportDir) {
    super();
    this._reportDir = reportDir || process.env.DEVICE_HARDWARE_DIR || '/var/lib/opendirectory/device-hardware';
    this._reports = new Map();
    this._recommendations = new Map();
  }

  async _persist(key, data) {
    try {
      await fsp.mkdir(this._reportDir, { recursive: true });
      await fsp.writeFile(path.join(this._reportDir, `${key}.json`), JSON.stringify(data, null, 2));
    } catch (_) {
      // Best-effort persistence, mirrors previous behaviour.
    }
  }

  async _load(key) {
    try {
      const raw = await fsp.readFile(path.join(this._reportDir, `${key}.json`), 'utf-8');
      return JSON.parse(raw);
    } catch (_) {
      return null;
    }
  }

  async save(key, report) {
    cacheSet(this._reports, key, report);
    await this._persist(key, report);
    return report;
  }

  async findByKey(key) {
    const cached = this._reports.get(key);
    if (cached) return cached;
    return this._load(key);
  }

  async saveRecommendations(key, recommendations) {
    const record = { recommendations, matchedAt: new Date().toISOString() };
    cacheSet(this._recommendations, key, record);
    return record;
  }

  async findRecommendations(key) {
    return this._recommendations.get(key) || null;
  }
}

module.exports = FileHardwareReportRepository;
