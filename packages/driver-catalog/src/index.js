'use strict';

// =============================================================================
// @opendirectory/driver-catalog
//
// Shared driver catalog and hardware-matching library.
// Follows the same pattern as @opendirectory/policy-compilers:
//   - Generic orchestration here in index.js
//   - Per-platform parsing in platforms/
//   - Per-vendor static data in vendors/
//
// Services that need live/network-backed data (e.g. Dell live catalog via
// printer-service) inject a custom fetchDrivers() callback rather than
// coupling this package to any specific service URL.
// =============================================================================

const { normalizeVendor, normalizeOs, scoreMatch } = require('./scoring');
const WindowsMatcher = require('./platforms/WindowsMatcher');
const LinuxMatcher   = require('./platforms/LinuxMatcher');
const HpProvider     = require('./vendors/HpProvider');
const LenovoProvider = require('./vendors/LenovoProvider');

// ─── Built-in static vendors ──────────────────────────────────────────────────

const STATIC_PROVIDERS = {
  hp:     HpProvider,
  lenovo: LenovoProvider,
};

// ─── DriverCatalog class ──────────────────────────────────────────────────────

class DriverCatalog {
  constructor() {
    // Additional async providers: vendor key → async fn(query, filters) → DriverEntry[]
    this._asyncProviders = {};
  }

  /**
   * Register an async driver provider for a vendor.
   * Called by the consuming service (e.g. device-service registers Dell via HTTP).
   *
   * @param {string}   vendorKey   — e.g. 'dell'
   * @param {Function} fetchFn     — async (query, filters) => DriverEntry[]
   */
  registerProvider(vendorKey, fetchFn) {
    this._asyncProviders[vendorKey.toLowerCase()] = fetchFn;
  }

  /**
   * Match drivers for a device based on its hardware profile.
   *
   * @param {{
   *   manufacturer?: string,
   *   model?:        string,
   *   os?:           string,
   *   hardwareIds?:  Array<string|object>
   * }} hwInfo
   * @returns {Promise<DriverEntry[]>}
   */
  async matchDrivers(hwInfo = {}) {
    const { manufacturer, model, os, hardwareIds = [] } = hwInfo;

    const vendor  = normalizeVendor(manufacturer);
    const osLabel = normalizeOs(os);

    const seen    = new Set();
    const results = [];

    const push = (driver, extra = {}) => {
      // Dedupe by apt package first so a vendor-branded entry and a
      // hardware-derived entry for the same package collapse into one.
      const key = driver.aptPackage || driver.id || driver.name;
      if (seen.has(key)) return;
      seen.add(key);
      results.push({ ...driver, ...extra });
    };

    // ── 1. Async providers (e.g. Dell live catalog) ──
    // Only hit the (large) Dell catalog when the device is a Dell, or the
    // vendor is unknown but we at least have a model to search for.
    // An empty query would return the entire catalog (tens of thousands
    // of entries) — never useful as a "recommendation".
    const wantDell   = vendor === 'dell' || (!vendor && !!model);
    const wantStatic = !vendor || vendor !== 'dell';

    if (wantDell && model && this._asyncProviders.dell) {
      try {
        const dellResults = await this._asyncProviders.dell(model, { os: osLabel, systemModel: model });
        for (const d of dellResults) {
          push(d, { matchScore: scoreMatch(d, { model, os: osLabel }), matchedVia: 'dell-catalog' });
        }
      } catch (err) {
        // Degrade gracefully — Dell catalog is not critical
      }
    }

    // ── 2. Static vendor providers ──
    if (wantStatic) {
      const providers = vendor ? [STATIC_PROVIDERS[vendor]].filter(Boolean) : Object.values(STATIC_PROVIDERS);
      for (const provider of providers) {
        for (const d of provider.getDrivers()) {
          if (osLabel && !d.os.includes(osLabel)) continue;
          push(d, { matchScore: scoreMatch(d, { model, os: osLabel }), matchedVia: 'static-catalog' });
        }
      }
    }

    // ── 3. Platform-specific hardware ID matching ──
    if (osLabel === 'linux' && hardwareIds.length > 0) {
      const parsed  = LinuxMatcher.parseHardwareIds(hardwareIds);
      const matched = LinuxMatcher.matchFromHardware(parsed, { manufacturer: manufacturer || '' });
      for (const d of matched) push(d);
      for (const d of LinuxMatcher.universalRecommendations()) push(d);
    }

    if (osLabel === 'windows' && hardwareIds.length > 0) {
      // Windows PnP IDs are informational — the static/live catalog already covers Windows.
      // Parse them to enrich matching (future: map to INF hardware IDs).
      const parsed = WindowsMatcher.parseHardwareIds(hardwareIds);
      // Log parsed IDs for diagnostics; can be extended later.
      void parsed;
    }

    // ── 4. Sort: higher score first; within same score prefer platform-matched ──
    results.sort((a, b) => (b.matchScore || 0) - (a.matchScore || 0));

    return results;
  }

  /**
   * Return all known vendor keys (static + registered async providers).
   * @returns {string[]}
   */
  getVendorKeys() {
    return [...new Set([...Object.keys(STATIC_PROVIDERS), ...Object.keys(this._asyncProviders)])];
  }
}

// ─── Module exports ───────────────────────────────────────────────────────────

module.exports = {
  DriverCatalog,
  // Named platform matchers for direct use
  WindowsMatcher,
  LinuxMatcher,
  // Named vendor providers for direct use
  HpProvider,
  LenovoProvider,
  // Scoring utilities
  normalizeVendor,
  normalizeOs,
  scoreMatch,
};
