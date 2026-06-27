'use strict';

// ─── Vendor normalisation ─────────────────────────────────────────────────────

const VENDOR_ALIASES = [
  { key: 'dell',     patterns: ['dell'] },
  { key: 'hp',       patterns: ['hp', 'hewlett', 'h.p.'] },
  { key: 'lenovo',   patterns: ['lenovo'] },
  { key: 'apple',    patterns: ['apple'] },
  { key: 'microsoft',patterns: ['microsoft'] },
  { key: 'asus',     patterns: ['asus', 'asustek'] },
  { key: 'acer',     patterns: ['acer'] },
  { key: 'toshiba',  patterns: ['toshiba', 'dynabook'] },
  { key: 'fujitsu',  patterns: ['fujitsu', 'fujitsu siemens'] },
  { key: 'samsung',  patterns: ['samsung'] },
  { key: 'panasonic',patterns: ['panasonic', 'matsushita'] },
  { key: 'lg',       patterns: ['lg electronics', 'lg'] },
];

function normalizeVendor(raw) {
  if (!raw) return null;
  const v = raw.toLowerCase().trim();
  for (const { key, patterns } of VENDOR_ALIASES) {
    if (patterns.some(p => v.includes(p))) return key;
  }
  return v;
}

// ─── OS normalisation ─────────────────────────────────────────────────────────

function normalizeOs(raw) {
  if (!raw) return null;
  const s = raw.toLowerCase();
  if (s.includes('windows')) return 'windows';
  if (s.includes('linux'))   return 'linux';
  if (s.includes('mac') || s.includes('darwin') || s.includes('macos')) return 'macos';
  return null;
}

// ─── Match scoring ────────────────────────────────────────────────────────────

/**
 * Score a driver entry against the device's known model + OS.
 * Higher score = better match.
 *
 * @param {{ models?: string[], os?: string[] }} driver
 * @param {{ model?: string, os?: string }}      device
 * @returns {number}
 */
function scoreMatch(driver, { model, os }) {
  let score = 0;

  if (model && Array.isArray(driver.models)) {
    const m = model.toLowerCase();
    for (const dm of driver.models) {
      const dml = dm.toLowerCase();
      if (dml.includes(m) || m.includes(dml)) {
        score += 20;
        break;
      }
    }
  }

  if (os && Array.isArray(driver.os) && driver.os.includes(os.toLowerCase())) {
    score += 10;
  }

  return score;
}

module.exports = { normalizeVendor, normalizeOs, scoreMatch };
