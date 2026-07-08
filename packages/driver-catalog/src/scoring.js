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
function tokenize(s) {
  return s.split(/\s+/).filter(Boolean);
}

// True if every token of the shorter token list appears as a whole token
// (not merely a substring) in the longer token list. Plain substring
// matching would let a short/partial model string like "T1" match an
// unrelated model such as "ThinkPad T16 Gen 1" (T16 is a different model,
// not a more specific T1) — comparing whole tokens avoids that.
function modelTokensMatch(aTokens, bTokens) {
  const [shorter, longer] = aTokens.length <= bTokens.length ? [aTokens, bTokens] : [bTokens, aTokens];
  if (shorter.length === 0) return false;
  // A single-character token (e.g. "1" or "X") is too generic to count as a
  // meaningful model match on its own — require at least one token with
  // some specificity (length >= 2, e.g. "G9", "T14") in the shorter list.
  if (!shorter.some(t => t.length >= 2)) return false;
  return shorter.every(t => longer.includes(t));
}

function scoreMatch(driver, { model, os }) {
  let score = 0;

  if (model && Array.isArray(driver.models)) {
    const mTokens = tokenize(model.toLowerCase());
    for (const dm of driver.models) {
      const dmTokens = tokenize(dm.toLowerCase());
      if (modelTokensMatch(mTokens, dmTokens)) {
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
