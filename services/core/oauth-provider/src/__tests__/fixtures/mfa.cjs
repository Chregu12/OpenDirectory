'use strict';

const { totp } = require('../../MfaAuthority');
const factors = new Map();

async function nextOtp(username) {
  const factor = factors.get(username); if (!factor) return undefined;
  while (true) {
    const current = Math.floor(Date.now() / 30000); const next = Math.max(current - 1, factor.lastCounter + 1);
    if (next <= current + 1) { factor.lastCounter = next; return totp(factor.secret, next); }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
}
function rememberFactor(username, secret, lastCounter) { factors.set(username, { secret, lastCounter }); }

module.exports = { nextOtp, rememberFactor };
