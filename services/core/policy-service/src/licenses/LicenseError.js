'use strict';

class LicenseError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

module.exports = { LicenseError };
