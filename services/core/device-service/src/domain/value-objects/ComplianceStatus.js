'use strict';

class ComplianceStatus {
  constructor(isCompliant, violations = []) {
    this._isCompliant = Boolean(isCompliant);
    this._violations = Array.isArray(violations) ? [...violations] : [];
  }
  get isCompliant() { return this._isCompliant; }
  get violations() { return [...this._violations]; }
  get hasViolations() { return this._violations.length > 0; }
  static compliant() { return new ComplianceStatus(true, []); }
  static nonCompliant(violations) { return new ComplianceStatus(false, violations); }
}

module.exports = ComplianceStatus;
