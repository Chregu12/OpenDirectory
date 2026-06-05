'use strict';

const ComplianceStatus = require('../domain/value-objects/ComplianceStatus');

describe('ComplianceStatus value object', () => {
  describe('constructor', () => {
    it('creates with isCompliant=true and no violations', () => {
      const status = new ComplianceStatus(true, []);
      expect(status.isCompliant).toBe(true);
      expect(status.violations).toEqual([]);
      expect(status.hasViolations).toBe(false);
    });

    it('creates with isCompliant=false and violations', () => {
      const status = new ComplianceStatus(false, ['no-antivirus', 'os-outdated']);
      expect(status.isCompliant).toBe(false);
      expect(status.violations).toEqual(['no-antivirus', 'os-outdated']);
      expect(status.hasViolations).toBe(true);
    });

    it('coerces isCompliant to boolean', () => {
      const status = new ComplianceStatus(1, []);
      expect(status.isCompliant).toBe(true);
    });

    it('defaults violations to [] when non-array passed', () => {
      const status = new ComplianceStatus(false, null);
      expect(status.violations).toEqual([]);
    });

    it('returns a copy of violations (immutability)', () => {
      const violations = ['v1'];
      const status = new ComplianceStatus(false, violations);
      const retrieved = status.violations;
      retrieved.push('v2');
      expect(status.violations).toHaveLength(1);
    });
  });

  describe('static compliant()', () => {
    it('creates a compliant status', () => {
      const status = ComplianceStatus.compliant();
      expect(status.isCompliant).toBe(true);
      expect(status.violations).toEqual([]);
    });
  });

  describe('static nonCompliant()', () => {
    it('creates a non-compliant status with violations', () => {
      const violations = ['firewall-disabled'];
      const status = ComplianceStatus.nonCompliant(violations);
      expect(status.isCompliant).toBe(false);
      expect(status.violations).toEqual(violations);
    });
  });

  describe('hasViolations getter', () => {
    it('returns false when violations array is empty', () => {
      const status = new ComplianceStatus(true, []);
      expect(status.hasViolations).toBe(false);
    });

    it('returns true when there are violations', () => {
      const status = new ComplianceStatus(false, ['v1']);
      expect(status.hasViolations).toBe(true);
    });
  });
});
