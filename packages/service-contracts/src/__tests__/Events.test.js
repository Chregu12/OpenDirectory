'use strict';

const eventsModule = require('../events');

describe('Events module', () => {
  describe('legacy PascalCase constants', () => {
    it('exports DEVICE_ENROLLED as PascalCase string', () => {
      expect(eventsModule.DEVICE_ENROLLED).toBe('DeviceEnrolled');
    });

    it('exports DEVICE_UPDATED', () => {
      expect(eventsModule.DEVICE_UPDATED).toBe('DeviceUpdated');
    });

    it('exports DEVICE_DELETED', () => {
      expect(eventsModule.DEVICE_DELETED).toBe('DeviceDeleted');
    });

    it('exports DEVICE_COMPLIANCE_CHANGED', () => {
      expect(eventsModule.DEVICE_COMPLIANCE_CHANGED).toBe('DeviceComplianceChanged');
    });

    it('exports DEVICE_THREAT_DETECTED', () => {
      expect(eventsModule.DEVICE_THREAT_DETECTED).toBe('DeviceThreatDetected');
    });

    it('exports POLICY_CREATED', () => {
      expect(eventsModule.POLICY_CREATED).toBe('PolicyCreated');
    });

    it('exports POLICY_UPDATED', () => {
      expect(eventsModule.POLICY_UPDATED).toBe('PolicyUpdated');
    });

    it('exports POLICY_ENABLED', () => {
      expect(eventsModule.POLICY_ENABLED).toBe('PolicyEnabled');
    });

    it('exports POLICY_DISABLED', () => {
      expect(eventsModule.POLICY_DISABLED).toBe('PolicyDisabled');
    });

    it('exports POLICY_DELETED', () => {
      expect(eventsModule.POLICY_DELETED).toBe('PolicyDeleted');
    });

    it('exports POLICY_APPLIED', () => {
      expect(eventsModule.POLICY_APPLIED).toBe('PolicyApplied');
    });

    it('exports RULE_ADDED', () => {
      expect(eventsModule.RULE_ADDED).toBe('PolicyRuleAdded');
    });

    it('exports RULE_REMOVED', () => {
      expect(eventsModule.RULE_REMOVED).toBe('PolicyRuleRemoved');
    });

    it('exports BLUEPRINT_CREATED', () => {
      expect(eventsModule.BLUEPRINT_CREATED).toBe('BlueprintCreated');
    });

    it('exports BLUEPRINT_UPDATED', () => {
      expect(eventsModule.BLUEPRINT_UPDATED).toBe('BlueprintUpdated');
    });

    it('exports BLUEPRINT_DEPLOYED', () => {
      expect(eventsModule.BLUEPRINT_DEPLOYED).toBe('BlueprintDeployed');
    });

    it('exports BLUEPRINT_DELETED', () => {
      expect(eventsModule.BLUEPRINT_DELETED).toBe('BlueprintDeleted');
    });

    it('exports UPDATE_CONFIGURED / UPDATE_TRIGGERED / UPDATE_COMPLETED / UPDATE_FAILED', () => {
      expect(eventsModule.UPDATE_CONFIGURED).toBe('UpdateConfigured');
      expect(eventsModule.UPDATE_TRIGGERED).toBe('UpdateTriggered');
      expect(eventsModule.UPDATE_COMPLETED).toBe('UpdateCompleted');
      expect(eventsModule.UPDATE_FAILED).toBe('UpdateFailed');
    });

    it('exports BACKUP constants', () => {
      expect(eventsModule.BACKUP_TRIGGERED).toBe('BackupTriggered');
      expect(eventsModule.BACKUP_COMPLETED).toBe('BackupCompleted');
      expect(eventsModule.BACKUP_FAILED).toBe('BackupFailed');
    });

    it('exports FAILOVER constants', () => {
      expect(eventsModule.FAILOVER_INITIATED).toBe('FailoverInitiated');
      expect(eventsModule.FAILOVER_COMPLETED).toBe('FailoverCompleted');
    });

    it('exports LICENSE constants', () => {
      expect(eventsModule.LICENSE_ASSIGNED).toBe('LicenseAssigned');
      expect(eventsModule.LICENSE_REVOKED).toBe('LicenseRevoked');
      expect(eventsModule.LICENSE_EXPIRED).toBe('LicenseExpired');
    });
  });

  describe('Events routing key object', () => {
    const { Events } = eventsModule;

    it('exports Events object', () => {
      expect(Events).toBeTruthy();
      expect(typeof Events).toBe('object');
    });

    it('DEVICE_ENROLLED uses dot-notation routing key', () => {
      expect(Events.DEVICE_ENROLLED).toBe('device.enrolled');
    });

    it('DEVICE_SEEN', () => {
      expect(Events.DEVICE_SEEN).toBe('device.seen');
    });

    it('DEVICE_COMPLIANT', () => {
      expect(Events.DEVICE_COMPLIANT).toBe('device.compliant');
    });

    it('DEVICE_NON_COMPLIANT', () => {
      expect(Events.DEVICE_NON_COMPLIANT).toBe('device.non_compliant');
    });

    it('APP_INSTALL_REQUESTED', () => {
      expect(Events.APP_INSTALL_REQUESTED).toBe('app.install.requested');
    });

    it('APP_INSTALL_COMPLETED', () => {
      expect(Events.APP_INSTALL_COMPLETED).toBe('app.install.completed');
    });

    it('APP_INSTALL_FAILED', () => {
      expect(Events.APP_INSTALL_FAILED).toBe('app.install.failed');
    });

    it('IDENTITY_LOGIN_SUCCESS', () => {
      expect(Events.IDENTITY_LOGIN_SUCCESS).toBe('identity.login.success');
    });

    it('IDENTITY_USER_CREATED', () => {
      expect(Events.IDENTITY_USER_CREATED).toBe('identity.user.created');
    });

    it('IDENTITY_USER_DELETED', () => {
      expect(Events.IDENTITY_USER_DELETED).toBe('identity.user.deleted');
    });

    it('IDENTITY_MFA_ENABLED', () => {
      expect(Events.IDENTITY_MFA_ENABLED).toBe('identity.mfa.enabled');
    });

    it('IDENTITY_PASSWORD_RESET', () => {
      expect(Events.IDENTITY_PASSWORD_RESET).toBe('identity.password.reset');
    });

    it('IDENTITY_ACCOUNT_LOCKED', () => {
      expect(Events.IDENTITY_ACCOUNT_LOCKED).toBe('identity.account.locked');
    });

    it('POLICY_CREATED routing key', () => {
      expect(Events.POLICY_CREATED).toBe('policy.created');
    });

    it('POLICY_UPDATED routing key', () => {
      expect(Events.POLICY_UPDATED).toBe('policy.updated');
    });

    it('POLICY_APPLIED routing key', () => {
      expect(Events.POLICY_APPLIED).toBe('policy.applied');
    });

    it('COMPLIANCE_PASSED / COMPLIANCE_FAILED', () => {
      expect(Events.COMPLIANCE_PASSED).toBe('compliance.passed');
      expect(Events.COMPLIANCE_FAILED).toBe('compliance.failed');
    });

    it('BACKUP_STARTED / BACKUP_COMPLETED / BACKUP_FAILED', () => {
      expect(Events.BACKUP_STARTED).toBe('system.backup.started');
      expect(Events.BACKUP_COMPLETED).toBe('system.backup.completed');
      expect(Events.BACKUP_FAILED).toBe('system.backup.failed');
    });

    it('CERT_ISSUED / CERT_EXPIRING / CERT_REVOKED', () => {
      expect(Events.CERT_ISSUED).toBe('security.cert.issued');
      expect(Events.CERT_EXPIRING).toBe('security.cert.expiring');
      expect(Events.CERT_REVOKED).toBe('security.cert.revoked');
    });

    it('PIM events', () => {
      expect(Events.PIM_ACCESS_GRANTED).toBe('security.pim.granted');
      expect(Events.PIM_ACCESS_REVOKED).toBe('security.pim.revoked');
    });
  });

  describe('module shape', () => {
    it('all exports are strings or the Events object', () => {
      for (const [key, value] of Object.entries(eventsModule)) {
        if (key === 'Events') {
          expect(typeof value).toBe('object');
        } else {
          expect(typeof value).toBe('string');
        }
      }
    });

    it('Events object values are all strings', () => {
      const { Events } = eventsModule;
      for (const value of Object.values(Events)) {
        expect(typeof value).toBe('string');
      }
    });

    it('Events routing keys use dot notation', () => {
      const { Events } = eventsModule;
      for (const value of Object.values(Events)) {
        expect(value).toMatch(/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/);
      }
    });
  });
});
