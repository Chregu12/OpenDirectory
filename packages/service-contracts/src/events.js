'use strict';

/**
 * Domain event type constants for all OpenDirectory services.
 *
 * Using shared constants prevents typos and gives every service a common
 * vocabulary without sharing implementation code.
 *
 * Two formats are exported for backwards compatibility:
 *   1. Legacy PascalCase string constants  (e.g. DEVICE_ENROLLED = 'DeviceEnrolled')
 *   2. Events object with dot-notation routing keys for RabbitMQ
 *      (e.g. Events.DEVICE_ENROLLED = 'device.enrolled')
 */

// ── Device service ────────────────────────────────────────────────────────────
const DEVICE_ENROLLED           = 'DeviceEnrolled';
const DEVICE_UPDATED            = 'DeviceUpdated';
const DEVICE_DELETED            = 'DeviceDeleted';
const DEVICE_COMPLIANCE_CHANGED = 'DeviceComplianceChanged';
const DEVICE_THREAT_DETECTED    = 'DeviceThreatDetected';
const DEVICE_GEOFENCE_VIOLATION = 'DeviceGeofenceViolation';

// ── Policy service ────────────────────────────────────────────────────────────
const POLICY_CREATED   = 'PolicyCreated';
const POLICY_UPDATED   = 'PolicyUpdated';
const POLICY_ENABLED   = 'PolicyEnabled';
const POLICY_DISABLED  = 'PolicyDisabled';
const POLICY_DELETED   = 'PolicyDeleted';
const POLICY_APPLIED   = 'PolicyApplied';
const RULE_ADDED       = 'PolicyRuleAdded';
const RULE_REMOVED     = 'PolicyRuleRemoved';

// ── Blueprint service ─────────────────────────────────────────────────────────
const BLUEPRINT_CREATED  = 'BlueprintCreated';
const BLUEPRINT_UPDATED  = 'BlueprintUpdated';
const BLUEPRINT_DEPLOYED = 'BlueprintDeployed';
const BLUEPRINT_DELETED  = 'BlueprintDeleted';

// ── Update service ────────────────────────────────────────────────────────────
const UPDATE_CONFIGURED  = 'UpdateConfigured';
const UPDATE_TRIGGERED   = 'UpdateTriggered';
const UPDATE_COMPLETED   = 'UpdateCompleted';
const UPDATE_FAILED      = 'UpdateFailed';

// ── Backup / DR service ───────────────────────────────────────────────────────
const BACKUP_TRIGGERED   = 'BackupTriggered';
const BACKUP_COMPLETED   = 'BackupCompleted';
const BACKUP_FAILED      = 'BackupFailed';
const FAILOVER_INITIATED = 'FailoverInitiated';
const FAILOVER_COMPLETED = 'FailoverCompleted';

// ── License service ───────────────────────────────────────────────────────────
const LICENSE_ASSIGNED   = 'LicenseAssigned';
const LICENSE_REVOKED    = 'LicenseRevoked';
const LICENSE_EXPIRED    = 'LicenseExpired';

/**
 * RabbitMQ routing-key constants for the opendirectory.events exchange.
 *
 * Pattern: <domain>.<entity>.<action>   (topic exchange, use # and * for wildcards)
 *
 * @example
 *   bus.publish(Events.DEVICE_ENROLLED, { deviceId, hostname, platform });
 *   bus.subscribe('my-queue', [Events.DEVICE_ENROLLED, 'device.#'], handler);
 */
const Events = {
  // ── Device ───────────────────────────────────────────────────────────────
  DEVICE_ENROLLED:      'device.enrolled',
  DEVICE_SEEN:          'device.seen',
  DEVICE_COMPLIANT:     'device.compliant',
  DEVICE_NON_COMPLIANT: 'device.non_compliant',
  DEVICE_LOST:          'device.lost',
  DEVICE_WIPED:         'device.wiped',

  // ── App / Install ────────────────────────────────────────────────────────
  APP_PACKAGE_UPLOADED:    'app.package.uploaded',
  APP_INSTALL_REQUESTED:   'app.install.requested',
  APP_INSTALL_COMPLETED:   'app.install.completed',
  APP_INSTALL_FAILED:      'app.install.failed',
  APP_UNINSTALL_COMPLETED: 'app.uninstall.completed',

  // ── Identity / Auth ──────────────────────────────────────────────────────
  IDENTITY_LOGIN_SUCCESS:  'identity.login.success',
  IDENTITY_LOGIN_FAILED:   'identity.login.failed',
  IDENTITY_USER_CREATED:   'identity.user.created',
  IDENTITY_USER_DELETED:   'identity.user.deleted',
  IDENTITY_MFA_ENABLED:    'identity.mfa.enabled',
  IDENTITY_MFA_DISABLED:   'identity.mfa.disabled',
  IDENTITY_PASSWORD_RESET: 'identity.password.reset',
  IDENTITY_ACCOUNT_LOCKED: 'identity.account.locked',

  // ── Policy ───────────────────────────────────────────────────────────────
  POLICY_CREATED:  'policy.created',
  POLICY_UPDATED:  'policy.updated',
  POLICY_APPLIED:  'policy.applied',
  POLICY_VIOLATED: 'policy.violated',

  // ── PIM ──────────────────────────────────────────────────────────────────
  PIM_ACCESS_GRANTED:   'security.pim.granted',
  PIM_ACCESS_REVOKED:   'security.pim.revoked',
  PIM_ACCESS_EXPIRED:   'security.pim.expired',
  PIM_ACCESS_REQUESTED: 'security.pim.requested',

  // ── Backup ───────────────────────────────────────────────────────────────
  BACKUP_STARTED:   'system.backup.started',
  BACKUP_COMPLETED: 'system.backup.completed',
  BACKUP_FAILED:    'system.backup.failed',

  // ── Certificate ──────────────────────────────────────────────────────────
  CERT_ISSUED:   'security.cert.issued',
  CERT_EXPIRING: 'security.cert.expiring',
  CERT_REVOKED:  'security.cert.revoked',

  // ── Compliance ───────────────────────────────────────────────────────────
  COMPLIANCE_PASSED: 'compliance.passed',
  COMPLIANCE_FAILED: 'compliance.failed',

  // ── Admin ────────────────────────────────────────────────────────────────
  ADMIN_CONFIG_CHANGED:    'admin.config.changed',
  ADMIN_SERVICE_RESTARTED: 'admin.service.restarted',
};

module.exports = {
  // Legacy PascalCase constants (backwards-compatible)
  DEVICE_ENROLLED,
  DEVICE_UPDATED,
  DEVICE_DELETED,
  DEVICE_COMPLIANCE_CHANGED,
  DEVICE_THREAT_DETECTED,
  DEVICE_GEOFENCE_VIOLATION,
  // Policy
  POLICY_CREATED,
  POLICY_UPDATED,
  POLICY_ENABLED,
  POLICY_DISABLED,
  POLICY_DELETED,
  POLICY_APPLIED,
  RULE_ADDED,
  RULE_REMOVED,
  // Blueprint
  BLUEPRINT_CREATED,
  BLUEPRINT_UPDATED,
  BLUEPRINT_DEPLOYED,
  BLUEPRINT_DELETED,
  // Update
  UPDATE_CONFIGURED,
  UPDATE_TRIGGERED,
  UPDATE_COMPLETED,
  UPDATE_FAILED,
  // Backup / DR
  BACKUP_TRIGGERED,
  BACKUP_COMPLETED,
  BACKUP_FAILED,
  FAILOVER_INITIATED,
  FAILOVER_COMPLETED,
  // License
  LICENSE_ASSIGNED,
  LICENSE_REVOKED,
  LICENSE_EXPIRED,

  // RabbitMQ routing-key object
  Events,
};
