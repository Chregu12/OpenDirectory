'use strict';

/**
 * Domain event type constants for all OpenDirectory services.
 *
 * Using shared constants prevents typos and gives every service a common
 * vocabulary without sharing implementation code.
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

module.exports = {
  // Device
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
  LICENSE_EXPIRED
};
