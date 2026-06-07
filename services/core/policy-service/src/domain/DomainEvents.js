'use strict';

/**
 * Domain event type constants shared across policy-service aggregates.
 *
 * Using constants prevents typos and makes event names discoverable.
 */

// Policy lifecycle events
const POLICY_CREATED   = 'PolicyCreated';
const POLICY_UPDATED   = 'PolicyUpdated';
const POLICY_ENABLED   = 'PolicyEnabled';
const POLICY_DISABLED  = 'PolicyDisabled';
const POLICY_DELETED   = 'PolicyDeleted';
const POLICY_APPLIED   = 'PolicyApplied';
const RULE_ADDED       = 'PolicyRuleAdded';
const RULE_REMOVED     = 'PolicyRuleRemoved';

// Blueprint lifecycle events
const BLUEPRINT_CREATED   = 'BlueprintCreated';
const BLUEPRINT_UPDATED   = 'BlueprintUpdated';
const BLUEPRINT_DEPLOYED  = 'BlueprintDeployed';
const BLUEPRINT_DELETED   = 'BlueprintDeleted';

module.exports = {
  POLICY_CREATED,
  POLICY_UPDATED,
  POLICY_ENABLED,
  POLICY_DISABLED,
  POLICY_DELETED,
  POLICY_APPLIED,
  RULE_ADDED,
  RULE_REMOVED,
  BLUEPRINT_CREATED,
  BLUEPRINT_UPDATED,
  BLUEPRINT_DEPLOYED,
  BLUEPRINT_DELETED
};
