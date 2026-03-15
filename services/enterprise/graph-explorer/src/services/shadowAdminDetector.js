/**
 * ShadowAdminDetector - Identifies accounts with hidden administrative privileges
 *
 * Shadow admins are principals that are not flagged with adminCount=1 in AD
 * but can effectively perform admin-level operations due to:
 *   - Nested group memberships that transitively reach a privileged group
 *   - ACL delegations (WriteDACL, WriteOwner, GenericAll/Write) on privileged objects
 *   - Ownership of privileged objects
 *   - Ability to reset passwords of admin accounts
 *   - Ability to modify group membership of privileged groups
 *   - Service accounts with excessive permissions
 *   - Application consent grants that provide admin-equivalent API permissions
 *
 * A shadow admin is dangerous because it bypasses typical admin-account monitoring.
 */

'use strict';

const { NODE_TYPES, EDGE_TYPES, RISK_LEVELS } = require('./graphBuilder');

// Groups whose effective members are considered admins
const PRIVILEGED_GROUP_IDS = new Set([
  'grp-domain-admins',
  'grp-enterprise-admins',
  'grp-schema-admins',
  'grp-account-operators',
  'grp-server-operators',
  'grp-backup-operators',
]);

// Permission nodes that represent admin-equivalent roles
const ADMIN_EQUIVALENT_PERMISSIONS = new Set([
  'perm-global-admin',
  'perm-user-admin',
  'perm-exchange-admin',
]);

// Edge types that, when targeting a privileged object, make the source a shadow admin
const SHADOW_ADMIN_EDGE_TYPES = new Set([
  EDGE_TYPES.WRITE_DACL,
  EDGE_TYPES.WRITE_OWNER,
  EDGE_TYPES.GENERIC_ALL,
  EDGE_TYPES.GENERIC_WRITE,
  EDGE_TYPES.FORCE_CHANGE_PASSWORD,
  EDGE_TYPES.CAN_ADD_MEMBER,
  EDGE_TYPES.ADD_SELF,
]);

class ShadowAdminDetector {
  constructor(graphBuilder, logger) {
    this.graph = graphBuilder;
    this.logger = logger;
    this.shadowAdmins = [];
    this.lastAnalysis = null;
  }

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------

  /**
   * Run full shadow-admin detection. Returns array of shadow admin findings.
   */
  detect() {
    const t0 = Date.now();
    this.logger.info('Starting shadow admin detection...');
    this.shadowAdmins = [];

    // Step 1: Build set of known (explicit) admins
    const knownAdmins = this._buildKnownAdminSet();
    this.logger.info(`Known explicit admins: ${knownAdmins.size}`);

    // Step 2: Detect each category of shadow admin
    this._detectNestedGroupShadowAdmins(knownAdmins);
    this._detectACLBasedShadowAdmins(knownAdmins);
    this._detectPasswordResetShadowAdmins(knownAdmins);
    this._detectGroupModificationShadowAdmins(knownAdmins);
    this._detectServiceAccountShadowAdmins(knownAdmins);
    this._detectDelegationShadowAdmins(knownAdmins);

    // De-duplicate by principal
    this._consolidateFindings();

    this.lastAnalysis = {
      timestamp: new Date().toISOString(),
      durationMs: Date.now() - t0,
      knownAdminCount: knownAdmins.size,
      shadowAdminCount: this.shadowAdmins.length,
      bySeverity: this._countBySeverity(),
      byTechnique: this._countByTechnique(),
    };

    this.logger.info('Shadow admin detection complete', this.lastAnalysis);
    return this.shadowAdmins;
  }

  getShadowAdmins(filters = {}) {
    let results = [...this.shadowAdmins];
    if (filters.severity) {
      results = results.filter((r) => r.severity === filters.severity);
    }
    if (filters.technique) {
      results = results.filter((r) => r.techniques.includes(filters.technique));
    }
    if (filters.principalType) {
      results = results.filter((r) => r.principal.type === filters.principalType);
    }
    return results;
  }

  getSummary() {
    return {
      ...this.lastAnalysis,
      shadowAdmins: this.shadowAdmins.map((sa) => ({
        id: sa.id,
        principalId: sa.principal.id,
        principalName: sa.principal.name,
        principalType: sa.principal.type,
        severity: sa.severity,
        techniques: sa.techniques,
        reachablePrivilegedGroups: sa.reachablePrivilegedGroups.map((g) => g.name),
        effectivePermissions: sa.effectivePermissions,
      })),
    };
  }

  // -----------------------------------------------------------------------
  // Build known admin set
  // -----------------------------------------------------------------------

  _buildKnownAdminSet() {
    const knownAdmins = new Set();

    // Users with adminCount=1
    for (const user of this.graph.getNodesByType(NODE_TYPES.USER)) {
      if (user.properties.adminCount === 1) {
        knownAdmins.add(user.id);
      }
    }

    // Direct members of privileged groups
    for (const groupId of PRIVILEGED_GROUP_IDS) {
      const incoming = this.graph.getIncomingEdges(groupId);
      for (const edge of incoming) {
        if (edge.type === EDGE_TYPES.MEMBER_OF) {
          const member = this.graph.getNode(edge.source);
          if (member && member.type === NODE_TYPES.USER) {
            knownAdmins.add(member.id);
          }
        }
      }
    }

    // Users with admin-equivalent role assignments
    for (const permId of ADMIN_EQUIVALENT_PERMISSIONS) {
      const incoming = this.graph.getIncomingEdges(permId);
      for (const edge of incoming) {
        if (edge.type === EDGE_TYPES.HAS_PERMISSION) {
          const member = this.graph.getNode(edge.source);
          if (member && member.type === NODE_TYPES.USER) {
            knownAdmins.add(member.id);
          }
        }
      }
    }

    return knownAdmins;
  }

  // -----------------------------------------------------------------------
  // Detection methods
  // -----------------------------------------------------------------------

  _detectNestedGroupShadowAdmins(knownAdmins) {
    const users = this.graph.getNodesByType(NODE_TYPES.USER);

    for (const user of users) {
      if (knownAdmins.has(user.id)) continue;

      // BFS through MemberOf to find transitive privileged group membership
      const reachable = this._findReachablePrivilegedGroups(user.id);

      if (reachable.length > 0) {
        this._addFinding({
          principal: user,
          severity: RISK_LEVELS.CRITICAL,
          technique: 'NestedGroupMembership',
          title: `Shadow admin via nested groups: ${user.displayName}`,
          description: `User "${user.displayName}" (${user.properties.upn || user.name}) is not flagged as an admin (adminCount=0) but can transitively reach the following privileged groups through nested membership: ${reachable.map((g) => g.name).join(', ')}. This user should be treated as an admin for monitoring purposes.`,
          reachablePrivilegedGroups: reachable,
          effectivePermissions: this._deriveEffectivePermissions(reachable),
          membershipChains: this._traceMembershipChains(user.id, reachable),
          recommendations: [
            'Set adminCount=1 on this account',
            'Apply the same security controls as known admins',
            'Flatten unnecessary nested group structures',
            'Enable MFA and Conditional Access',
            'Consider using PIM for just-in-time access',
          ],
        });
      }
    }
  }

  _detectACLBasedShadowAdmins(knownAdmins) {
    for (const edgeType of SHADOW_ADMIN_EDGE_TYPES) {
      const edgeIds = this.graph.edgesByType.get(edgeType);
      if (!edgeIds) continue;

      for (const eid of edgeIds) {
        const edge = this.graph.getEdge(eid);
        const source = this.graph.getNode(edge.source);
        const target = this.graph.getNode(edge.target);
        if (!source || !target) continue;

        // Skip if source is already a known admin
        if (knownAdmins.has(source.id)) continue;

        // Only flag if target is a privileged group, OU, or admin user
        const targetIsPrivileged =
          PRIVILEGED_GROUP_IDS.has(target.id) ||
          (target.type === NODE_TYPES.OU && target.properties?.level === 0) ||
          (target.type === NODE_TYPES.USER && target.properties?.adminCount === 1);

        if (!targetIsPrivileged) continue;

        // Resolve the principals (could be a group -> members)
        const affectedPrincipals = this._resolveGroupMembers(source);

        for (const principal of affectedPrincipals) {
          if (knownAdmins.has(principal.id)) continue;

          this._addFinding({
            principal,
            severity: RISK_LEVELS.CRITICAL,
            technique: 'ACLDelegation',
            title: `Shadow admin via ACL: ${principal.displayName || principal.name} (${edgeType} on ${target.name})`,
            description: `"${principal.displayName || principal.name}" has ${edgeType} permission on the privileged object "${target.name}" (${target.type}). This ACL grants admin-equivalent capabilities without the account being flagged as a privileged account.`,
            reachablePrivilegedGroups: [target],
            effectivePermissions: [edgeType],
            recommendations: [
              `Remove or restrict the ${edgeType} ACE from "${target.name}"`,
              'Audit all non-default ACLs on Tier 0 objects',
              'Flag this account in your PAM solution',
              'Add this account to Protected Users group',
            ],
          });
        }
      }
    }
  }

  _detectPasswordResetShadowAdmins(knownAdmins) {
    const resetEdgeIds = this.graph.edgesByType.get(EDGE_TYPES.CAN_RESET_PASSWORD);
    if (!resetEdgeIds) return;

    for (const eid of resetEdgeIds) {
      const edge = this.graph.getEdge(eid);
      const source = this.graph.getNode(edge.source);
      const target = this.graph.getNode(edge.target);
      if (!source || !target) continue;

      // Check if the target of the password reset is an admin or has privileged access
      const targetIsAdmin = knownAdmins.has(target.id);
      const targetHasPrivAccess = this._hasPrivilegedAccess(target.id);

      if (!targetIsAdmin && !targetHasPrivAccess) continue;

      const affectedPrincipals = this._resolveGroupMembers(source);

      for (const principal of affectedPrincipals) {
        if (knownAdmins.has(principal.id)) continue;

        this._addFinding({
          principal,
          severity: RISK_LEVELS.HIGH,
          technique: 'PasswordResetDelegation',
          title: `Shadow admin via password reset: ${principal.displayName || principal.name} can reset ${target.name}`,
          description: `"${principal.displayName || principal.name}" can reset the password of "${target.displayName || target.name}", who ${targetIsAdmin ? 'is a known admin' : 'has privileged access'}. By resetting the password and logging in as the target, this principal gains admin-equivalent access.`,
          reachablePrivilegedGroups: [],
          effectivePermissions: ['CanResetPassword'],
          intermediateTarget: { id: target.id, name: target.name, type: target.type },
          recommendations: [
            'Restrict password reset delegation scope',
            'Do not allow password resets for admin accounts via delegation',
            'Require approval workflows for admin password resets',
            'Monitor all password reset events for privileged accounts',
          ],
        });
      }
    }
  }

  _detectGroupModificationShadowAdmins(knownAdmins) {
    const addMemberEdgeIds = this.graph.edgesByType.get(EDGE_TYPES.CAN_ADD_MEMBER);
    if (!addMemberEdgeIds) return;

    for (const eid of addMemberEdgeIds) {
      const edge = this.graph.getEdge(eid);
      const source = this.graph.getNode(edge.source);
      const target = this.graph.getNode(edge.target);
      if (!source || !target) continue;

      // Is the target group privileged or can lead to a privileged group?
      const targetReachable = this._findReachablePrivilegedGroupsFromGroup(target.id);
      const targetIsPrivileged = PRIVILEGED_GROUP_IDS.has(target.id) || targetReachable.length > 0;

      if (!targetIsPrivileged) continue;

      const affectedPrincipals = this._resolveGroupMembers(source);

      for (const principal of affectedPrincipals) {
        if (knownAdmins.has(principal.id)) continue;

        this._addFinding({
          principal,
          severity: RISK_LEVELS.HIGH,
          technique: 'GroupModification',
          title: `Shadow admin via group modification: ${principal.displayName || principal.name} can add members to ${target.name}`,
          description: `"${principal.displayName || principal.name}" can add members to "${target.name}"${targetReachable.length > 0 ? `, which transitively leads to: ${targetReachable.map((g) => g.name).join(', ')}` : ''}. This allows the principal to grant themselves (or others) administrative access.`,
          reachablePrivilegedGroups: PRIVILEGED_GROUP_IDS.has(target.id) ? [target] : targetReachable,
          effectivePermissions: ['CanAddMember'],
          recommendations: [
            'Restrict group modification rights',
            'Enable group modification auditing',
            'Use privileged access groups with approval workflows',
            'Monitor membership changes on sensitive groups',
          ],
        });
      }
    }
  }

  _detectServiceAccountShadowAdmins(knownAdmins) {
    const users = this.graph.getNodesByType(NODE_TYPES.USER);
    const serviceAccounts = users.filter(
      (u) => u.properties.isServiceAccount && !knownAdmins.has(u.id)
    );

    for (const svc of serviceAccounts) {
      const reachable = this._findReachablePrivilegedGroups(svc.id);
      const hasPrivAccess = this._hasPrivilegedAccess(svc.id);

      if (reachable.length === 0 && !hasPrivAccess) continue;

      const issues = [];
      if (svc.properties.passwordNeverExpires) issues.push('passwordNeverExpires');
      if (svc.properties.passwordLastSet) {
        const age = Math.floor(
          (Date.now() - new Date(svc.properties.passwordLastSet).getTime()) / (1000 * 60 * 60 * 24)
        );
        if (age > 180) issues.push(`password ${age} days old`);
      }

      this._addFinding({
        principal: svc,
        severity: RISK_LEVELS.HIGH,
        technique: 'ServiceAccountPrivilege',
        title: `Shadow admin service account: ${svc.displayName}`,
        description: `Service account "${svc.displayName}" has admin-equivalent access but is not flagged as an admin. ${issues.length > 0 ? `Additional concerns: ${issues.join(', ')}.` : ''} Service accounts are high-value targets because they often have weak credential hygiene.`,
        reachablePrivilegedGroups: reachable,
        effectivePermissions: this._deriveEffectivePermissions(reachable),
        credentialIssues: issues,
        recommendations: [
          'Convert to Group Managed Service Account (gMSA)',
          'Apply least-privilege principle to service account permissions',
          'Disable interactive logon for the service account',
          'Rotate credentials immediately and set up regular rotation',
          'Monitor all logon events for this account',
        ],
      });
    }
  }

  _detectDelegationShadowAdmins(knownAdmins) {
    const delegationEdgeIds = this.graph.edgesByType.get(EDGE_TYPES.DELEGATES_TO);
    if (!delegationEdgeIds) return;

    for (const eid of delegationEdgeIds) {
      const edge = this.graph.getEdge(eid);
      const source = this.graph.getNode(edge.source);
      const target = this.graph.getNode(edge.target);
      if (!source || !target) continue;

      // If the source (application/SPN) delegates to a service account that has
      // privileged access, users who can manage the application are shadow admins
      const targetHasPrivAccess = this._hasPrivilegedAccess(target.id);
      if (!targetHasPrivAccess && !knownAdmins.has(target.id)) continue;

      // Find who manages/owns the source application
      const incomingToSource = this.graph.getIncomingEdges(source.id);
      const managers = incomingToSource
        .filter((e) => [EDGE_TYPES.OWNS, EDGE_TYPES.MANAGES].includes(e.type))
        .map((e) => this.graph.getNode(e.source))
        .filter(Boolean);

      for (const manager of managers) {
        if (knownAdmins.has(manager.id)) continue;

        this._addFinding({
          principal: manager,
          severity: RISK_LEVELS.HIGH,
          technique: 'ApplicationDelegation',
          title: `Shadow admin via app delegation: ${manager.displayName || manager.name} -> ${source.name} -> ${target.name}`,
          description: `"${manager.displayName || manager.name}" manages application "${source.name}" which delegates to "${target.displayName || target.name}". Since the delegate has privileged access, anyone who can control the application effectively has admin access.`,
          reachablePrivilegedGroups: [],
          effectivePermissions: ['ApplicationManagement', 'DelegationControl'],
          recommendations: [
            'Review application delegation configuration',
            'Apply least-privilege to application permissions',
            'Restrict who can manage the application registration',
            'Monitor application credential changes',
          ],
        });
      }
    }
  }

  // -----------------------------------------------------------------------
  // Graph traversal helpers
  // -----------------------------------------------------------------------

  _findReachablePrivilegedGroups(startId) {
    const visited = new Set([startId]);
    const queue = [startId];
    const reachable = [];

    while (queue.length > 0) {
      const current = queue.shift();
      const outEdges = this.graph.getOutgoingEdges(current);

      for (const edge of outEdges) {
        if (edge.type !== EDGE_TYPES.MEMBER_OF) continue;
        if (visited.has(edge.target)) continue;
        visited.add(edge.target);

        if (PRIVILEGED_GROUP_IDS.has(edge.target)) {
          const group = this.graph.getNode(edge.target);
          if (group) reachable.push(group);
        }

        // Continue traversal through groups
        const target = this.graph.getNode(edge.target);
        if (target && target.type === NODE_TYPES.GROUP) {
          queue.push(edge.target);
        }
      }
    }

    return reachable;
  }

  _findReachablePrivilegedGroupsFromGroup(groupId) {
    return this._findReachablePrivilegedGroups(groupId);
  }

  _hasPrivilegedAccess(nodeId) {
    const outEdges = this.graph.getOutgoingEdges(nodeId);
    for (const edge of outEdges) {
      if (PRIVILEGED_GROUP_IDS.has(edge.target)) return true;
      if (ADMIN_EQUIVALENT_PERMISSIONS.has(edge.target)) return true;

      const target = this.graph.getNode(edge.target);
      if (target && target.type === NODE_TYPES.DEVICE && target.properties?.role === 'DomainController') {
        return true;
      }
    }

    // Check transitive membership
    const reachable = this._findReachablePrivilegedGroups(nodeId);
    return reachable.length > 0;
  }

  _resolveGroupMembers(node) {
    if (node.type === NODE_TYPES.USER) return [node];
    if (node.type !== NODE_TYPES.GROUP) return [node];

    // BFS to find all user members of this group (including nested)
    const users = [];
    const visited = new Set([node.id]);
    const queue = [node.id];

    while (queue.length > 0) {
      const current = queue.shift();
      const incoming = this.graph.getIncomingEdges(current);

      for (const edge of incoming) {
        if (edge.type !== EDGE_TYPES.MEMBER_OF) continue;
        if (visited.has(edge.source)) continue;
        visited.add(edge.source);

        const member = this.graph.getNode(edge.source);
        if (!member) continue;

        if (member.type === NODE_TYPES.USER) {
          users.push(member);
        } else if (member.type === NODE_TYPES.GROUP) {
          queue.push(member.id);
        }
      }
    }

    return users.length > 0 ? users : [node];
  }

  _traceMembershipChains(userId, targetGroups) {
    const chains = [];

    for (const targetGroup of targetGroups) {
      const path = this.graph.shortestPath(userId, targetGroup.id, {
        edgeTypes: [EDGE_TYPES.MEMBER_OF],
      });
      if (path) {
        chains.push({
          targetGroup: targetGroup.name,
          chain: path.nodes.map((n) => ({ id: n.id, name: n.name, type: n.type })),
          hopCount: path.length,
        });
      }
    }

    return chains;
  }

  _deriveEffectivePermissions(reachableGroups) {
    const permissions = new Set();

    for (const group of reachableGroups) {
      const groupName = group.name.toLowerCase();
      if (groupName.includes('domain admins')) {
        permissions.add('DomainAdmin');
        permissions.add('FullDomainControl');
        permissions.add('DCSync');
        permissions.add('GPOModification');
      }
      if (groupName.includes('enterprise admins')) {
        permissions.add('EnterpriseAdmin');
        permissions.add('ForestTrust');
        permissions.add('SchemaModification');
      }
      if (groupName.includes('schema admins')) {
        permissions.add('SchemaAdmin');
        permissions.add('SchemaModification');
      }
      if (groupName.includes('account operators')) {
        permissions.add('AccountManagement');
        permissions.add('PasswordReset');
      }
      if (groupName.includes('server operators')) {
        permissions.add('ServerManagement');
        permissions.add('ServiceControl');
      }
      if (groupName.includes('backup operators')) {
        permissions.add('BackupRestore');
        permissions.add('FileAccess');
        permissions.add('RegistryAccess');
      }
    }

    return [...permissions];
  }

  // -----------------------------------------------------------------------
  // Finding management
  // -----------------------------------------------------------------------

  _addFinding(finding) {
    this.shadowAdmins.push({
      id: `sa-${this.shadowAdmins.length + 1}-${Date.now()}`,
      ...finding,
      detectedAt: new Date().toISOString(),
      techniques: finding.techniques || [finding.technique],
    });
  }

  _consolidateFindings() {
    const byPrincipal = new Map();

    for (const finding of this.shadowAdmins) {
      const key = finding.principal.id;
      if (!byPrincipal.has(key)) {
        byPrincipal.set(key, { ...finding, techniques: [...finding.techniques] });
      } else {
        const existing = byPrincipal.get(key);
        // Merge techniques
        for (const t of finding.techniques) {
          if (!existing.techniques.includes(t)) existing.techniques.push(t);
        }
        // Merge reachable groups
        const existingGroupIds = new Set(existing.reachablePrivilegedGroups.map((g) => g.id));
        for (const g of finding.reachablePrivilegedGroups) {
          if (!existingGroupIds.has(g.id)) existing.reachablePrivilegedGroups.push(g);
        }
        // Merge effective permissions
        const permSet = new Set(existing.effectivePermissions);
        for (const p of finding.effectivePermissions) permSet.add(p);
        existing.effectivePermissions = [...permSet];
        // Merge recommendations
        const recSet = new Set(existing.recommendations);
        for (const r of finding.recommendations) recSet.add(r);
        existing.recommendations = [...recSet];
        // Keep the highest severity
        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        if ((order[finding.severity] || 4) < (order[existing.severity] || 4)) {
          existing.severity = finding.severity;
          existing.title = finding.title;
          existing.description = finding.description;
        }
      }
    }

    this.shadowAdmins = [...byPrincipal.values()];

    // Sort by severity
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    this.shadowAdmins.sort((a, b) => (order[a.severity] || 4) - (order[b.severity] || 4));
  }

  _countBySeverity() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const sa of this.shadowAdmins) {
      counts[sa.severity] = (counts[sa.severity] || 0) + 1;
    }
    return counts;
  }

  _countByTechnique() {
    const counts = {};
    for (const sa of this.shadowAdmins) {
      for (const t of sa.techniques) {
        counts[t] = (counts[t] || 0) + 1;
      }
    }
    return counts;
  }
}

module.exports = ShadowAdminDetector;
