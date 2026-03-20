/**
 * AttackPathAnalyzer - Detects privilege escalation chains in the AD graph
 *
 * Inspired by BloodHound: walks the graph looking for sequences of
 * relationships that allow a lower-privileged principal to reach a
 * high-value target (Domain Admins, Domain Controllers, etc.).
 *
 * Techniques detected:
 *   - Direct admin membership
 *   - Nested group escalation
 *   - ACL-based attacks (WriteDACL, WriteOwner, GenericAll, GenericWrite)
 *   - Password reset chains
 *   - Session stealing (HasSession on high-value targets)
 *   - Kerberoasting vectors (SPNs on privileged accounts)
 *   - Service account abuse
 *   - GPO abuse paths
 */

'use strict';

const { NODE_TYPES, EDGE_TYPES, RISK_LEVELS } = require('./graphBuilder');

// Edge types that represent an abusable privilege escalation step
const ESCALATION_EDGE_TYPES = new Set([
  EDGE_TYPES.MEMBER_OF,
  EDGE_TYPES.HAS_PERMISSION,
  EDGE_TYPES.ADMIN_OF,
  EDGE_TYPES.CAN_RESET_PASSWORD,
  EDGE_TYPES.CAN_ADD_MEMBER,
  EDGE_TYPES.WRITE_DACL,
  EDGE_TYPES.WRITE_OWNER,
  EDGE_TYPES.GENERIC_ALL,
  EDGE_TYPES.GENERIC_WRITE,
  EDGE_TYPES.FORCE_CHANGE_PASSWORD,
  EDGE_TYPES.ADD_SELF,
  EDGE_TYPES.DELEGATES_TO,
  EDGE_TYPES.HAS_SESSION,
  EDGE_TYPES.CAN_RDP,
  EDGE_TYPES.CAN_PSREMOTE,
]);

// Node IDs / names that are considered high-value targets
const HIGH_VALUE_TARGET_NAMES = new Set([
  'domain admins',
  'enterprise admins',
  'schema admins',
  'global administrator',
  'dc01',
  'dc02',
]);

const HIGH_VALUE_GROUP_IDS = new Set([
  'grp-domain-admins',
  'grp-enterprise-admins',
  'grp-schema-admins',
]);

class AttackPathAnalyzer {
  constructor(graphBuilder, logger) {
    this.graph = graphBuilder;
    this.logger = logger;
    this.attackPaths = [];
    this.lastAnalysis = null;
  }

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------

  /**
   * Run full attack-path analysis.
   * Returns an array of attack path objects.
   */
  analyze() {
    const t0 = Date.now();
    this.logger.info('Starting attack path analysis...');
    this.attackPaths = [];

    this._detectDirectAdminPaths();
    this._detectNestedGroupEscalation();
    this._detectACLAbusePaths();
    this._detectPasswordResetChains();
    this._detectSessionStealing();
    this._detectServiceAccountAbuse();
    this._detectGPOAbuse();
    this._detectKerberoastableAccounts();

    // De-duplicate paths that share the same start/end/technique
    this._deduplicatePaths();

    // Sort by severity (critical first)
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    this.attackPaths.sort((a, b) => (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4));

    this.lastAnalysis = {
      timestamp: new Date().toISOString(),
      durationMs: Date.now() - t0,
      totalPaths: this.attackPaths.length,
      bySeverity: this._countBySeverity(),
    };

    this.logger.info('Attack path analysis complete', this.lastAnalysis);
    return this.attackPaths;
  }

  getAttackPaths(filters = {}) {
    let paths = [...this.attackPaths];
    if (filters.severity) {
      paths = paths.filter((p) => p.severity === filters.severity);
    }
    if (filters.technique) {
      paths = paths.filter((p) => p.technique === filters.technique);
    }
    if (filters.sourceType) {
      paths = paths.filter((p) => p.source?.type === filters.sourceType);
    }
    if (filters.limit) {
      paths = paths.slice(0, filters.limit);
    }
    return paths;
  }

  getSummary() {
    return {
      ...this.lastAnalysis,
      paths: this.attackPaths.map((p) => ({
        id: p.id,
        title: p.title,
        severity: p.severity,
        technique: p.technique,
        sourceNode: p.source ? { id: p.source.id, name: p.source.name, type: p.source.type } : null,
        targetNode: p.target ? { id: p.target.id, name: p.target.name, type: p.target.type } : null,
        hopCount: p.path ? p.path.length : 0,
      })),
    };
  }

  // -----------------------------------------------------------------------
  // Detection methods
  // -----------------------------------------------------------------------

  _detectDirectAdminPaths() {
    const users = this.graph.getNodesByType(NODE_TYPES.USER);
    for (const user of users) {
      if (user.properties.adminCount === 1) continue; // already a known admin

      const outEdges = this.graph.getOutgoingEdges(user.id);
      for (const edge of outEdges) {
        if (edge.type !== EDGE_TYPES.MEMBER_OF) continue;
        const target = this.graph.getNode(edge.target);
        if (target && this._isHighValueTarget(target)) {
          this._addPath({
            title: `Direct admin membership: ${user.displayName} -> ${target.name}`,
            description: `User "${user.displayName}" (${user.name}) is a direct member of the high-privilege group "${target.name}". If this account is compromised, the attacker gains immediate administrative access.`,
            severity: RISK_LEVELS.CRITICAL,
            technique: 'DirectAdminMembership',
            source: user,
            target,
            path: [
              { node: user, edge: null },
              { node: target, edge },
            ],
            mitigations: [
              'Verify this membership is intentional and documented',
              'Enable MFA and Conditional Access for this account',
              'Implement Privileged Access Workstations (PAW)',
              'Use just-in-time (JIT) access via PIM instead of standing membership',
            ],
          });
        }
      }
    }
  }

  _detectNestedGroupEscalation() {
    const users = this.graph.getNodesByType(NODE_TYPES.USER);

    for (const user of users) {
      if (user.properties.adminCount === 1) continue;

      // BFS through MemberOf edges to find paths to high-value groups
      const visited = new Set([user.id]);
      const queue = [{ nodeId: user.id, path: [{ node: user, edge: null }] }];

      while (queue.length > 0) {
        const { nodeId, path } = queue.shift();
        if (path.length > 6) continue; // limit depth

        const outEdges = this.graph.getOutgoingEdges(nodeId);
        for (const edge of outEdges) {
          if (edge.type !== EDGE_TYPES.MEMBER_OF) continue;
          if (visited.has(edge.target)) continue;
          visited.add(edge.target);

          const target = this.graph.getNode(edge.target);
          if (!target) continue;

          const newPath = [...path, { node: target, edge }];

          if (this._isHighValueTarget(target) && path.length > 1) {
            // Only record if there is at least one intermediate group (nested)
            this._addPath({
              title: `Nested group escalation: ${user.displayName} -> ${target.name} (${path.length} hops)`,
              description: `User "${user.displayName}" can reach the privileged group "${target.name}" through ${path.length - 1} levels of nested group membership. An attacker compromising this account could follow the chain: ${newPath.map((s) => s.node.name).join(' -> ')}.`,
              severity: RISK_LEVELS.HIGH,
              technique: 'NestedGroupEscalation',
              source: user,
              target,
              path: newPath,
              mitigations: [
                'Flatten unnecessary group nesting',
                'Review and reduce transitive group memberships',
                'Monitor changes to these groups with alerts',
                'Implement tiered administration model',
              ],
            });
          }

          if (target.type === NODE_TYPES.GROUP) {
            queue.push({ nodeId: target.id, path: newPath });
          }
        }
      }
    }
  }

  _detectACLAbusePaths() {
    const aclEdgeTypes = [
      EDGE_TYPES.WRITE_DACL,
      EDGE_TYPES.WRITE_OWNER,
      EDGE_TYPES.GENERIC_ALL,
      EDGE_TYPES.GENERIC_WRITE,
      EDGE_TYPES.FORCE_CHANGE_PASSWORD,
      EDGE_TYPES.ADD_SELF,
    ];

    for (const edgeType of aclEdgeTypes) {
      const edgeIds = this.graph.edgesByType.get(edgeType);
      if (!edgeIds) continue;

      for (const eid of edgeIds) {
        const edge = this.graph.getEdge(eid);
        const source = this.graph.getNode(edge.source);
        const target = this.graph.getNode(edge.target);
        if (!source || !target) continue;

        const isTargetHigh =
          this._isHighValueTarget(target) ||
          target.riskLevel === RISK_LEVELS.CRITICAL ||
          target.riskLevel === RISK_LEVELS.HIGH;

        if (!isTargetHigh) continue;

        const techniqueDescriptions = {
          [EDGE_TYPES.WRITE_DACL]: {
            technique: 'WriteDACLAbuse',
            desc: `can modify the DACL on "${target.name}", allowing them to grant themselves any permission`,
          },
          [EDGE_TYPES.WRITE_OWNER]: {
            technique: 'WriteOwnerAbuse',
            desc: `can change the owner of "${target.name}", which grants implicit WriteDACL`,
          },
          [EDGE_TYPES.GENERIC_ALL]: {
            technique: 'GenericAllAbuse',
            desc: `has GenericAll rights on "${target.name}", providing full control`,
          },
          [EDGE_TYPES.GENERIC_WRITE]: {
            technique: 'GenericWriteAbuse',
            desc: `has GenericWrite on "${target.name}", allowing modification of security-sensitive attributes`,
          },
          [EDGE_TYPES.FORCE_CHANGE_PASSWORD]: {
            technique: 'ForceChangePassword',
            desc: `can force-reset the password of "${target.name}" without knowing the current password`,
          },
          [EDGE_TYPES.ADD_SELF]: {
            technique: 'AddSelfAbuse',
            desc: `can add themselves to "${target.name}"`,
          },
        };

        const info = techniqueDescriptions[edgeType];

        this._addPath({
          title: `ACL abuse: ${source.name} ${info.technique} on ${target.name}`,
          description: `"${source.displayName || source.name}" ${info.desc}. This is a direct privilege escalation vector.`,
          severity: RISK_LEVELS.CRITICAL,
          technique: info.technique,
          source,
          target,
          path: [
            { node: source, edge: null },
            { node: target, edge },
          ],
          mitigations: [
            'Remove or restrict this ACL entry',
            'Audit all non-default ACLs on privileged objects',
            'Use AdminSDHolder to protect sensitive accounts',
            'Implement monitoring for ACL changes on Tier 0 assets',
          ],
        });
      }
    }
  }

  _detectPasswordResetChains() {
    const resetEdgeIds = this.graph.edgesByType.get(EDGE_TYPES.CAN_RESET_PASSWORD);
    if (!resetEdgeIds) return;

    for (const eid of resetEdgeIds) {
      const edge = this.graph.getEdge(eid);
      const source = this.graph.getNode(edge.source);
      const target = this.graph.getNode(edge.target);
      if (!source || !target) continue;

      // Check if the target has any interesting access
      const targetOutEdges = this.graph.getOutgoingEdges(target.id);
      const interestingAccess = targetOutEdges.filter((e) =>
        [EDGE_TYPES.MEMBER_OF, EDGE_TYPES.HAS_PERMISSION, EDGE_TYPES.ADMIN_OF].includes(e.type)
      );

      if (interestingAccess.length > 0) {
        for (const accessEdge of interestingAccess) {
          const accessTarget = this.graph.getNode(accessEdge.target);
          if (!accessTarget) continue;

          this._addPath({
            title: `Password reset chain: ${source.name} -> reset ${target.name} -> ${accessTarget.name}`,
            description: `"${source.displayName || source.name}" can reset the password of "${target.displayName || target.name}", who has ${accessEdge.type} on "${accessTarget.name}". An attacker can chain these operations: reset password, log in as the target, then access "${accessTarget.name}".`,
            severity: this._isHighValueTarget(accessTarget) ? RISK_LEVELS.HIGH : RISK_LEVELS.MEDIUM,
            technique: 'PasswordResetChain',
            source,
            target: accessTarget,
            path: [
              { node: source, edge: null },
              { node: target, edge },
              { node: accessTarget, edge: accessEdge },
            ],
            mitigations: [
              'Restrict password reset delegation to minimum necessary scope',
              'Ensure MFA is required for password-resettable accounts',
              'Monitor password reset events for privileged accounts',
              'Implement tiered delegation model',
            ],
          });
        }
      }
    }
  }

  _detectSessionStealing() {
    const sessionEdgeIds = this.graph.edgesByType.get(EDGE_TYPES.HAS_SESSION);
    if (!sessionEdgeIds) return;

    for (const eid of sessionEdgeIds) {
      const edge = this.graph.getEdge(eid);
      const user = this.graph.getNode(edge.source);
      const device = this.graph.getNode(edge.target);
      if (!user || !device) continue;

      // Check if any lower-privilege user is admin of that device
      const deviceIncoming = this.graph.getIncomingEdges(device.id);
      const deviceAdmins = deviceIncoming.filter(
        (e) => e.type === EDGE_TYPES.ADMIN_OF && e.source !== user.id
      );

      for (const adminEdge of deviceAdmins) {
        const localAdmin = this.graph.getNode(adminEdge.source);
        if (!localAdmin) continue;

        // Can the local admin steal the session of the higher-privilege user?
        const userIsPrivileged =
          user.riskLevel === RISK_LEVELS.CRITICAL || user.riskLevel === RISK_LEVELS.HIGH;

        if (userIsPrivileged) {
          this._addPath({
            title: `Session theft: ${localAdmin.name} -> ${device.name} -> steal ${user.name}'s credentials`,
            description: `"${localAdmin.displayName || localAdmin.name}" has local admin on "${device.name}" where "${user.displayName}" has an active session. The attacker could extract credentials from memory (e.g., Mimikatz) and impersonate the privileged user.`,
            severity: RISK_LEVELS.CRITICAL,
            technique: 'SessionStealing',
            source: localAdmin,
            target: user,
            path: [
              { node: localAdmin, edge: null },
              { node: device, edge: adminEdge },
              { node: user, edge },
            ],
            mitigations: [
              'Do not allow privileged users to log into non-Tier 0 systems',
              'Enable Credential Guard on all workstations',
              'Implement LAPS for local admin passwords',
              'Use Protected Users security group for privileged accounts',
              'Deploy session isolation via PAW architecture',
            ],
          });
        }
      }
    }
  }

  _detectServiceAccountAbuse() {
    const users = this.graph.getNodesByType(NODE_TYPES.USER);
    const serviceAccounts = users.filter((u) => u.properties.isServiceAccount);

    for (const svc of serviceAccounts) {
      const issues = [];

      // Check for password never expires
      if (svc.properties.passwordNeverExpires) {
        issues.push('Password is set to never expire');
      }

      // Check for old password
      if (svc.properties.passwordLastSet) {
        const passwordAge = Date.now() - new Date(svc.properties.passwordLastSet).getTime();
        const daysOld = Math.floor(passwordAge / (1000 * 60 * 60 * 24));
        if (daysOld > 180) {
          issues.push(`Password is ${daysOld} days old`);
        }
      }

      // Check for direct high-value access
      const outEdges = this.graph.getOutgoingEdges(svc.id);
      const highValueEdges = outEdges.filter((e) => {
        const target = this.graph.getNode(e.target);
        return target && (this._isHighValueTarget(target) || target.riskLevel === RISK_LEVELS.CRITICAL);
      });

      if (issues.length > 0 && highValueEdges.length > 0) {
        for (const edge of highValueEdges) {
          const target = this.graph.getNode(edge.target);
          this._addPath({
            title: `Vulnerable service account: ${svc.name} -> ${target.name}`,
            description: `Service account "${svc.displayName}" has access to high-value target "${target.name}" via ${edge.type}. Security issues: ${issues.join('; ')}. Service accounts with stale credentials and high privileges are prime targets for attackers.`,
            severity: RISK_LEVELS.HIGH,
            technique: 'ServiceAccountAbuse',
            source: svc,
            target,
            path: [
              { node: svc, edge: null },
              { node: target, edge },
            ],
            mitigations: [
              'Rotate the service account password immediately',
              'Implement Group Managed Service Accounts (gMSA)',
              'Apply the principle of least privilege',
              'Monitor logon events for this service account',
              'Disable interactive logon for service accounts',
            ],
          });
        }
      }
    }
  }

  _detectGPOAbuse() {
    const gpoAdminEdges = this.graph.edgesByType.get(EDGE_TYPES.WRITE_DACL);
    if (!gpoAdminEdges) return;

    for (const eid of gpoAdminEdges) {
      const edge = this.graph.getEdge(eid);
      const source = this.graph.getNode(edge.source);
      const target = this.graph.getNode(edge.target);
      if (!source || !target) continue;

      if (target.type === NODE_TYPES.OU || target.type === NODE_TYPES.GPO) {
        // Find what is under this OU
        const ouChildren = this.graph.getOutgoingEdges(target.id)
          .filter((e) => e.type === EDGE_TYPES.CONTAINS)
          .map((e) => this.graph.getNode(e.target))
          .filter(Boolean);

        this._addPath({
          title: `GPO/OU abuse: ${source.name} can modify "${target.name}"`,
          description: `"${source.displayName || source.name}" has WriteDACL on ${target.type} "${target.name}". This allows creating or modifying GPOs that apply to all objects within, potentially deploying malicious scripts or configurations. Affected child objects: ${ouChildren.length > 0 ? ouChildren.map((c) => c.name).join(', ') : 'root domain scope'}.`,
          severity: RISK_LEVELS.CRITICAL,
          technique: 'GPOAbuse',
          source,
          target,
          path: [
            { node: source, edge: null },
            { node: target, edge },
          ],
          mitigations: [
            'Restrict GPO edit permissions to dedicated admin accounts',
            'Monitor GPO changes with advanced audit logging',
            'Implement GPO change approval workflows',
            'Use AGPM (Advanced Group Policy Management) for change control',
          ],
        });
      }
    }
  }

  _detectKerberoastableAccounts() {
    const users = this.graph.getNodesByType(NODE_TYPES.USER);

    for (const user of users) {
      const spns = user.properties.servicePrincipalNames;
      if (!spns || spns.length === 0) continue;

      // Check if this user has any privileged access
      const outEdges = this.graph.getOutgoingEdges(user.id);
      const privilegedEdges = outEdges.filter((e) => {
        const target = this.graph.getNode(e.target);
        return target && (this._isHighValueTarget(target) || target.properties?.isPrivileged);
      });

      if (privilegedEdges.length > 0) {
        this._addPath({
          title: `Kerberoastable privileged account: ${user.name}`,
          description: `User "${user.displayName}" has SPNs set (${spns.join(', ')}) making the account Kerberoastable. This account also has privileged access. An attacker can request a service ticket and crack the password offline.`,
          severity: RISK_LEVELS.CRITICAL,
          technique: 'Kerberoasting',
          source: user,
          target: user,
          path: [{ node: user, edge: null }],
          mitigations: [
            'Use a long (25+ character) randomly generated password',
            'Move SPNs to a dedicated service account with minimal privileges',
            'Use Group Managed Service Accounts (gMSA)',
            'Monitor Kerberos TGS requests (Event ID 4769) for anomalies',
          ],
        });
      }
    }
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  _isHighValueTarget(node) {
    if (HIGH_VALUE_GROUP_IDS.has(node.id)) return true;
    if (node.name && HIGH_VALUE_TARGET_NAMES.has(node.name.toLowerCase())) return true;
    if (node.properties?.isPrivileged) return true;
    if (node.type === NODE_TYPES.DEVICE && node.properties?.role === 'DomainController') return true;
    return false;
  }

  _addPath(pathData) {
    this.attackPaths.push({
      id: `ap-${this.attackPaths.length + 1}-${Date.now()}`,
      ...pathData,
      detectedAt: new Date().toISOString(),
    });
  }

  _deduplicatePaths() {
    const seen = new Set();
    this.attackPaths = this.attackPaths.filter((p) => {
      const key = `${p.technique}:${p.source?.id}:${p.target?.id}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  _countBySeverity() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const p of this.attackPaths) {
      counts[p.severity] = (counts[p.severity] || 0) + 1;
    }
    return counts;
  }
}

module.exports = AttackPathAnalyzer;
