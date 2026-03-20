const { EventEmitter } = require('events');
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

/**
 * PolicyAgentService — Generic server-side policy management via WebSocket push
 *
 * Architecture:
 *   Server (this) → device-service.sendToDevice() → WebSocket → Agent (platform-specific)
 *
 * The server compiles policies into platform-agnostic intent objects.
 * Agents receive these intents and translate them into platform-specific enforcement:
 *   Windows → Registry/GPO/PowerShell
 *   macOS   → .mobileconfig/profiles/launchctl
 *   Linux   → sysctl/PAM/auditd/systemd
 *
 * This service NEVER generates platform-specific code — that's the agent's job.
 */
class PolicyAgentService extends EventEmitter {
  constructor(deviceService) {
    super();
    this.deviceService = deviceService;
    this.devicePolicies = new Map();   // deviceId → [{ policyId, version, appliedAt }]
    this.policyVersions = new Map();   // policyId → { version, settings, ... }
    this.complianceState = new Map();  // deviceId → { compliant, violations[], lastCheck }
  }

  // ─── Generic command dispatch ──────────────────────────────────────────

  sendPolicyCommand(deviceId, commandType, data) {
    const commandId = `pol-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const message = {
      type: 'command',
      id: commandId,
      command_type: commandType,
      data,
      category: 'policy'
    };

    const sent = this.deviceService.sendToDevice(deviceId, message);
    if (!sent) {
      this.deviceService.cacheForOfflineDevice?.(deviceId, message);
    }

    logger.info(`Policy command ${commandType} → device ${deviceId} (sent=${sent})`);
    this.emit('commandSent', { deviceId, commandType, commandId, sent });
    return { commandId, sent };
  }

  // ─── Policy Deployment (platform-agnostic intent) ──────────────────────

  /**
   * Apply a policy to a device. The policy uses a platform-agnostic schema:
   *
   * {
   *   id, name, version,
   *   security: {
   *     password:   { minLength, maxAgeDays, complexity, lockoutThreshold, lockoutDuration, historyLength },
   *     screenLock: { enabled, timeoutMinutes, requirePassword },
   *     firewall:   { enabled, defaultDeny, stealth, allowedPorts[] },
   *     encryption: { required, showRecoveryKey },
   *     audit:      { enabled, logLogin, logFileAccess, logPrivilegeUse }
   *   },
   *   network: {
   *     ssh:    { enabled, permitRootLogin, passwordAuth, port, allowGroups[] },
   *     drives: [{ letter, server, share, type, label, mountPoint }],
   *     printers: [{ name, address, protocol, driver, location, isDefault }]
   *   },
   *   software: {
   *     updates:      { automatic, schedule, rebootAllowed, maintenanceWindow },
   *     restrictions: { blacklist[], whitelist[] },
   *     wingetAutoUpdate: { ... }  // Windows-specific, ignored by other agents
   *   },
   *   browser: {
   *     homepage, defaultSearchEngine, blockedExtensions[]
   *   },
   *   sudo: {
   *     adminGroups[]  // Linux-specific, ignored by other agents
   *   }
   * }
   */
  applyPolicy(deviceId, policy) {
    const data = {
      policyId: policy.id,
      policyName: policy.name,
      version: policy.version || '1.0',
      settings: this.normalizePolicy(policy),
      enforceMode: policy.enforceMode || 'enforce',  // 'enforce' | 'audit'
      notifyUser: policy.notifyUser !== false
    };

    const result = this.sendPolicyCommand(deviceId, 'apply_policy', data);

    // Track policy assignment
    const existing = this.devicePolicies.get(deviceId) || [];
    const idx = existing.findIndex(p => p.policyId === policy.id);
    const entry = { policyId: policy.id, version: data.version, sentAt: new Date().toISOString() };
    if (idx >= 0) existing[idx] = entry; else existing.push(entry);
    this.devicePolicies.set(deviceId, existing);

    this.policyVersions.set(policy.id, { ...data.settings, version: data.version });

    this.emit('policyApplied', { deviceId, policyId: policy.id, version: data.version, commandId: result.commandId });
    return result;
  }

  /**
   * Apply a policy to multiple devices.
   */
  applyPolicyToDevices(deviceIds, policy) {
    const results = [];
    for (const deviceId of deviceIds) {
      results.push({ deviceId, ...this.applyPolicy(deviceId, policy) });
    }
    this.emit('bulkPolicyApplied', { deviceIds, policyId: policy.id, results });
    return results;
  }

  /**
   * Remove a policy from a device (undo enforcement).
   */
  removePolicy(deviceId, policyId) {
    const policyData = this.policyVersions.get(policyId);
    const result = this.sendPolicyCommand(deviceId, 'remove_policy', {
      policyId,
      settings: policyData || {}
    });

    // Update tracking
    const existing = this.devicePolicies.get(deviceId) || [];
    this.devicePolicies.set(deviceId, existing.filter(p => p.policyId !== policyId));

    this.emit('policyRemoved', { deviceId, policyId, commandId: result.commandId });
    return result;
  }

  /**
   * Request compliance check from agent (local Soll/Ist comparison).
   */
  checkCompliance(deviceId, policyId) {
    const policyData = this.policyVersions.get(policyId);
    return this.sendPolicyCommand(deviceId, 'check_compliance', {
      policyId,
      expectedSettings: policyData || {}
    });
  }

  /**
   * Request compliance check for all policies assigned to a device.
   */
  checkDeviceCompliance(deviceId) {
    const policies = this.devicePolicies.get(deviceId) || [];
    const expectedPolicies = policies.map(p => ({
      policyId: p.policyId,
      version: p.version,
      settings: this.policyVersions.get(p.policyId) || {}
    }));
    return this.sendPolicyCommand(deviceId, 'check_all_compliance', {
      policies: expectedPolicies
    });
  }

  /**
   * Request drift detection from agent (hash-based comparison).
   */
  detectDrift(deviceId) {
    const policies = this.devicePolicies.get(deviceId) || [];
    return this.sendPolicyCommand(deviceId, 'detect_drift', {
      expectedPolicies: policies
    });
  }

  /**
   * Rollback a policy on a device to previous state.
   */
  rollbackPolicy(deviceId, policyId) {
    return this.sendPolicyCommand(deviceId, 'rollback_policy', { policyId });
  }

  /**
   * Force re-apply all policies on a device.
   */
  resyncPolicies(deviceId) {
    const policies = this.devicePolicies.get(deviceId) || [];
    const fullPolicies = policies.map(p => ({
      policyId: p.policyId,
      version: p.version,
      settings: this.policyVersions.get(p.policyId) || {}
    }));
    return this.sendPolicyCommand(deviceId, 'resync_policies', {
      policies: fullPolicies
    });
  }

  /**
   * Apply a single policy module to a device (e.g. only password, only firewall).
   */
  applyPolicyModule(deviceId, module, settings) {
    return this.sendPolicyCommand(deviceId, 'apply_policy_module', {
      module,  // 'password', 'firewall', 'screenLock', 'audit', 'browser', 'ssh', 'encryption'
      settings
    });
  }

  /**
   * Get policy status for a device (what's applied, compliance state).
   */
  getDevicePolicyStatus(deviceId) {
    return {
      deviceId,
      assignedPolicies: this.devicePolicies.get(deviceId) || [],
      compliance: this.complianceState.get(deviceId) || null
    };
  }

  // ─── Handle results from agents ───────────────────────────────────────

  handleCommandResult(deviceId, result) {
    logger.info(`Policy result from ${deviceId}: ${result.commandId} → ${result.status}`);

    if (result.complianceReport) {
      this.complianceState.set(deviceId, {
        compliant: result.complianceReport.compliant,
        violations: result.complianceReport.violations || [],
        lastCheck: new Date().toISOString()
      });

      if (!result.complianceReport.compliant) {
        this.emit('complianceViolation', {
          deviceId,
          violations: result.complianceReport.violations
        });
      }
    }

    if (result.driftReport) {
      this.emit('driftDetected', {
        deviceId,
        drifted: result.driftReport.drifted || [],
        missing: result.driftReport.missing || []
      });
    }

    this.emit('commandResult', {
      deviceId,
      commandId: result.commandId,
      status: result.status,
      output: result.output
    });
  }

  // ─── Normalize policy to platform-agnostic schema ─────────────────────

  normalizePolicy(policy) {
    const s = policy.settings || policy;
    return {
      security: {
        password: s.password || s.security?.password || null,
        screenLock: s.screenLock || s.security?.screenLock || null,
        firewall: s.firewall || s.security?.firewall || null,
        encryption: s.encryption || s.security?.encryption || null,
        audit: s.audit || s.security?.audit || null
      },
      network: {
        ssh: s.ssh || s.network?.ssh || null,
        drives: s.networkDrives || s.network?.drives || null,
        printers: s.printers || s.network?.printers || null
      },
      software: {
        updates: s.updates || s.software?.updates || null,
        restrictions: s.software?.restrictions || null,
        wingetAutoUpdate: s.wingetAutoUpdate || s.software?.wingetAutoUpdate || null
      },
      browser: s.browser || null,
      sudo: s.sudo || null
    };
  }
}

module.exports = PolicyAgentService;
