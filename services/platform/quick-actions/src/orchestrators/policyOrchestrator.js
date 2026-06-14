'use strict';

const { call } = require('../utils/serviceClient');
const { publish } = require('../utils/eventPublisher');

// ─── in-memory deployment tracker ────────────────────────────────────────────
// For a production deployment this would be a persistent store (Postgres, Redis, etc.).
// Here we use a simple in-process Map so the service is self-contained and
// stateless from the caller's perspective (no DB dependency).

const deployments = new Map(); // deploymentId → deployment record

function genId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

/**
 * Execute a single orchestration step without throwing.
 */
async function step(name, fn) {
  try {
    const result = await fn();
    return { ok: true, name, result };
  } catch (err) {
    console.warn(`[policyOrchestrator] Step "${name}" failed:`, err.message);
    return { ok: false, name, error: err.message };
  }
}

// ─── public orchestrators ─────────────────────────────────────────────────────

/**
 * Deploy a policy to a target.
 *
 * @param {object} params
 * @param {string}  params.policyId   - Policy ID to deploy
 * @param {string}  params.targetType - 'user' | 'group' | 'ou' | 'device' | 'all'
 * @param {string}  [params.targetId] - ID of the specific target (not needed for 'all')
 * @param {boolean} [params.enforced=true]
 * @param {boolean} [params.dryRun=false]
 */
async function deployPolicy({ policyId, targetType, targetId, enforced = true, dryRun = false }) {
  if (!policyId)    throw new Error('policyId is required');
  if (!targetType)  throw new Error('targetType is required');

  const deploymentId   = genId();
  const completedSteps = [];
  const affectedTargets = [];
  const appliedSettings = [];
  let   dryRunReport    = null;

  // Step 1 – Fetch policy definition
  let policy = null;
  const s1 = await step('fetch-policy', async () => {
    const res = await call('policy', 'GET', `/api/policies/${encodeURIComponent(policyId)}`);
    policy = res.data || res;
    if (policy.settings) appliedSettings.push(...Object.keys(policy.settings));
    return res;
  });
  completedSteps.push(s1);

  if (!s1.ok) {
    return {
      success: false,
      deploymentId,
      policyId,
      failedAt: 'fetch-policy',
      error: s1.error,
      completedSteps: completedSteps.map(s => ({ name: s.name, ok: s.ok, error: s.error })),
    };
  }

  if (dryRun) {
    // In dry-run mode we simulate what would happen but make no mutations.
    dryRunReport = {
      policyId,
      policyName: policy?.name || policyId,
      targetType,
      targetId: targetId || 'all',
      wouldApply: appliedSettings,
      estimatedAffectedTargets: targetType === 'all' ? 'all' : 1,
      enforced,
      timestamp: new Date().toISOString(),
    };
    return {
      success: true,
      deployed: false,
      deploymentId,
      policyId,
      dryRun: true,
      dryRunReport,
      completedSteps: completedSteps.map(s => ({ name: s.name, ok: s.ok, error: s.error })),
    };
  }

  // Step 2 – Apply to the appropriate target type
  switch (targetType) {
    case 'ou': {
      const s2 = await step('apply-gpo-to-ou', async () => {
        const res = await call('directory', 'POST', `/api/gpo/${encodeURIComponent(policyId)}/apply`, {
          ouDn: targetId,
          enforced,
        });
        affectedTargets.push(targetId || 'all-ous');
        return res;
      });
      completedSteps.push(s2);
      break;
    }

    case 'device': {
      const s2 = await step('push-policy-to-device', async () => {
        const res = await call('mdm', 'POST', '/api/policies/push', {
          policyId,
          deviceId: targetId,
          enforced,
        });
        affectedTargets.push(targetId);
        return res;
      });
      completedSteps.push(s2);
      break;
    }

    case 'user': {
      const s2 = await step('assign-policy-to-user', async () => {
        const res = await call('pim', 'POST', '/api/policies/assign', {
          policyId,
          userId: targetId,
          enforced,
        });
        affectedTargets.push(targetId);
        return res;
      });
      completedSteps.push(s2);
      break;
    }

    case 'group': {
      const s2 = await step('assign-policy-to-group', async () => {
        const res = await call('directory', 'POST', '/api/policies/group/assign', {
          policyId,
          groupId: targetId,
          enforced,
        });
        affectedTargets.push(targetId);
        return res;
      });
      completedSteps.push(s2);
      break;
    }

    case 'all': {
      // Broadcast to all target types concurrently
      const [devRes, ouRes, userRes] = await Promise.allSettled([
        call('mdm', 'POST', '/api/policies/push', { policyId, scope: 'all', enforced }),
        call('directory', 'POST', `/api/gpo/${encodeURIComponent(policyId)}/apply`, { scope: 'all', enforced }),
        call('policy', 'POST', '/api/policies/broadcast', { policyId, enforced }),
      ]);
      const broadcastStep = {
        name: 'broadcast-to-all',
        ok: [devRes, ouRes, userRes].some(r => r.status === 'fulfilled'),
        results: { mdm: devRes.status, directory: ouRes.status, policy: userRes.status },
      };
      if (!broadcastStep.ok) {
        broadcastStep.error = 'All broadcast targets failed';
      }
      completedSteps.push(broadcastStep);
      affectedTargets.push('all-devices', 'all-ous', 'all-users');
      break;
    }

    default:
      console.warn(`[policyOrchestrator] Unknown targetType "${targetType}"`);
  }

  // Step 3 – Notify policy-service of the deployment
  const s3 = await step('record-deployment', () =>
    call('policy', 'POST', '/api/policies/deployments', {
      deploymentId,
      policyId,
      targetType,
      targetId,
      enforced,
      deployedAt: new Date().toISOString(),
      status: 'deployed',
    })
  );
  completedSteps.push(s3);

  // Record locally for status lookups
  const record = {
    deploymentId,
    policyId,
    targetType,
    targetId,
    enforced,
    dryRun,
    affectedTargets,
    appliedSettings,
    deployedAt: new Date().toISOString(),
    status: 'deployed',
    completedSteps: completedSteps.map(s => ({ name: s.name, ok: s.ok, error: s.error })),
    policySnapshot: policy,
  };
  deployments.set(deploymentId, record);

  const failed = completedSteps.filter(s => !s.ok);

  await publish('policy.deployed', { policyId, deploymentId: record.deploymentId, _source: 'quick-actions' });

  return {
    success: failed.length === 0,
    deployed: true,
    deploymentId,
    policyId,
    affectedTargets: affectedTargets.length,
    appliedSettings,
    dryRunReport: null,
    completedSteps: record.completedSteps,
    ...(failed.length > 0 ? {
      failedAt: failed[0].name,
      error: failed[0].error,
      warnings: failed.map(s => `${s.name}: ${s.error}`),
    } : {}),
  };
}

/**
 * Get the status of a policy deployment.
 */
async function getPolicyDeploymentStatus(deploymentId) {
  if (!deploymentId) throw new Error('deploymentId is required');

  // Try local store first (fast path)
  if (deployments.has(deploymentId)) {
    const record = deployments.get(deploymentId);
    return { success: true, ...record };
  }

  // Fall back to policy-service
  try {
    const res = await call('policy', 'GET', `/api/policies/deployments/${encodeURIComponent(deploymentId)}`);
    return { success: true, ...res };
  } catch (err) {
    return { success: false, deploymentId, error: err.message };
  }
}

/**
 * Roll back a policy deployment — revoke the policy from the target(s).
 */
async function rollbackPolicy(deploymentId) {
  if (!deploymentId) throw new Error('deploymentId is required');

  const record = deployments.get(deploymentId);
  if (!record) {
    return { success: false, deploymentId, error: 'Deployment not found in local store; manual rollback may be needed.' };
  }

  const completedSteps = [];

  // Reverse the original deployment based on targetType
  switch (record.targetType) {
    case 'ou': {
      const s = await step('rollback-gpo-from-ou', () =>
        call('directory', 'POST', `/api/gpo/${encodeURIComponent(record.policyId)}/remove`, {
          ouDn: record.targetId,
        })
      );
      completedSteps.push(s);
      break;
    }
    case 'device': {
      const s = await step('rollback-policy-from-device', () =>
        call('mdm', 'DELETE', `/api/policies/${encodeURIComponent(record.policyId)}/devices/${encodeURIComponent(record.targetId)}`)
      );
      completedSteps.push(s);
      break;
    }
    case 'user': {
      const s = await step('rollback-policy-from-user', () =>
        call('pim', 'DELETE', `/api/policies/${encodeURIComponent(record.policyId)}/users/${encodeURIComponent(record.targetId)}`)
      );
      completedSteps.push(s);
      break;
    }
    case 'group': {
      const s = await step('rollback-policy-from-group', () =>
        call('directory', 'DELETE', `/api/policies/${encodeURIComponent(record.policyId)}/groups/${encodeURIComponent(record.targetId)}`)
      );
      completedSteps.push(s);
      break;
    }
    default: {
      const s = await step('rollback-broadcast', () =>
        call('policy', 'POST', `/api/policies/${encodeURIComponent(record.policyId)}/revoke`, {
          targetType: record.targetType,
          targetId: record.targetId,
        })
      );
      completedSteps.push(s);
    }
  }

  // Update local record
  record.status     = 'rolled-back';
  record.rolledBackAt = new Date().toISOString();
  deployments.set(deploymentId, record);

  // Notify policy-service
  await step('record-rollback', () =>
    call('policy', 'PATCH', `/api/policies/deployments/${encodeURIComponent(deploymentId)}`, {
      status: 'rolled-back',
      rolledBackAt: record.rolledBackAt,
    })
  ).catch(() => {});

  const failed = completedSteps.filter(s => !s.ok);

  await publish('policy.rolledback', { deploymentId, _source: 'quick-actions' });

  return {
    success: failed.length === 0,
    deploymentId,
    policyId: record.policyId,
    rolledBack: true,
    rolledBackAt: record.rolledBackAt,
    completedSteps: completedSteps.map(s => ({ name: s.name, ok: s.ok, error: s.error })),
    ...(failed.length > 0 ? { warnings: failed.map(s => `${s.name}: ${s.error}`) } : {}),
  };
}

/**
 * Get a quick compliance snapshot across all devices and policies.
 */
async function getComplianceSnapshot() {
  const [policyRes, complianceRes] = await Promise.allSettled([
    call('policy', 'GET', '/api/compliance/summary'),
    call('device', 'GET', '/api/compliance/devices'),
  ]);

  let total        = 0;
  let compliant    = 0;
  let nonCompliant = 0;
  let topViolations = [];

  if (policyRes.status === 'fulfilled') {
    const d = policyRes.value.data || policyRes.value;
    total        = d.total        ?? total;
    compliant    = d.compliant    ?? compliant;
    nonCompliant = d.nonCompliant ?? (total - compliant);
    topViolations = d.topViolations || [];
  }

  if (complianceRes.status === 'fulfilled') {
    const d = complianceRes.value.data || complianceRes.value;
    if (!total && d.total) total = d.total;
    if (!compliant && d.compliant) compliant = d.compliant;
    if (!nonCompliant && d.nonCompliant) nonCompliant = d.nonCompliant;
  }

  return {
    success: true,
    snapshot: {
      total,
      compliant,
      nonCompliant: nonCompliant || (total - compliant),
      complianceRate: total > 0 ? Math.round((compliant / total) * 100) : null,
      topViolations,
      generatedAt: new Date().toISOString(),
    },
    warnings: [
      policyRes.status    === 'rejected' ? `policy-service: ${policyRes.reason.message}`    : null,
      complianceRes.status === 'rejected' ? `device-service: ${complianceRes.reason.message}` : null,
    ].filter(Boolean),
  };
}

module.exports = {
  deployPolicy,
  getPolicyDeploymentStatus,
  rollbackPolicy,
  getComplianceSnapshot,
};
