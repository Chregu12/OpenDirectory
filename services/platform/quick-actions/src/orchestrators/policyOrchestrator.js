'use strict';

const { call } = require('../utils/serviceClient');
const { publish } = require('../utils/eventPublisher');

// ─── persistent deployment store (Redis + in-memory fallback) ─────────────────
// Redis is the primary store so deployment state survives process restarts.
// If Redis is unavailable at startup or drops mid-run, all operations fall back
// to the in-process Map without throwing so the service stays operational.

let deploymentsCache = new Map(); // in-process fallback
let redis = null;
try {
  const Redis = require('ioredis');
  redis = new Redis(process.env.REDIS_URL || 'redis://redis:6379', {
    lazyConnect: false,
    enableReadyCheck: true,
    maxRetriesPerRequest: 1,
  });
  redis.on('error', (err) => {
    console.warn('[policyOrchestrator] Redis error, falling back to in-memory store:', err.message);
    redis = null;
  });
  redis.on('connect', () => {
    console.log('[policyOrchestrator] Redis connected');
  });
} catch (_) {
  console.warn('[policyOrchestrator] ioredis not available, using in-memory store');
  redis = null;
}

// TTL of 24 hours for deployment records stored in Redis
const DEPLOYMENT_TTL_S = 86400;

async function setDeployment(id, data) {
  if (redis) {
    await redis.set(`deployment:${id}`, JSON.stringify(data), 'EX', DEPLOYMENT_TTL_S).catch((err) => {
      console.warn('[policyOrchestrator] Redis set failed:', err.message);
    });
  }
  // Always keep a copy in-memory too (fast read path and offline fallback)
  deploymentsCache.set(id, data);
}

async function getDeployment(id) {
  if (redis) {
    try {
      const val = await redis.get(`deployment:${id}`);
      if (val) return JSON.parse(val);
    } catch (err) {
      console.warn('[policyOrchestrator] Redis get failed:', err.message);
    }
  }
  return deploymentsCache.get(id) || null;
}

async function hasDeployment(id) {
  if (redis) {
    try {
      const exists = await redis.exists(`deployment:${id}`);
      if (exists) return true;
    } catch (err) {
      console.warn('[policyOrchestrator] Redis exists check failed:', err.message);
    }
  }
  return deploymentsCache.has(id);
}

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

  // Record in persistent store for status lookups
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
  await setDeployment(deploymentId, record);

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

  // Try persistent store first (fast path — survives restarts)
  if (await hasDeployment(deploymentId)) {
    const record = await getDeployment(deploymentId);
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

  const record = await getDeployment(deploymentId);
  if (!record) {
    return { success: false, deploymentId, error: 'Deployment not found in store; manual rollback may be needed.' };
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

  // Update persistent record
  record.status     = 'rolled-back';
  record.rolledBackAt = new Date().toISOString();
  await setDeployment(deploymentId, record);

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
