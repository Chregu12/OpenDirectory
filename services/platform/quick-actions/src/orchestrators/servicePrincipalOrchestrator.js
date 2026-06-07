'use strict';

const crypto = require('crypto');
const { call } = require('../utils/serviceClient');

// ─── helpers ──────────────────────────────────────────────────────────────────

function generateClientId()     { return crypto.randomUUID(); }
function generateClientSecret() { return crypto.randomBytes(32).toString('hex'); }

/**
 * Wrap a single orchestration step. Returns { ok, result } or { ok: false, error }.
 * Never throws — allows the caller to decide whether to continue or abort.
 */
async function step(name, fn, rollbackFns) {
  try {
    const result = await fn();
    return { ok: true, name, result };
  } catch (err) {
    console.warn(`[servicePrincipal] Step "${name}" failed:`, err.message);
    return { ok: false, name, error: err.message };
  }
}

async function rollback(steps, context) {
  for (const rb of steps) {
    try {
      await rb(context);
    } catch (e) {
      console.warn('[servicePrincipal] rollback step failed:', e.message);
    }
  }
}

// ─── public orchestrators ─────────────────────────────────────────────────────

/**
 * Create a Service Principal — application identity across AD/Kerberos/auth.
 *
 * @param {object} params
 * @param {string} params.appName      - Short application name (no spaces)
 * @param {string} params.description  - Human-readable description
 * @param {string[]} params.permissions - List of permission strings to assign
 * @param {string} params.createdBy    - User or service initiating creation
 */
async function createServicePrincipal({ appName, description = '', permissions = [], createdBy = 'system' }) {
  if (!appName) throw new Error('appName is required');

  const clientId     = generateClientId();
  const clientSecret = generateClientSecret();
  const samAccount   = `${appName}$`;
  const spn          = `app/${appName}`;

  const completedSteps = [];
  const rollbackFns    = [];
  let serviceAccountDn = null;

  // Step 1 – Create AD computer/service account in Samba AD
  const s1 = await step('create-ad-account', async () => {
    const res = await call('samba', 'POST', '/api/computers/join', {
      computerName: samAccount,
      description,
      serviceAccount: true,
    });
    serviceAccountDn = res.dn || res.computerDn || `CN=${samAccount},CN=Computers,DC=opendirectory,DC=local`;
    return res;
  });
  completedSteps.push(s1);
  if (s1.ok) {
    rollbackFns.push(async () =>
      call('samba', 'DELETE', `/api/computers/${encodeURIComponent(samAccount)}`)
    );
  } else {
    // Provide a fallback DN even if samba is unreachable
    serviceAccountDn = `CN=${samAccount},CN=Computers,DC=opendirectory,DC=local`;
    console.warn('[servicePrincipal] Continuing despite AD account creation failure');
  }

  // Step 2 – Register Kerberos SPN
  const s2 = await step('create-kerberos-spn', async () =>
    call('kerberos', 'POST', '/api/principals', {
      principal: spn,
      password: clientSecret,
    })
  );
  completedSteps.push(s2);
  if (s2.ok) {
    rollbackFns.push(async () =>
      call('kerberos', 'DELETE', `/api/principals/${encodeURIComponent(spn)}`)
    );
  }

  // Step 3 – Register in auth-service as a service account
  const s3 = await step('register-service-account', async () =>
    call('auth', 'POST', '/api/service-accounts', {
      name:      appName,
      clientId,
      clientSecret,
      description,
      createdBy,
    })
  );
  completedSteps.push(s3);
  if (s3.ok) {
    rollbackFns.push(async () =>
      call('auth', 'DELETE', `/api/service-accounts/${encodeURIComponent(clientId)}`)
    );
  }

  // Step 4 – Assign requested permissions via PIM
  const assignedPermissions = [];
  if (permissions.length > 0) {
    const s4 = await step('assign-permissions', async () => {
      const res = await call('pim', 'POST', `/api/v1/permissions/users/${encodeURIComponent(clientId)}/assign`, {
        permissions,
        principal: clientId,
        principalType: 'servicePrincipal',
      });
      assignedPermissions.push(...permissions);
      return res;
    });
    completedSteps.push(s4);
    if (s4.ok) {
      rollbackFns.push(async () =>
        call('pim', 'POST', `/api/v1/permissions/users/${encodeURIComponent(clientId)}/revoke`, {
          permissions,
        })
      );
    }
  }

  const failed = completedSteps.filter(s => !s.ok);
  const success = failed.length === 0;

  if (!success) {
    console.warn(`[servicePrincipal] createServicePrincipal completed with ${failed.length} failed step(s). Not rolling back partial creation.`);
  }

  return {
    success,
    clientId,
    // Only return secret on initial creation
    clientSecret: s3.ok ? clientSecret : null,
    spn,
    serviceAccountDn,
    permissions: assignedPermissions,
    completedSteps: completedSteps.map(s => ({ name: s.name, ok: s.ok, error: s.error })),
    ...(success ? {} : {
      failedAt: failed[0].name,
      error: failed[0].error,
    }),
  };
}

/**
 * List all service principals (aggregated from auth-service).
 */
async function listServicePrincipals() {
  try {
    const res = await call('auth', 'GET', '/api/service-accounts');
    return { success: true, data: res.data || res.accounts || res || [] };
  } catch (err) {
    return { success: false, error: err.message, data: [] };
  }
}

/**
 * Get full details for a single service principal.
 */
async function getServicePrincipalDetails(clientId) {
  if (!clientId) throw new Error('clientId is required');

  const [authResult, pimResult] = await Promise.allSettled([
    call('auth', 'GET', `/api/service-accounts/${encodeURIComponent(clientId)}`),
    call('pim', 'GET', `/api/v1/permissions/users/${encodeURIComponent(clientId)}`),
  ]);

  return {
    success: true,
    clientId,
    account:     authResult.status === 'fulfilled' ? authResult.value : null,
    permissions: pimResult.status  === 'fulfilled' ? pimResult.value  : null,
    warnings: [
      authResult.status === 'rejected' ? `auth-service: ${authResult.reason.message}` : null,
      pimResult.status  === 'rejected' ? `pim: ${pimResult.reason.message}`           : null,
    ].filter(Boolean),
  };
}

/**
 * Delete a service principal — revoke PIM, remove Kerberos SPN, delete AD account.
 */
async function deleteServicePrincipal(clientId) {
  if (!clientId) throw new Error('clientId is required');

  const completedSteps = [];

  // Fetch account details first to get the appName/spn
  let appName = clientId;
  try {
    const acct = await call('auth', 'GET', `/api/service-accounts/${encodeURIComponent(clientId)}`);
    appName = acct.name || acct.data?.name || clientId;
  } catch { /* continue with clientId as fallback */ }

  const spn        = `app/${appName}`;
  const samAccount = `${appName}$`;

  // Step 1 – Revoke all PIM permissions
  const s1 = await step('revoke-permissions', () =>
    call('pim', 'POST', `/api/v1/permissions/users/${encodeURIComponent(clientId)}/revoke-all`, {})
  );
  completedSteps.push(s1);

  // Step 2 – Delete from auth-service
  const s2 = await step('delete-service-account', () =>
    call('auth', 'DELETE', `/api/service-accounts/${encodeURIComponent(clientId)}`)
  );
  completedSteps.push(s2);

  // Step 3 – Delete Kerberos SPN
  const s3 = await step('delete-kerberos-spn', () =>
    call('kerberos', 'DELETE', `/api/principals/${encodeURIComponent(spn)}`)
  );
  completedSteps.push(s3);

  // Step 4 – Delete AD account
  const s4 = await step('delete-ad-account', () =>
    call('samba', 'DELETE', `/api/computers/${encodeURIComponent(samAccount)}`)
  );
  completedSteps.push(s4);

  const failed = completedSteps.filter(s => !s.ok);
  return {
    success: failed.length === 0,
    clientId,
    deletedAt: new Date().toISOString(),
    completedSteps: completedSteps.map(s => ({ name: s.name, ok: s.ok, error: s.error })),
    ...(failed.length > 0 ? { warnings: failed.map(s => `${s.name}: ${s.error}`) } : {}),
  };
}

/**
 * Rotate the client secret for a service principal.
 * Generates a new secret, updates auth-service and Kerberos SPN password.
 */
async function rotateServicePrincipalSecret(clientId) {
  if (!clientId) throw new Error('clientId is required');

  const newSecret  = generateClientSecret();
  const completedSteps = [];

  let appName = clientId;
  try {
    const acct = await call('auth', 'GET', `/api/service-accounts/${encodeURIComponent(clientId)}`);
    appName = acct.name || acct.data?.name || clientId;
  } catch { /* use fallback */ }

  const spn = `app/${appName}`;

  // Step 1 – Update auth-service
  const s1 = await step('update-auth-secret', () =>
    call('auth', 'PATCH', `/api/service-accounts/${encodeURIComponent(clientId)}`, {
      clientSecret: newSecret,
      rotatedAt: new Date().toISOString(),
    })
  );
  completedSteps.push(s1);

  // Step 2 – Update Kerberos SPN password
  const s2 = await step('update-kerberos-password', () =>
    call('kerberos', 'PATCH', `/api/principals/${encodeURIComponent(spn)}`, {
      password: newSecret,
    })
  );
  completedSteps.push(s2);

  const failed = completedSteps.filter(s => !s.ok);
  return {
    success:     failed.length === 0,
    clientId,
    // Only expose new secret if the primary auth-service step succeeded
    newClientSecret: s1.ok ? newSecret : null,
    rotatedAt: new Date().toISOString(),
    completedSteps: completedSteps.map(s => ({ name: s.name, ok: s.ok, error: s.error })),
    ...(failed.length > 0 ? { warnings: failed.map(s => `${s.name}: ${s.error}`) } : {}),
  };
}

module.exports = {
  createServicePrincipal,
  listServicePrincipals,
  getServicePrincipalDetails,
  deleteServicePrincipal,
  rotateServicePrincipalSecret,
};
