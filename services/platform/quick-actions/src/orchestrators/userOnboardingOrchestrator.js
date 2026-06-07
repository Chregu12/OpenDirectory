'use strict';

const crypto = require('crypto');
const { call } = require('../utils/serviceClient');

// ─── helpers ──────────────────────────────────────────────────────────────────

function genId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

function generateTemporaryPassword() {
  // 16-char password: uppercase + lowercase + digits + special
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%';
  return Array.from(crypto.randomBytes(16))
    .map(b => chars[b % chars.length])
    .join('');
}

/**
 * Execute a single orchestration step without throwing.
 */
async function step(name, fn) {
  try {
    const result = await fn();
    return { ok: true, name, result };
  } catch (err) {
    console.warn(`[userOnboarding] Step "${name}" failed:`, err.message);
    return { ok: false, name, error: err.message };
  }
}

/** Map department name to an AD OU distinguished name. */
function departmentOu(department) {
  const dept = (department || 'General').replace(/\s+/g, '');
  return `OU=${dept},OU=Users,DC=opendirectory,DC=local`;
}

/** Map department to a Samba AD group DN. */
function departmentGroupDn(department) {
  const dept = (department || 'General').replace(/\s+/g, '');
  return `CN=${dept},OU=Groups,DC=opendirectory,DC=local`;
}

// ─── public orchestrators ─────────────────────────────────────────────────────

/**
 * Onboard a new employee — creates accounts, assigns roles and devices, sends welcome.
 *
 * @param {object} params
 * @param {string} params.firstName
 * @param {string} params.lastName
 * @param {string} params.email
 * @param {string} [params.department]
 * @param {string} [params.jobTitle]
 * @param {string} [params.role]        - 'admin' | 'elevated' | 'standard'
 * @param {string} [params.manager]     - Manager's DN or username
 * @param {string} [params.assignDeviceId]
 */
async function onboardUser({ firstName, lastName, email, department = 'General', jobTitle = '', role = 'standard', manager = '', assignDeviceId }) {
  if (!firstName || !lastName) throw new Error('firstName and lastName are required');
  if (!email) throw new Error('email is required');

  const userId          = genId();
  const temporaryPwd    = generateTemporaryPassword();
  const ouDn            = departmentOu(department);
  const groupDn         = departmentGroupDn(department);
  const completedSteps  = [];
  const groupMemberships = [];
  const policiesApplied  = [];
  let   userDn           = `CN=${firstName} ${lastName},${ouDn}`;

  // Step 1 – Create AD user in enterprise-directory
  const s1 = await step('create-ad-user', async () => {
    const res = await call('directory', 'POST', '/api/users', {
      givenName:  firstName,
      sn:         lastName,
      mail:       email,
      department,
      title:      jobTitle,
      manager,
      ou:         ouDn,
      sAMAccountName: email.split('@')[0],
    });
    userDn = res.dn || res.userDn || userDn;
    return res;
  });
  completedSteps.push(s1);

  // Step 2 – Create auth-service user and set initial password
  const s2 = await step('create-auth-user', () =>
    call('auth', 'POST', '/api/users', {
      id:       userId,
      email,
      name:     `${firstName} ${lastName}`,
      password: temporaryPwd,
      forcePasswordChange: true,
      department,
      role,
    })
  );
  completedSteps.push(s2);

  // Step 3 – Assign role via PIM (elevated) or basic RBAC (standard)
  if (role === 'admin' || role === 'elevated') {
    const s3 = await step('assign-elevated-role', () =>
      call('pim', 'POST', '/api/v1/pim/roles', {
        userId,
        email,
        role,
        justification: `New employee onboarding: ${firstName} ${lastName}`,
        department,
      })
    );
    completedSteps.push(s3);
  } else {
    const s3 = await step('assign-standard-role', () =>
      call('auth', 'POST', '/api/users/roles', {
        userId,
        email,
        role: 'standard',
        department,
      })
    );
    completedSteps.push(s3);
  }

  // Step 4 – Add to department group in Samba AD
  const s4 = await step('add-to-department-group', async () => {
    const res = await call('samba', 'POST', `/api/groups/${encodeURIComponent(groupDn)}/members`, {
      userDn,
      email,
    });
    groupMemberships.push(department);
    return res;
  });
  completedSteps.push(s4);

  // Step 5 – Assign device if provided
  let assignedDevice = null;
  if (assignDeviceId) {
    const s5 = await step('assign-device', async () => {
      const res = await call('device', 'PATCH', `/api/devices/${encodeURIComponent(assignDeviceId)}`, {
        assignedUser:  userId,
        assignedEmail: email,
      });
      assignedDevice = assignDeviceId;
      return res;
    });
    completedSteps.push(s5);
  }

  // Step 6 – Push user policies
  const s6 = await step('push-user-policies', async () => {
    const res = await call('policy', 'POST', '/api/policies/assign', {
      targetType: 'user',
      targetId:   userId,
      department,
      role,
    });
    if (res.policies) policiesApplied.push(...res.policies);
    return res;
  });
  completedSteps.push(s6);

  // Step 7 – Send welcome notification
  const s7 = await step('send-welcome-notification', () =>
    call('auth', 'POST', '/api/notifications', {
      userId,
      email,
      type: 'welcome',
      payload: {
        name:       `${firstName} ${lastName}`,
        department,
        jobTitle,
        temporaryPassword: temporaryPwd,
        loginUrl: process.env.PORTAL_URL || 'https://opendirectory.heusser.local',
      },
    })
  );
  completedSteps.push(s7);

  const failed = completedSteps.filter(s => !s.ok);
  return {
    success: failed.length === 0,
    userId,
    userDn,
    email,
    temporaryPassword: s2.ok ? temporaryPwd : null,
    assignedDevice,
    groupMemberships,
    policiesApplied,
    completedSteps: completedSteps.map(s => ({ name: s.name, ok: s.ok, error: s.error })),
    ...(failed.length > 0 ? {
      failedAt: failed[0].name,
      error: failed[0].error,
      warnings: failed.map(s => `${s.name}: ${s.error}`),
    } : {}),
  };
}

/**
 * Offboard a departing employee — disable account, revoke privileges, unassign devices.
 *
 * @param {string} userId
 * @param {object} options
 * @param {boolean} [options.revokeDevices=true]  - Unassign all devices from the user
 * @param {string}  [options.transferFilesTo]     - UserId to transfer data ownership
 * @param {boolean} [options.disableAccount=true] - Whether to disable (vs. delete) the AD account
 */
async function offboardUser(userId, { revokeDevices = true, transferFilesTo, disableAccount = true } = {}) {
  if (!userId) throw new Error('userId is required');

  const completedSteps  = [];
  const devicesRevoked  = [];
  const groupsRemoved   = [];

  // Step 1 – Disable AD account
  const s1 = await step('disable-ad-account', () =>
    call('directory', 'POST', `/api/users/${encodeURIComponent(userId)}/disable`, {
      reason: 'offboarding',
      transferFilesTo,
    })
  );
  completedSteps.push(s1);

  // Step 2 – Revoke all PIM elevations
  const s2 = await step('revoke-pim-elevations', () =>
    call('pim', 'POST', `/api/v1/permissions/users/${encodeURIComponent(userId)}/revoke-all`, {
      reason: 'offboarding',
    })
  );
  completedSteps.push(s2);

  // Step 3 – Disable auth-service account
  const s3 = await step('disable-auth-account', () =>
    call('auth', 'PATCH', `/api/users/${encodeURIComponent(userId)}`, {
      disabled: true,
      disabledAt: new Date().toISOString(),
      disabledReason: 'offboarding',
    })
  );
  completedSteps.push(s3);

  // Step 4 – Unassign all devices
  if (revokeDevices) {
    const s4 = await step('unassign-devices', async () => {
      const devRes = await call('device', 'GET', `/api/devices?assignedUser=${encodeURIComponent(userId)}`);
      const userDevices = devRes.data || devRes.devices || [];

      await Promise.allSettled(
        userDevices.map(async (d) => {
          try {
            await call('device', 'PATCH', `/api/devices/${encodeURIComponent(d.id)}`, {
              assignedUser: null,
              assignedEmail: null,
            });
            devicesRevoked.push(d.id);
          } catch (e) {
            console.warn(`[userOnboarding] Failed to unassign device ${d.id}:`, e.message);
          }
        })
      );
      return { devicesRevoked };
    });
    completedSteps.push(s4);
  }

  // Step 5 – Remove from all groups (best-effort)
  const s5 = await step('remove-from-groups', async () => {
    const groupRes = await call('samba', 'GET', `/api/users/${encodeURIComponent(userId)}/groups`);
    const groups   = groupRes.groups || [];

    await Promise.allSettled(
      groups.map(async (g) => {
        try {
          await call('samba', 'DELETE', `/api/groups/${encodeURIComponent(g.dn || g.id)}/members/${encodeURIComponent(userId)}`);
          groupsRemoved.push(g.name || g.dn || g.id);
        } catch (e) {
          console.warn(`[userOnboarding] Failed to remove from group ${g.name}:`, e.message);
        }
      })
    );
    return { groupsRemoved };
  });
  completedSteps.push(s5);

  // Step 6 – Archive home directory reference
  const s6 = await step('archive-home-directory', () =>
    call('directory', 'POST', `/api/users/${encodeURIComponent(userId)}/archive`, {
      transferFilesTo,
      archivedAt: new Date().toISOString(),
    })
  );
  completedSteps.push(s6);

  const failed = completedSteps.filter(s => !s.ok);
  return {
    disabled: s1.ok || s3.ok,
    userId,
    devicesRevoked,
    groupsRemoved,
    offboardedAt: new Date().toISOString(),
    completedSteps: completedSteps.map(s => ({ name: s.name, ok: s.ok, error: s.error })),
    ...(failed.length > 0 ? { warnings: failed.map(s => `${s.name}: ${s.error}`) } : {}),
  };
}

module.exports = { onboardUser, offboardUser };
