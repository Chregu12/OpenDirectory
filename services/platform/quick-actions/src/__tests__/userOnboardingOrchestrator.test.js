'use strict';

jest.mock('../utils/serviceClient.js');

const { call } = require('../utils/serviceClient.js');
const {
  onboardUser,
  offboardUser,
} = require('../orchestrators/userOnboardingOrchestrator');

beforeEach(() => {
  jest.clearAllMocks();
  call.mockResolvedValue({ success: true });
});

// ── onboardUser ───────────────────────────────────────────────────────────────

describe('onboardUser()', () => {
  const baseParams = {
    firstName: 'Alice',
    lastName: 'Smith',
    email: 'alice.smith@example.com',
    department: 'Engineering',
    jobTitle: 'Engineer',
    role: 'standard',
  };

  test('all 7 steps succeed → success: true', async () => {
    call.mockResolvedValue({ dn: 'CN=Alice Smith,OU=Engineering,OU=Users,DC=opendirectory,DC=local', policies: [] });

    const result = await onboardUser(baseParams);
    expect(result.success).toBe(true);
  });

  test('returns userId (non-empty string)', async () => {
    call.mockResolvedValue({});

    const result = await onboardUser(baseParams);
    expect(result.userId).toBeTruthy();
    expect(typeof result.userId).toBe('string');
  });

  test('returns userDn', async () => {
    call.mockResolvedValue({ dn: 'CN=Alice Smith,OU=Engineering,OU=Users,DC=opendirectory,DC=local' });

    const result = await onboardUser(baseParams);
    expect(result.userDn).toContain('Alice Smith');
  });

  test('returns email', async () => {
    call.mockResolvedValue({});

    const result = await onboardUser(baseParams);
    expect(result.email).toBe(baseParams.email);
  });

  test('temporaryPassword is generated (non-empty, non-null)', async () => {
    call.mockResolvedValue({});

    const result = await onboardUser(baseParams);
    expect(result.temporaryPassword).toBeTruthy();
    expect(result.temporaryPassword.length).toBeGreaterThan(0);
  });

  test('step 1: creates AD user in enterprise-directory', async () => {
    call.mockResolvedValue({});

    await onboardUser(baseParams);

    const directoryCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'directory' && method === 'POST' && path === '/api/users'
    );
    expect(directoryCall).toBeDefined();
    expect(directoryCall[3].givenName).toBe('Alice');
    expect(directoryCall[3].mail).toBe(baseParams.email);
  });

  test('step 2: creates auth-service user with forcePasswordChange', async () => {
    call.mockResolvedValue({});

    await onboardUser(baseParams);

    const authCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'auth' && method === 'POST' && path === '/api/users'
    );
    expect(authCall).toBeDefined();
    expect(authCall[3].forcePasswordChange).toBe(true);
    expect(authCall[3].email).toBe(baseParams.email);
  });

  test('standard role → calls auth RBAC role assignment', async () => {
    call.mockResolvedValue({});

    await onboardUser({ ...baseParams, role: 'standard' });

    const rbacCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'auth' && method === 'POST' && path === '/api/users/roles'
    );
    expect(rbacCall).toBeDefined();
    expect(rbacCall[3].role).toBe('standard');
  });

  test('admin role → calls PIM for elevated role assignment', async () => {
    call.mockResolvedValue({});

    await onboardUser({ ...baseParams, role: 'admin' });

    const pimCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'pim' && method === 'POST' && path.includes('/pim/roles')
    );
    expect(pimCall).toBeDefined();
    expect(pimCall[3].role).toBe('admin');
  });

  test('elevated role → calls PIM for elevated role assignment', async () => {
    call.mockResolvedValue({});

    await onboardUser({ ...baseParams, role: 'elevated' });

    const pimCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'pim' && method === 'POST' && path.includes('/pim/roles')
    );
    expect(pimCall).toBeDefined();
  });

  test('step 4: adds to department group in Samba', async () => {
    call.mockResolvedValue({});

    await onboardUser(baseParams);

    const sambaCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'samba' && method === 'POST' && path.includes('/members')
    );
    expect(sambaCall).toBeDefined();
  });

  test('step 5: assigns device when assignDeviceId provided', async () => {
    call.mockResolvedValue({});

    await onboardUser({ ...baseParams, assignDeviceId: 'd-123' });

    const deviceCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'device' && method === 'PATCH' && path.includes('d-123')
    );
    expect(deviceCall).toBeDefined();
    expect(deviceCall[3].assignedEmail).toBe(baseParams.email);
  });

  test('step 5: skipped when assignDeviceId not provided', async () => {
    call.mockResolvedValue({});

    await onboardUser(baseParams);

    const deviceCall = call.mock.calls.find(
      ([svc, method]) => svc === 'device' && method === 'PATCH'
    );
    expect(deviceCall).toBeUndefined();
  });

  test('step 6: pushes user policies via policy-service', async () => {
    call.mockResolvedValue({});

    await onboardUser(baseParams);

    const policyCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'policy' && method === 'POST' && path.includes('/policies/assign')
    );
    expect(policyCall).toBeDefined();
    expect(policyCall[3].targetType).toBe('user');
  });

  test('step 7: sends welcome notification', async () => {
    call.mockResolvedValue({});

    await onboardUser(baseParams);

    const notifCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'auth' && method === 'POST' && path === '/api/notifications'
    );
    expect(notifCall).toBeDefined();
    expect(notifCall[3].type).toBe('welcome');
  });

  test('notification step failure → non-blocking, warnings array has it', async () => {
    call.mockImplementation((svc, method, path) => {
      if (svc === 'auth' && method === 'POST' && path === '/api/notifications') {
        return Promise.reject(new Error('notifications down'));
      }
      return Promise.resolve({});
    });

    const result = await onboardUser(baseParams);
    // Other steps succeeded, user was created
    expect(result.userId).toBeTruthy();
    // warnings contains notification failure
    expect(Array.isArray(result.warnings)).toBe(true);
    expect(result.warnings.some(w => w.includes('send-welcome-notification'))).toBe(true);
  });

  test('auth step fails → temporaryPassword is null', async () => {
    call.mockImplementation((svc, method, path) => {
      if (svc === 'auth' && method === 'POST' && path === '/api/users') {
        return Promise.reject(new Error('auth down'));
      }
      return Promise.resolve({});
    });

    const result = await onboardUser(baseParams);
    expect(result.temporaryPassword).toBeNull();
  });

  test('missing firstName/lastName → throws', async () => {
    await expect(onboardUser({ email: 'a@b.com' })).rejects.toThrow('firstName and lastName are required');
  });

  test('missing email → throws', async () => {
    await expect(onboardUser({ firstName: 'Alice', lastName: 'Smith' })).rejects.toThrow('email is required');
  });

  test('completedSteps array is present with correct structure', async () => {
    call.mockResolvedValue({});

    const result = await onboardUser(baseParams);
    expect(Array.isArray(result.completedSteps)).toBe(true);
    result.completedSteps.forEach(s => {
      expect(s).toHaveProperty('name');
      expect(s).toHaveProperty('ok');
    });
  });

  test('groupMemberships array populated after step 4', async () => {
    call.mockResolvedValue({});

    const result = await onboardUser(baseParams);
    expect(Array.isArray(result.groupMemberships)).toBe(true);
    expect(result.groupMemberships).toContain('Engineering');
  });

  test('assignedDevice populated when assignDeviceId provided and step succeeds', async () => {
    call.mockResolvedValue({});

    const result = await onboardUser({ ...baseParams, assignDeviceId: 'device-42' });
    expect(result.assignedDevice).toBe('device-42');
  });

  test('assignedDevice is null when assignDeviceId not provided', async () => {
    call.mockResolvedValue({});

    const result = await onboardUser(baseParams);
    expect(result.assignedDevice).toBeNull();
  });
});

// ── offboardUser ──────────────────────────────────────────────────────────────

describe('offboardUser()', () => {
  test('missing userId → throws', async () => {
    await expect(offboardUser('')).rejects.toThrow('userId is required');
  });

  test('disables AD + auth accounts → disabled: true', async () => {
    call.mockResolvedValue({ groups: [], data: [] });

    const result = await offboardUser('u1');
    expect(result.disabled).toBe(true);
  });

  test('calls directory service to disable AD account', async () => {
    call.mockResolvedValue({ groups: [], data: [] });

    await offboardUser('u1');

    const disableCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'directory' && method === 'POST' && path.includes('/disable')
    );
    expect(disableCall).toBeDefined();
  });

  test('calls auth service to disable auth account', async () => {
    call.mockResolvedValue({ groups: [], data: [] });

    await offboardUser('u1');

    const authDisable = call.mock.calls.find(
      ([svc, method, path]) => svc === 'auth' && method === 'PATCH' && path.includes('u1')
    );
    expect(authDisable).toBeDefined();
    expect(authDisable[3].disabled).toBe(true);
  });

  test('revokes PIM elevations', async () => {
    call.mockResolvedValue({ groups: [], data: [] });

    await offboardUser('u1');

    const pimCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'pim' && method === 'POST' && path.includes('/revoke-all')
    );
    expect(pimCall).toBeDefined();
  });

  test('revokeDevices: true → calls device-service to unassign devices', async () => {
    call.mockImplementation((svc, method, path) => {
      if (svc === 'device' && method === 'GET') {
        return Promise.resolve({ data: [{ id: 'd1' }, { id: 'd2' }] });
      }
      if (svc === 'samba' && method === 'GET') {
        return Promise.resolve({ groups: [] });
      }
      return Promise.resolve({});
    });

    const result = await offboardUser('u1', { revokeDevices: true });
    expect(result.devicesRevoked).toBeDefined();
    expect(Array.isArray(result.devicesRevoked)).toBe(true);
  });

  test('revokeDevices: false → no device unassignment calls', async () => {
    call.mockImplementation((svc, method, path) => {
      if (svc === 'samba' && method === 'GET') return Promise.resolve({ groups: [] });
      return Promise.resolve({});
    });

    await offboardUser('u1', { revokeDevices: false });

    const deviceGet = call.mock.calls.find(
      ([svc, method, path]) => svc === 'device' && method === 'GET' && path.includes('assignedUser')
    );
    expect(deviceGet).toBeUndefined();
  });

  test('transferFilesTo provided → passed to directory archive call', async () => {
    call.mockImplementation((svc, method, path) => {
      if (svc === 'samba' && method === 'GET') return Promise.resolve({ groups: [] });
      if (svc === 'device' && method === 'GET') return Promise.resolve({ data: [] });
      return Promise.resolve({});
    });

    await offboardUser('u1', { transferFilesTo: 'manager@example.com' });

    const archiveCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'directory' && method === 'POST' && path.includes('/archive')
    );
    expect(archiveCall).toBeDefined();
    expect(archiveCall[3].transferFilesTo).toBe('manager@example.com');
  });

  test('returns offboardedAt timestamp', async () => {
    call.mockImplementation((svc, method) => {
      if (svc === 'samba' && method === 'GET') return Promise.resolve({ groups: [] });
      if (svc === 'device' && method === 'GET') return Promise.resolve({ data: [] });
      return Promise.resolve({});
    });

    const result = await offboardUser('u1');
    expect(result.offboardedAt).toBeDefined();
    expect(new Date(result.offboardedAt).getTime()).not.toBeNaN();
  });

  test('returns userId', async () => {
    call.mockImplementation((svc, method) => {
      if (svc === 'samba' && method === 'GET') return Promise.resolve({ groups: [] });
      if (svc === 'device' && method === 'GET') return Promise.resolve({ data: [] });
      return Promise.resolve({});
    });

    const result = await offboardUser('user-id-123');
    expect(result.userId).toBe('user-id-123');
  });

  test('step failure → warnings array populated', async () => {
    call.mockImplementation((svc, method, path) => {
      if (svc === 'directory' && method === 'POST' && path.includes('/disable')) {
        return Promise.reject(new Error('directory unavailable'));
      }
      if (svc === 'samba' && method === 'GET') return Promise.resolve({ groups: [] });
      if (svc === 'device' && method === 'GET') return Promise.resolve({ data: [] });
      return Promise.resolve({});
    });

    const result = await offboardUser('u1');
    expect(Array.isArray(result.warnings)).toBe(true);
    expect(result.warnings.length).toBeGreaterThan(0);
  });

  test('removes from groups in Samba', async () => {
    call.mockImplementation((svc, method, path) => {
      if (svc === 'samba' && method === 'GET') {
        return Promise.resolve({ groups: [{ dn: 'CN=Engineering,OU=Groups,DC=opendirectory,DC=local', name: 'Engineering' }] });
      }
      if (svc === 'device' && method === 'GET') return Promise.resolve({ data: [] });
      return Promise.resolve({});
    });

    await offboardUser('u1');

    const groupRemove = call.mock.calls.find(
      ([svc, method, path]) => svc === 'samba' && method === 'DELETE' && path.includes('/members/')
    );
    expect(groupRemove).toBeDefined();
  });

  test('archives home directory via directory service', async () => {
    call.mockImplementation((svc, method, path) => {
      if (svc === 'samba' && method === 'GET') return Promise.resolve({ groups: [] });
      if (svc === 'device' && method === 'GET') return Promise.resolve({ data: [] });
      return Promise.resolve({});
    });

    await offboardUser('u1');

    const archiveCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'directory' && method === 'POST' && path.includes('/archive')
    );
    expect(archiveCall).toBeDefined();
  });
});
