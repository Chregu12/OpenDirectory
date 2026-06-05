'use strict';

jest.mock('../utils/serviceClient.js');

const { call } = require('../utils/serviceClient.js');
const {
  createServicePrincipal,
  listServicePrincipals,
  getServicePrincipalDetails,
  deleteServicePrincipal,
  rotateServicePrincipalSecret,
} = require('../orchestrators/servicePrincipalOrchestrator');

// UUID v4 regex
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
// 64-char hex string (32 bytes)
const SECRET_RE = /^[0-9a-f]{64}$/i;

beforeEach(() => {
  jest.clearAllMocks();
  call.mockResolvedValue({ success: true });
});

// ── createServicePrincipal ─────────────────────────────────────────────────────

describe('createServicePrincipal()', () => {
  test('happy path — all steps succeed → success: true', async () => {
    call.mockResolvedValue({ dn: 'CN=myApp$,CN=Computers,DC=opendirectory,DC=local' });

    const result = await createServicePrincipal({
      appName: 'myApp',
      description: 'Test app',
      permissions: ['read:users'],
      createdBy: 'admin',
    });

    expect(result.success).toBe(true);
  });

  test('returns clientId in valid UUID format', async () => {
    call.mockResolvedValue({});

    const result = await createServicePrincipal({ appName: 'testApp' });
    expect(result.clientId).toMatch(UUID_RE);
  });

  test('returns clientSecret as 64-char hex string', async () => {
    call.mockResolvedValue({});

    const result = await createServicePrincipal({ appName: 'testApp' });
    expect(result.clientSecret).toMatch(SECRET_RE);
  });

  test('returns spn in app/<appName> format', async () => {
    call.mockResolvedValue({});

    const result = await createServicePrincipal({ appName: 'myService' });
    expect(result.spn).toBe('app/myService');
  });

  test('returns serviceAccountDn', async () => {
    call.mockResolvedValue({ dn: 'CN=myApp$,CN=Computers,DC=opendirectory,DC=local' });

    const result = await createServicePrincipal({ appName: 'myApp' });
    expect(result.serviceAccountDn).toBeTruthy();
  });

  test('permissions array is forwarded to PIM assignment call', async () => {
    call.mockResolvedValue({});

    const permissions = ['read:users', 'write:devices'];
    await createServicePrincipal({ appName: 'permApp', permissions });

    // The PIM assign call should include the permissions
    const pimCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'pim' && method === 'POST' && path.includes('/assign')
    );
    expect(pimCall).toBeDefined();
    expect(pimCall[3].permissions).toEqual(permissions);
  });

  test('empty permissions → no PIM call made', async () => {
    call.mockResolvedValue({});

    await createServicePrincipal({ appName: 'noPermApp', permissions: [] });

    const pimCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'pim' && method === 'POST' && path.includes('/assign')
    );
    expect(pimCall).toBeUndefined();
  });

  test('samba step fails → success: false, failedAt: create-ad-account', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'samba') return Promise.reject(new Error('samba-ad-dc unreachable'));
      return Promise.resolve({});
    });

    const result = await createServicePrincipal({ appName: 'failApp' });
    expect(result.success).toBe(false);
    expect(result.failedAt).toBe('create-ad-account');
  });

  test('kerberos step fails → success: false, failedAt: create-kerberos-spn', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'kerberos') return Promise.reject(new Error('kerberos unreachable'));
      return Promise.resolve({});
    });

    const result = await createServicePrincipal({ appName: 'failKrb' });
    expect(result.success).toBe(false);
    expect(result.failedAt).toBe('create-kerberos-spn');
  });

  test('auth step fails → clientSecret is null', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'auth') return Promise.reject(new Error('auth unreachable'));
      return Promise.resolve({});
    });

    const result = await createServicePrincipal({ appName: 'failAuth' });
    expect(result.clientSecret).toBeNull();
  });

  test('completedSteps array has correct structure', async () => {
    call.mockResolvedValue({});

    const result = await createServicePrincipal({ appName: 'myApp', permissions: ['r'] });
    expect(Array.isArray(result.completedSteps)).toBe(true);
    result.completedSteps.forEach(s => {
      expect(s).toHaveProperty('name');
      expect(s).toHaveProperty('ok');
    });
  });

  test('missing appName → throws', async () => {
    await expect(createServicePrincipal({})).rejects.toThrow('appName is required');
  });

  test('all services down → success: false with completedSteps', async () => {
    call.mockRejectedValue(new Error('network down'));

    const result = await createServicePrincipal({ appName: 'allDown' });
    expect(result.success).toBe(false);
    expect(result.completedSteps.length).toBeGreaterThan(0);
  });

  test('makes samba call with correct payload', async () => {
    call.mockResolvedValue({});

    await createServicePrincipal({ appName: 'sambaTest', description: 'desc' });

    const sambaCall = call.mock.calls.find(([svc, method]) => svc === 'samba' && method === 'POST');
    expect(sambaCall).toBeDefined();
    expect(sambaCall[3].serviceAccount).toBe(true);
    expect(sambaCall[3].computerName).toBe('sambaTest$');
  });

  test('makes auth service call with clientId and clientSecret', async () => {
    call.mockResolvedValue({});

    const result = await createServicePrincipal({ appName: 'authTest' });

    const authCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'auth' && method === 'POST' && path.includes('/service-accounts')
    );
    expect(authCall).toBeDefined();
    expect(authCall[3].clientId).toBe(result.clientId);
    expect(authCall[3].clientSecret).toMatch(SECRET_RE);
  });
});

// ── listServicePrincipals ─────────────────────────────────────────────────────

describe('listServicePrincipals()', () => {
  test('returns success: true with data array on success', async () => {
    call.mockResolvedValue({ data: [{ clientId: 'c1' }, { clientId: 'c2' }] });

    const result = await listServicePrincipals();
    expect(result.success).toBe(true);
    expect(Array.isArray(result.data)).toBe(true);
    expect(result.data).toHaveLength(2);
  });

  test('empty list → returns []', async () => {
    call.mockResolvedValue({ data: [] });

    const result = await listServicePrincipals();
    expect(result.data).toEqual([]);
  });

  test('service error → returns success: false with error message', async () => {
    call.mockRejectedValue(new Error('auth-service down'));

    const result = await listServicePrincipals();
    expect(result.success).toBe(false);
    expect(result.error).toContain('auth-service down');
    expect(result.data).toEqual([]);
  });

  test('calls auth service GET /api/service-accounts', async () => {
    call.mockResolvedValue({ data: [] });

    await listServicePrincipals();

    expect(call).toHaveBeenCalledWith('auth', 'GET', '/api/service-accounts');
  });
});

// ── deleteServicePrincipal ────────────────────────────────────────────────────

describe('deleteServicePrincipal()', () => {
  test('all cleanup steps succeed → success: true', async () => {
    call.mockResolvedValue({ name: 'myApp' });

    const result = await deleteServicePrincipal('test-client-id');
    expect(result.success).toBe(true);
    expect(result.clientId).toBe('test-client-id');
  });

  test('returns deletedAt timestamp', async () => {
    call.mockResolvedValue({});

    const result = await deleteServicePrincipal('c1');
    expect(result.deletedAt).toBeDefined();
    expect(new Date(result.deletedAt).getTime()).not.toBeNaN();
  });

  test('missing clientId → throws', async () => {
    await expect(deleteServicePrincipal('')).rejects.toThrow('clientId is required');
  });

  test('one step fails → success: false with warnings', async () => {
    let callCount = 0;
    call.mockImplementation((svc, method) => {
      // Auth GET (lookup) succeeds, then PIM revoke fails
      if (svc === 'pim') return Promise.reject(new Error('pim-error'));
      return Promise.resolve({ name: 'myApp' });
    });

    const result = await deleteServicePrincipal('test-id');
    expect(result.success).toBe(false);
    expect(Array.isArray(result.warnings)).toBe(true);
  });

  test('calls 4 cleanup steps (revoke-pim, delete-auth, delete-kerberos, delete-samba)', async () => {
    call.mockResolvedValue({ name: 'testApp' });

    await deleteServicePrincipal('c1');

    // completedSteps should have 4 entries
    const result = await deleteServicePrincipal('c1');
    expect(result.completedSteps).toHaveLength(4);
  });

  test('partial cleanup → warnings list each failed step', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'kerberos') return Promise.reject(new Error('kerberos error'));
      if (svc === 'samba') return Promise.reject(new Error('samba error'));
      return Promise.resolve({ name: 'myApp' });
    });

    const result = await deleteServicePrincipal('c1');
    expect(result.warnings.length).toBeGreaterThan(0);
  });
});

// ── rotateServicePrincipalSecret ──────────────────────────────────────────────

describe('rotateServicePrincipalSecret()', () => {
  test('generates new 64-char hex secret', async () => {
    call.mockResolvedValue({ name: 'myApp' });

    const result = await rotateServicePrincipalSecret('c1');
    expect(result.newClientSecret).toMatch(SECRET_RE);
  });

  test('returns rotatedAt timestamp', async () => {
    call.mockResolvedValue({});

    const result = await rotateServicePrincipalSecret('c1');
    expect(result.rotatedAt).toBeDefined();
    expect(new Date(result.rotatedAt).getTime()).not.toBeNaN();
  });

  test('returns clientId', async () => {
    call.mockResolvedValue({});

    const result = await rotateServicePrincipalSecret('target-id');
    expect(result.clientId).toBe('target-id');
  });

  test('calls auth-service PATCH with new secret', async () => {
    call.mockResolvedValue({});

    const result = await rotateServicePrincipalSecret('c1');

    const authPatch = call.mock.calls.find(
      ([svc, method]) => svc === 'auth' && method === 'PATCH'
    );
    expect(authPatch).toBeDefined();
    expect(authPatch[3].clientSecret).toBe(result.newClientSecret);
  });

  test('calls kerberos PATCH with new secret', async () => {
    call.mockResolvedValue({});

    const result = await rotateServicePrincipalSecret('c1');

    const krbPatch = call.mock.calls.find(
      ([svc, method]) => svc === 'kerberos' && method === 'PATCH'
    );
    expect(krbPatch).toBeDefined();
    expect(krbPatch[3].password).toBe(result.newClientSecret);
  });

  test('kerberos step fails → returns partial with warning', async () => {
    call.mockImplementation((svc, method) => {
      if (svc === 'kerberos') return Promise.reject(new Error('kerberos unavailable'));
      return Promise.resolve({});
    });

    const result = await rotateServicePrincipalSecret('c1');
    expect(result.success).toBe(false);
    expect(Array.isArray(result.warnings)).toBe(true);
    expect(result.warnings[0]).toContain('update-kerberos-password');
  });

  test('auth step fails → newClientSecret is null', async () => {
    call.mockImplementation((svc, method) => {
      if (svc === 'auth' && method === 'PATCH') return Promise.reject(new Error('auth error'));
      return Promise.resolve({});
    });

    const result = await rotateServicePrincipalSecret('c1');
    expect(result.newClientSecret).toBeNull();
  });

  test('missing clientId → throws', async () => {
    await expect(rotateServicePrincipalSecret('')).rejects.toThrow('clientId is required');
  });

  test('completedSteps has 2 entries (auth-update + kerberos-update)', async () => {
    call.mockResolvedValue({});

    const result = await rotateServicePrincipalSecret('c1');
    expect(result.completedSteps).toHaveLength(2);
    expect(result.completedSteps.map(s => s.name)).toEqual(
      expect.arrayContaining(['update-auth-secret', 'update-kerberos-password'])
    );
  });
});

// ── getServicePrincipalDetails ────────────────────────────────────────────────

describe('getServicePrincipalDetails()', () => {
  test('returns account and permissions on success', async () => {
    call.mockResolvedValue({ name: 'myApp', permissions: ['read:users'] });

    const result = await getServicePrincipalDetails('c1');
    expect(result.success).toBe(true);
    expect(result.account).toBeDefined();
    expect(result.clientId).toBe('c1');
  });

  test('missing clientId → throws', async () => {
    await expect(getServicePrincipalDetails('')).rejects.toThrow('clientId is required');
  });

  test('auth-service failure → account is null, warning added', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'auth') return Promise.reject(new Error('auth down'));
      return Promise.resolve({ permissions: [] });
    });

    const result = await getServicePrincipalDetails('c1');
    expect(result.account).toBeNull();
    expect(result.warnings.some(w => w.includes('auth-service'))).toBe(true);
  });

  test('pim failure → permissions is null, warning added', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'pim') return Promise.reject(new Error('pim down'));
      return Promise.resolve({ name: 'myApp' });
    });

    const result = await getServicePrincipalDetails('c1');
    expect(result.permissions).toBeNull();
    expect(result.warnings.some(w => w.includes('pim'))).toBe(true);
  });
});
