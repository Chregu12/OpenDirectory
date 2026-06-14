'use strict';

jest.mock('../utils/serviceClient.js');
jest.mock('../utils/eventPublisher', () => ({ publish: jest.fn(), connect: jest.fn() }));

const { call } = require('../utils/serviceClient.js');

// Re-require between describe blocks to reset the in-memory deployments Map
function freshOrchestrator() {
  jest.resetModules();
  jest.mock('../utils/serviceClient.js');
  jest.mock('../utils/eventPublisher', () => ({ publish: jest.fn(), connect: jest.fn() }));
  const { call: freshCall } = require('../utils/serviceClient.js');
  const orchestrator = require('../orchestrators/policyOrchestrator');
  return { orchestrator, call: freshCall };
}

let deployPolicy, getPolicyDeploymentStatus, rollbackPolicy, getComplianceSnapshot;

beforeAll(() => {
  ({ deployPolicy, getPolicyDeploymentStatus, rollbackPolicy, getComplianceSnapshot } =
    require('../orchestrators/policyOrchestrator'));
});

beforeEach(() => {
  jest.clearAllMocks();
  call.mockResolvedValue({ data: { name: 'TestPolicy', settings: { enforce: true, audit: true } } });
});

// ── deployPolicy ──────────────────────────────────────────────────────────────

describe('deployPolicy()', () => {
  test('missing policyId → throws', async () => {
    await expect(deployPolicy({ targetType: 'ou' })).rejects.toThrow('policyId is required');
  });

  test('missing targetType → throws', async () => {
    await expect(deployPolicy({ policyId: 'p1' })).rejects.toThrow('targetType is required');
  });

  test('targetType: ou → calls enterprise-directory GPO apply endpoint', async () => {
    call.mockResolvedValue({ data: { name: 'GPO', settings: {} } });

    await deployPolicy({ policyId: 'p1', targetType: 'ou', targetId: 'OU=IT,DC=od,DC=local' });

    const gpoCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'directory' && method === 'POST' && path.includes('/apply')
    );
    expect(gpoCall).toBeDefined();
    expect(gpoCall[3].ouDn).toBe('OU=IT,DC=od,DC=local');
  });

  test('targetType: device → calls mobile-management policy push', async () => {
    call.mockResolvedValue({ data: { name: 'DevicePolicy', settings: {} } });

    await deployPolicy({ policyId: 'p1', targetType: 'device', targetId: 'd-123' });

    const mdmCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'mdm' && method === 'POST' && path === '/api/policies/push'
    );
    expect(mdmCall).toBeDefined();
    expect(mdmCall[3].deviceId).toBe('d-123');
  });

  test('targetType: user → calls conditional-access (pim) assign', async () => {
    call.mockResolvedValue({ data: { name: 'UserPolicy', settings: {} } });

    await deployPolicy({ policyId: 'p1', targetType: 'user', targetId: 'u-1' });

    const pimCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'pim' && method === 'POST' && path === '/api/policies/assign'
    );
    expect(pimCall).toBeDefined();
    expect(pimCall[3].userId).toBe('u-1');
  });

  test('targetType: group → calls directory group assign', async () => {
    call.mockResolvedValue({ data: { name: 'GroupPolicy', settings: {} } });

    await deployPolicy({ policyId: 'p1', targetType: 'group', targetId: 'g-1' });

    const groupCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'directory' && method === 'POST' && path.includes('/group/assign')
    );
    expect(groupCall).toBeDefined();
    expect(groupCall[3].groupId).toBe('g-1');
  });

  test('targetType: all → broadcasts to all targets in parallel', async () => {
    call.mockResolvedValue({ data: { name: 'AllPolicy', settings: {} } });

    const result = await deployPolicy({ policyId: 'p1', targetType: 'all' });

    // Should call mdm, directory, and policy service
    const mdmCall = call.mock.calls.find(([svc]) => svc === 'mdm');
    const dirCall = call.mock.calls.find(([svc, , path]) => svc === 'directory' && path && path.includes('/gpo/'));
    const polCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'policy' && method === 'POST' && path === '/api/policies/broadcast'
    );
    expect(mdmCall).toBeDefined();
    expect(dirCall).toBeDefined();
    expect(polCall).toBeDefined();
  });

  test('dryRun: true → does NOT call deploy endpoints, returns dryRunReport', async () => {
    call.mockResolvedValue({ data: { name: 'TestPolicy', settings: { key: 'val' } } });

    const result = await deployPolicy({ policyId: 'p1', targetType: 'ou', targetId: 'OU=IT', dryRun: true });

    expect(result.dryRun).toBe(true);
    expect(result.deployed).toBe(false);
    expect(result.dryRunReport).toBeDefined();
    expect(result.dryRunReport.targetType).toBe('ou');

    // No GPO apply call should have been made
    const gpoCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'directory' && method === 'POST' && path && path.includes('/apply')
    );
    expect(gpoCall).toBeUndefined();
  });

  test('dryRun: true → returns dryRunReport with policyId and targetType', async () => {
    call.mockResolvedValue({ data: { name: 'MyPolicy', settings: { k: 'v' } } });

    const result = await deployPolicy({ policyId: 'myPol', targetType: 'device', dryRun: true });
    expect(result.dryRunReport.policyId).toBe('myPol');
    expect(result.dryRunReport.targetType).toBe('device');
  });

  test('enforced: true → passes enforced flag to downstream calls', async () => {
    call.mockResolvedValue({ data: { name: 'P', settings: {} } });

    await deployPolicy({ policyId: 'p1', targetType: 'device', targetId: 'd1', enforced: true });

    const mdmCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'mdm' && method === 'POST'
    );
    expect(mdmCall).toBeDefined();
    expect(mdmCall[3].enforced).toBe(true);
  });

  test('returns deploymentId', async () => {
    call.mockResolvedValue({ data: { name: 'P', settings: {} } });

    const result = await deployPolicy({ policyId: 'p1', targetType: 'ou', targetId: 'OU=IT' });
    expect(result.deploymentId).toBeTruthy();
    expect(typeof result.deploymentId).toBe('string');
  });

  test('records deployment locally for status lookup', async () => {
    call.mockResolvedValue({ data: { name: 'P', settings: {} } });

    const deployResult = await deployPolicy({ policyId: 'p1', targetType: 'ou', targetId: 'OU=IT' });
    const statusResult = await getPolicyDeploymentStatus(deployResult.deploymentId);

    expect(statusResult.success).toBe(true);
    expect(statusResult.policyId).toBe('p1');
  });

  test('policy fetch fails → returns success: false, failedAt: fetch-policy', async () => {
    call.mockImplementation((svc, method, path) => {
      if (svc === 'policy' && method === 'GET') return Promise.reject(new Error('policy-service down'));
      return Promise.resolve({});
    });

    const result = await deployPolicy({ policyId: 'p1', targetType: 'ou' });
    expect(result.success).toBe(false);
    expect(result.failedAt).toBe('fetch-policy');
  });

  test('records deployment to policy-service after apply', async () => {
    call.mockResolvedValue({ data: { name: 'P', settings: {} } });

    await deployPolicy({ policyId: 'p1', targetType: 'user', targetId: 'u1' });

    const recordCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'policy' && method === 'POST' && path === '/api/policies/deployments'
    );
    expect(recordCall).toBeDefined();
  });
});

// ── getPolicyDeploymentStatus ─────────────────────────────────────────────────

describe('getPolicyDeploymentStatus()', () => {
  test('returns status of existing deployment from local store', async () => {
    call.mockResolvedValue({ data: { name: 'P', settings: {} } });

    const deployResult = await deployPolicy({ policyId: 'pol-1', targetType: 'ou', targetId: 'OU=IT' });
    const status = await getPolicyDeploymentStatus(deployResult.deploymentId);

    expect(status.success).toBe(true);
    expect(status.deploymentId).toBe(deployResult.deploymentId);
  });

  test('unknown deploymentId falls back to policy-service', async () => {
    // Not in local store; mock the policy-service response
    call.mockResolvedValue({ deploymentId: 'xyz', status: 'deployed' });

    const result = await getPolicyDeploymentStatus('xyz');
    expect(result.success).toBe(true);
  });

  test('policy-service also fails → returns success: false', async () => {
    call.mockRejectedValue(new Error('policy-service down'));

    const result = await getPolicyDeploymentStatus('unknown-id');
    expect(result.success).toBe(false);
    expect(result.error).toBeTruthy();
  });

  test('missing deploymentId → throws', async () => {
    await expect(getPolicyDeploymentStatus('')).rejects.toThrow('deploymentId is required');
  });
});

// ── rollbackPolicy ────────────────────────────────────────────────────────────

describe('rollbackPolicy()', () => {
  test('missing deploymentId → throws', async () => {
    await expect(rollbackPolicy('')).rejects.toThrow('deploymentId is required');
  });

  test('unknown deploymentId → returns success: false', async () => {
    const result = await rollbackPolicy('non-existent-id');
    expect(result.success).toBe(false);
    expect(result.error).toContain('not found');
  });

  test('rolls back ou deployment by calling GPO remove', async () => {
    call.mockResolvedValue({ data: { name: 'P', settings: {} } });

    const deploy = await deployPolicy({ policyId: 'p1', targetType: 'ou', targetId: 'OU=IT' });
    const rollback = await rollbackPolicy(deploy.deploymentId);

    expect(rollback.success).toBe(true);
    const removeCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'directory' && method === 'POST' && path && path.includes('/remove')
    );
    expect(removeCall).toBeDefined();
  });

  test('rolls back device deployment by calling MDM delete', async () => {
    call.mockResolvedValue({ data: { name: 'P', settings: {} } });

    const deploy = await deployPolicy({ policyId: 'p1', targetType: 'device', targetId: 'd1' });
    const rollback = await rollbackPolicy(deploy.deploymentId);

    expect(rollback.success).toBe(true);
    const mdmDelete = call.mock.calls.find(
      ([svc, method, path]) => svc === 'mdm' && method === 'DELETE'
    );
    expect(mdmDelete).toBeDefined();
  });

  test('rolls back user deployment by calling pim delete', async () => {
    call.mockResolvedValue({ data: { name: 'P', settings: {} } });

    const deploy = await deployPolicy({ policyId: 'p1', targetType: 'user', targetId: 'u1' });
    const rollback = await rollbackPolicy(deploy.deploymentId);

    const pimDelete = call.mock.calls.find(
      ([svc, method]) => svc === 'pim' && method === 'DELETE'
    );
    expect(pimDelete).toBeDefined();
  });

  test('returns rolledBack: true', async () => {
    call.mockResolvedValue({ data: { name: 'P', settings: {} } });

    const deploy = await deployPolicy({ policyId: 'p1', targetType: 'ou', targetId: 'OU=IT' });
    const rollback = await rollbackPolicy(deploy.deploymentId);

    expect(rollback.rolledBack).toBe(true);
  });

  test('returns rolledBackAt timestamp', async () => {
    call.mockResolvedValue({ data: { name: 'P', settings: {} } });

    const deploy = await deployPolicy({ policyId: 'p1', targetType: 'ou', targetId: 'OU=IT' });
    const rollback = await rollbackPolicy(deploy.deploymentId);

    expect(rollback.rolledBackAt).toBeDefined();
    expect(new Date(rollback.rolledBackAt).getTime()).not.toBeNaN();
  });

  test('rollback failure → success: false with warnings', async () => {
    call.mockImplementation((svc, method, path) => {
      // Succeed for policy fetch and deploy steps
      if (svc === 'policy' && method === 'GET') return Promise.resolve({ data: { name: 'P', settings: {} } });
      if (svc === 'policy' && method === 'POST') return Promise.resolve({});
      if (svc === 'directory' && method === 'POST' && path && path.includes('/remove')) {
        return Promise.reject(new Error('rollback failed'));
      }
      return Promise.resolve({});
    });

    const deploy = await deployPolicy({ policyId: 'p1', targetType: 'ou', targetId: 'OU=IT' });
    const rollback = await rollbackPolicy(deploy.deploymentId);

    expect(rollback.success).toBe(false);
    expect(Array.isArray(rollback.warnings)).toBe(true);
  });
});

// ── getComplianceSnapshot ─────────────────────────────────────────────────────

describe('getComplianceSnapshot()', () => {
  test('returns snapshot with all expected fields', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'policy') {
        return Promise.resolve({ total: 100, compliant: 85, nonCompliant: 15, topViolations: ['no-antivirus'] });
      }
      return Promise.resolve({ total: 100, compliant: 85 });
    });

    const result = await getComplianceSnapshot();
    expect(result.success).toBe(true);
    expect(result.snapshot.total).toBe(100);
    expect(result.snapshot.compliant).toBe(85);
    expect(result.snapshot.nonCompliant).toBe(15);
    expect(Array.isArray(result.snapshot.topViolations)).toBe(true);
  });

  test('complianceRate calculated as percentage', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'policy') return Promise.resolve({ total: 100, compliant: 80, nonCompliant: 20, topViolations: [] });
      return Promise.resolve({ total: 100, compliant: 80 });
    });

    const result = await getComplianceSnapshot();
    expect(result.snapshot.complianceRate).toBe(80);
  });

  test('snapshot includes generatedAt timestamp', async () => {
    call.mockImplementation(() => Promise.resolve({ total: 10, compliant: 10, topViolations: [] }));

    const result = await getComplianceSnapshot();
    expect(result.snapshot.generatedAt).toBeDefined();
  });

  test('policy-service down → warning added', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'policy') return Promise.reject(new Error('policy-service unreachable'));
      return Promise.resolve({ total: 50, compliant: 40 });
    });

    const result = await getComplianceSnapshot();
    expect(result.success).toBe(true);
    expect(result.warnings.some(w => w.includes('policy-service'))).toBe(true);
  });

  test('device-service down → warning added', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'device') return Promise.reject(new Error('device-service unreachable'));
      return Promise.resolve({ total: 50, compliant: 40, topViolations: [] });
    });

    const result = await getComplianceSnapshot();
    expect(result.success).toBe(true);
    expect(result.warnings.some(w => w.includes('device-service'))).toBe(true);
  });

  test('both services down → still returns success: true with empty snapshot', async () => {
    call.mockRejectedValue(new Error('all down'));

    const result = await getComplianceSnapshot();
    expect(result.success).toBe(true);
    expect(result.warnings).toHaveLength(2);
  });

  test('fans out to both policy-service and device-service', async () => {
    call.mockImplementation(() => Promise.resolve({ total: 10, compliant: 8, topViolations: [] }));

    await getComplianceSnapshot();

    const policyCall = call.mock.calls.find(([svc]) => svc === 'policy');
    const deviceCall = call.mock.calls.find(([svc]) => svc === 'device');
    expect(policyCall).toBeDefined();
    expect(deviceCall).toBeDefined();
  });

  test('complianceRate is null when total is 0', async () => {
    call.mockImplementation(() => Promise.resolve({ total: 0, compliant: 0, topViolations: [] }));

    const result = await getComplianceSnapshot();
    expect(result.snapshot.complianceRate).toBeNull();
  });
});
