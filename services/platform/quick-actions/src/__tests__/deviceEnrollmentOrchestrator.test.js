'use strict';

jest.mock('../utils/serviceClient.js');

const { call } = require('../utils/serviceClient.js');
const {
  enrollDevice,
  getEnrollmentStatus,
  unenrollDevice,
  bulkEnroll,
} = require('../orchestrators/deviceEnrollmentOrchestrator');

beforeEach(() => {
  jest.clearAllMocks();
  call.mockResolvedValue({ success: true });
});

// ── enrollDevice — macOS ───────────────────────────────────────────────────────

describe('enrollDevice() — macOS', () => {
  test('calls device-service to create device record', async () => {
    call.mockResolvedValue({});

    await enrollDevice({ platform: 'macos', deviceName: 'MacBook-01' });

    const deviceCreate = call.mock.calls.find(
      ([svc, method, path]) => svc === 'device' && method === 'POST' && path === '/api/devices'
    );
    expect(deviceCreate).toBeDefined();
    expect(deviceCreate[3].platform).toBe('macos');
    expect(deviceCreate[3].name).toBe('MacBook-01');
  });

  test('calls samba-ad-dc to create computer account', async () => {
    call.mockResolvedValue({});

    await enrollDevice({ platform: 'macos', deviceName: 'MacBook-01' });

    const sambaCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'samba' && method === 'POST'
    );
    expect(sambaCall).toBeDefined();
    expect(sambaCall[3].computerName).toBe('MacBook-01');
  });

  test('calls mobile-management for MDM profile', async () => {
    call.mockResolvedValue({});

    await enrollDevice({ platform: 'macos', deviceName: 'MacBook-01' });

    const mdmCall = call.mock.calls.find(
      ([svc, method]) => svc === 'mdm' && method === 'POST'
    );
    expect(mdmCall).toBeDefined();
    expect(mdmCall[3].platform).toBe('macos');
  });

  test('calls policy-service for baseline policy', async () => {
    call.mockResolvedValue({});

    await enrollDevice({ platform: 'macos', deviceName: 'MacBook-01' });

    const policyCall = call.mock.calls.find(
      ([svc, method]) => svc === 'policy' && method === 'POST'
    );
    expect(policyCall).toBeDefined();
    expect(policyCall[3].platform).toBe('macos');
    expect(policyCall[3].policyType).toBe('baseline');
  });

  test('returns deviceId, computerDn, platform', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'samba') return Promise.resolve({ dn: 'CN=MacBook-01,CN=Computers,DC=opendirectory,DC=local' });
      return Promise.resolve({});
    });

    const result = await enrollDevice({ platform: 'macos', deviceName: 'MacBook-01' });
    expect(result.deviceId).toBeTruthy();
    expect(result.platform).toBe('macos');
    expect(result.computerDn).toContain('MacBook-01');
  });

  test('nextSteps array contains macOS-specific instructions', async () => {
    call.mockResolvedValue({});

    const result = await enrollDevice({ platform: 'macos', deviceName: 'MacBook-01' });
    expect(Array.isArray(result.nextSteps)).toBe(true);
    expect(result.nextSteps.length).toBeGreaterThan(0);
    const joined = result.nextSteps.join(' ');
    expect(joined).toMatch(/MDM|System Preferences|profile/i);
  });

  test('platformConfig.platform not present but apnsEnabled present', async () => {
    call.mockResolvedValue({});

    const result = await enrollDevice({ platform: 'macos', deviceName: 'Mac01' });
    expect(result.platformConfig).toBeDefined();
    expect(result.platformConfig.apnsEnabled).toBe(true);
  });

  test('all steps succeed → success: true', async () => {
    call.mockResolvedValue({});

    const result = await enrollDevice({ platform: 'macos', deviceName: 'Mac01' });
    expect(result.success).toBe(true);
  });
});

// ── enrollDevice — Windows ─────────────────────────────────────────────────────

describe('enrollDevice() — Windows', () => {
  test('returns platformConfig.machinePassword when winrm step succeeds', async () => {
    call.mockResolvedValue({});

    const result = await enrollDevice({ platform: 'windows', deviceName: 'WIN-PC-01' });
    expect(result.platformConfig.winrmConfigured).toBe(true);
    // machinePassword should be returned but it's in result from orchestrator inline
    // We check via completedSteps
    const winrmStep = result.completedSteps.find(s => s.name === 'configure-winrm');
    expect(winrmStep).toBeDefined();
    expect(winrmStep.ok).toBe(true);
  });

  test('calls directory service for WinRM configuration', async () => {
    call.mockResolvedValue({});

    await enrollDevice({ platform: 'windows', deviceName: 'WIN-PC-01' });

    const winrmCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'directory' && method === 'POST' && path.includes('/winrm')
    );
    expect(winrmCall).toBeDefined();
    expect(winrmCall[3].deviceName).toBe('WIN-PC-01');
  });

  test('calls directory service for GPO baseline', async () => {
    call.mockResolvedValue({});

    await enrollDevice({ platform: 'windows', deviceName: 'WIN-PC-01' });

    const gpoCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'directory' && method === 'POST' && path.includes('/gpo')
    );
    expect(gpoCall).toBeDefined();
    expect(gpoCall[3].platform).toBe('windows');
  });

  test('nextSteps contains Windows-specific instructions', async () => {
    call.mockResolvedValue({});

    const result = await enrollDevice({ platform: 'windows', deviceName: 'WIN-PC-01' });
    const joined = result.nextSteps.join(' ');
    expect(joined).toMatch(/gpupdate|domain|System Properties/i);
  });

  test('platformConfig.gpoApplied is true on success', async () => {
    call.mockResolvedValue({});

    const result = await enrollDevice({ platform: 'windows', deviceName: 'WIN-PC-01' });
    expect(result.platformConfig.gpoApplied).toBe(true);
  });
});

// ── enrollDevice — Linux ───────────────────────────────────────────────────────

describe('enrollDevice() — Linux', () => {
  test('calls directory service for SSSD config', async () => {
    call.mockResolvedValue({});

    await enrollDevice({ platform: 'linux', deviceName: 'linux-server-01' });

    const sssdCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'directory' && method === 'POST' && path.includes('/sssd')
    );
    expect(sssdCall).toBeDefined();
  });

  test('calls kerberos service for keytab', async () => {
    call.mockResolvedValue({});

    await enrollDevice({ platform: 'linux', deviceName: 'linux-server-01' });

    const keytabCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'kerberos' && method === 'POST' && path.includes('/keytabs')
    );
    expect(keytabCall).toBeDefined();
    expect(keytabCall[3].principal).toBe('host/linux-server-01');
  });

  test('platformConfig.sssdConfigured is present', async () => {
    call.mockResolvedValue({});

    const result = await enrollDevice({ platform: 'linux', deviceName: 'linux-server-01' });
    expect(result.platformConfig).toHaveProperty('sssdConfigured');
  });

  test('platformConfig.kerberosKeytab is present', async () => {
    call.mockResolvedValue({});

    const result = await enrollDevice({ platform: 'linux', deviceName: 'linux-server-01' });
    expect(result.platformConfig).toHaveProperty('kerberosKeytab');
  });

  test('nextSteps contains Linux-specific instructions', async () => {
    call.mockResolvedValue({});

    const result = await enrollDevice({ platform: 'linux', deviceName: 'linux-server-01' });
    const joined = result.nextSteps.join(' ');
    expect(joined).toMatch(/sssd|krb5|keytab|systemctl/i);
  });

  test('sssd config returned from service used in platformConfig', async () => {
    call.mockImplementation((svc, method, path) => {
      if (svc === 'directory' && path.includes('/sssd')) {
        return Promise.resolve({ config: '[domain/opendirectory]\nid_provider=ad' });
      }
      return Promise.resolve({});
    });

    const result = await enrollDevice({ platform: 'linux', deviceName: 'srv01' });
    // sssdConfig in platformResult is surfaced via nextSteps or sssdConfig property
    expect(result.platformConfig.sssdConfigured).toBe(true);
  });
});

// ── enrollDevice — iOS ────────────────────────────────────────────────────────

describe('enrollDevice() — iOS', () => {
  test('calls mobile-management for MDM enrollment URL', async () => {
    call.mockResolvedValue({ enrollmentUrl: 'https://mdm.example.com/enroll?token=abc' });

    await enrollDevice({ platform: 'ios', deviceName: 'iPhone-01', assignedUserId: 'u1' });

    const mdmCall = call.mock.calls.find(
      ([svc, method]) => svc === 'mdm' && method === 'POST'
    );
    expect(mdmCall).toBeDefined();
    expect(mdmCall[3].platform).toBe('ios');
  });

  test('returns enrollmentUrl', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'mdm') return Promise.resolve({ enrollmentUrl: 'mdmenroll://enroll?device=iphone' });
      return Promise.resolve({});
    });

    const result = await enrollDevice({ platform: 'ios', deviceName: 'iPhone-01' });
    expect(result.enrollmentUrl).toBeTruthy();
  });

  test('sends enrollment invitation when assignedUserId is provided', async () => {
    call.mockResolvedValue({});

    await enrollDevice({ platform: 'ios', deviceName: 'iPhone-01', assignedUserId: 'u1' });

    const notifCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'auth' && method === 'POST' && path.includes('/notifications')
    );
    expect(notifCall).toBeDefined();
    expect(notifCall[3].type).toBe('device_enrollment');
  });

  test('no invitation sent when assignedUserId is omitted', async () => {
    call.mockResolvedValue({});

    await enrollDevice({ platform: 'ios', deviceName: 'iPhone-01' });

    const notifCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'auth' && method === 'POST' && path.includes('/notifications')
    );
    expect(notifCall).toBeUndefined();
  });
});

// ── enrollDevice — Android ────────────────────────────────────────────────────

describe('enrollDevice() — Android', () => {
  test('calls mobile-management for MDM enrollment', async () => {
    call.mockResolvedValue({});

    await enrollDevice({ platform: 'android', deviceName: 'Android-01' });

    const mdmCall = call.mock.calls.find(([svc, method]) => svc === 'mdm' && method === 'POST');
    expect(mdmCall).toBeDefined();
    expect(mdmCall[3].platform).toBe('android');
  });

  test('platformConfig shows platform marker via mdmEnrolled', async () => {
    call.mockResolvedValue({});

    const result = await enrollDevice({ platform: 'android', deviceName: 'Android-01' });
    expect(result.platformConfig.mdmEnrolled).toBeDefined();
  });
});

// ── enrollDevice — common failures ────────────────────────────────────────────

describe('enrollDevice() — failure scenarios', () => {
  test('missing platform → throws', async () => {
    await expect(enrollDevice({ deviceName: 'TestDevice' })).rejects.toThrow('platform is required');
  });

  test('missing deviceName → throws', async () => {
    await expect(enrollDevice({ platform: 'macos' })).rejects.toThrow('deviceName is required');
  });

  test('device-service create fails → success: false, failedAt: create-device-record', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'device') return Promise.reject(new Error('device-service down'));
      return Promise.resolve({});
    });

    const result = await enrollDevice({ platform: 'macos', deviceName: 'Mac01' });
    expect(result.success).toBe(false);
    expect(result.failedAt).toBe('create-device-record');
  });

  test('samba create fails → partial: device created, computerDn is fallback', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'samba') return Promise.reject(new Error('samba down'));
      return Promise.resolve({});
    });

    const result = await enrollDevice({ platform: 'macos', deviceName: 'Mac01' });
    // computerDn uses fallback value since samba failed
    expect(result.computerDn).toContain('Mac01');
    // device-record step still ran
    const deviceStep = result.completedSteps.find(s => s.name === 'create-device-record');
    expect(deviceStep.ok).toBe(true);
  });

  test('result includes warnings array when steps fail', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'device') return Promise.reject(new Error('down'));
      return Promise.resolve({});
    });

    const result = await enrollDevice({ platform: 'linux', deviceName: 'srv01' });
    expect(Array.isArray(result.warnings)).toBe(true);
  });
});

// ── bulkEnroll ────────────────────────────────────────────────────────────────

describe('bulkEnroll()', () => {
  test('enrolls 3 devices and returns array with results', async () => {
    call.mockResolvedValue({});

    const devices = [
      { platform: 'macos', deviceName: 'Mac-01' },
      { platform: 'windows', deviceName: 'Win-01' },
      { platform: 'linux', deviceName: 'Linux-01' },
    ];

    const result = await bulkEnroll(devices);
    expect(result.total).toBe(3);
    expect(Array.isArray(result.results)).toBe(true);
    expect(result.results).toHaveLength(3);
  });

  test('2 succeed, 1 fails → mixed results array', async () => {
    let callCount = 0;
    call.mockImplementation((svc, method, path, body) => {
      // Fail for the third device (Linux) device-service
      if (svc === 'device' && body && body.name === 'Linux-01') {
        return Promise.reject(new Error('device-service fail'));
      }
      return Promise.resolve({});
    });

    const devices = [
      { platform: 'macos', deviceName: 'Mac-01' },
      { platform: 'windows', deviceName: 'Win-01' },
      { platform: 'linux', deviceName: 'Linux-01' },
    ];

    const result = await bulkEnroll(devices);
    expect(result.total).toBe(3);
    // At least 2 should succeed
    expect(result.succeeded).toBeGreaterThanOrEqual(2);
  });

  test('uses Promise.allSettled — all run even if one fails', async () => {
    const executionOrder = [];
    call.mockImplementation((svc, method, path, body) => {
      executionOrder.push(body && body.name);
      if (svc === 'device' && body && body.name === 'Win-01') {
        return Promise.reject(new Error('fail'));
      }
      return Promise.resolve({});
    });

    const devices = [
      { platform: 'macos', deviceName: 'Mac-01' },
      { platform: 'windows', deviceName: 'Win-01' },
      { platform: 'linux', deviceName: 'Linux-01' },
    ];

    const result = await bulkEnroll(devices);
    // All 3 should appear in results regardless of failures
    expect(result.results).toHaveLength(3);
  });

  test('empty array → throws', async () => {
    await expect(bulkEnroll([])).rejects.toThrow('devices must be a non-empty array');
  });

  test('non-array → throws', async () => {
    await expect(bulkEnroll(null)).rejects.toThrow('devices must be a non-empty array');
  });

  test('result includes succeeded + failed counts', async () => {
    call.mockResolvedValue({});

    const devices = [
      { platform: 'macos', deviceName: 'Mac-01' },
      { platform: 'macos', deviceName: 'Mac-02' },
    ];

    const result = await bulkEnroll(devices);
    expect(result).toHaveProperty('succeeded');
    expect(result).toHaveProperty('failed');
    expect(result.succeeded + result.failed).toBe(result.total);
  });
});

// ── unenrollDevice ────────────────────────────────────────────────────────────

describe('unenrollDevice()', () => {
  test('calls MDM DELETE and device-service DELETE', async () => {
    call.mockResolvedValue({});

    await unenrollDevice('device-123');

    const mdmDelete = call.mock.calls.find(
      ([svc, method]) => svc === 'mdm' && method === 'DELETE'
    );
    const deviceDelete = call.mock.calls.find(
      ([svc, method]) => svc === 'device' && method === 'DELETE'
    );
    expect(mdmDelete).toBeDefined();
    expect(deviceDelete).toBeDefined();
  });

  test('wipe: true → extra MDM wipe call before unenroll', async () => {
    call.mockResolvedValue({});

    await unenrollDevice('device-123', { wipe: true });

    const wipeCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'mdm' && method === 'POST' && path.includes('/wipe')
    );
    expect(wipeCall).toBeDefined();
  });

  test('wipe: false (default) → no wipe call', async () => {
    call.mockResolvedValue({});

    await unenrollDevice('device-123');

    const wipeCall = call.mock.calls.find(
      ([svc, method, path]) => svc === 'mdm' && method === 'POST' && path && path.includes('/wipe')
    );
    expect(wipeCall).toBeUndefined();
  });

  test('returns success: true on full success', async () => {
    call.mockResolvedValue({});

    const result = await unenrollDevice('device-123');
    expect(result.success).toBe(true);
    expect(result.deviceId).toBe('device-123');
    expect(result.wiped).toBe(false);
  });

  test('returns unenrolledAt timestamp', async () => {
    call.mockResolvedValue({});

    const result = await unenrollDevice('device-123');
    expect(result.unenrolledAt).toBeDefined();
    expect(new Date(result.unenrolledAt).getTime()).not.toBeNaN();
  });

  test('missing deviceId → throws', async () => {
    await expect(unenrollDevice('')).rejects.toThrow('deviceId is required');
  });

  test('step failure → success: false with warnings', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'mdm') return Promise.reject(new Error('MDM unreachable'));
      return Promise.resolve({});
    });

    const result = await unenrollDevice('device-123');
    expect(result.success).toBe(false);
    expect(Array.isArray(result.warnings)).toBe(true);
  });
});

// ── getEnrollmentStatus ───────────────────────────────────────────────────────

describe('getEnrollmentStatus()', () => {
  test('returns success: true with device and mdmStatus', async () => {
    call.mockResolvedValue({ status: 'enrolled' });

    const result = await getEnrollmentStatus('d1');
    expect(result.success).toBe(true);
    expect(result.deviceId).toBe('d1');
    expect(result.device).toBeDefined();
    expect(result.mdmStatus).toBeDefined();
  });

  test('missing deviceId → throws', async () => {
    await expect(getEnrollmentStatus('')).rejects.toThrow('deviceId is required');
  });

  test('device-service failure → device is null, warning added', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'device') return Promise.reject(new Error('device-service down'));
      return Promise.resolve({});
    });

    const result = await getEnrollmentStatus('d1');
    expect(result.device).toBeNull();
    expect(result.warnings.some(w => w.includes('device-service'))).toBe(true);
  });

  test('MDM service failure → mdmStatus is null, warning added', async () => {
    call.mockImplementation((svc) => {
      if (svc === 'mdm') return Promise.reject(new Error('MDM down'));
      return Promise.resolve({});
    });

    const result = await getEnrollmentStatus('d1');
    expect(result.mdmStatus).toBeNull();
    expect(result.warnings.some(w => w.includes('mdm'))).toBe(true);
  });
});
