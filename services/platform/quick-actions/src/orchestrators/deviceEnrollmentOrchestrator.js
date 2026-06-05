'use strict';

const { call } = require('../utils/serviceClient');

// ─── helpers ──────────────────────────────────────────────────────────────────

function genId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

/**
 * Execute a single orchestration step without throwing.
 * Returns { ok, name, result } or { ok: false, name, error }.
 */
async function step(name, fn) {
  try {
    const result = await fn();
    return { ok: true, name, result };
  } catch (err) {
    console.warn(`[deviceEnrollment] Step "${name}" failed:`, err.message);
    return { ok: false, name, error: err.message };
  }
}

// ─── platform-specific helpers ────────────────────────────────────────────────

async function enrollMacos(deviceId, deviceName, completedSteps) {
  const apnsPushToken = `apns-placeholder-${genId()}`;

  const s = await step('mdm-enroll-macos', () =>
    call('mdm', 'POST', '/api/mdm/enroll', {
      deviceId,
      deviceName,
      platform: 'macos',
      apnsPushToken,
    })
  );
  completedSteps.push(s);

  const sp = await step('push-macos-baseline-policy', () =>
    call('policy', 'POST', '/api/policies/assign', {
      target: deviceId,
      platform: 'macos',
      policyType: 'baseline',
    })
  );
  completedSteps.push(sp);

  return {
    apnsPushToken,
    enrollmentUrl: s.ok ? (s.result.enrollmentUrl || `mdmEnroll://enroll?device=${deviceId}`) : null,
    platformConfig: { apnsEnabled: true, mdmEnrolled: s.ok },
    nextSteps: ['Open System Preferences → Privacy & Security → Device Management', 'Trust the MDM profile'],
  };
}

async function enrollWindows(deviceId, deviceName, completedSteps) {
  const machinePassword = require('crypto').randomBytes(16).toString('hex');

  const s = await step('configure-winrm', () =>
    call('directory', 'POST', '/api/winrm/configure', {
      deviceId,
      deviceName,
      machinePassword,
    })
  );
  completedSteps.push(s);

  const sg = await step('push-windows-gpo', () =>
    call('directory', 'POST', '/api/gpo/baseline/apply', {
      target: deviceId,
      platform: 'windows',
    })
  );
  completedSteps.push(sg);

  return {
    machinePassword: s.ok ? machinePassword : null,
    enrollmentUrl: null,
    platformConfig: { winrmConfigured: s.ok, gpoApplied: sg.ok },
    nextSteps: ['Run gpupdate /force on the endpoint', 'Verify domain join in System Properties'],
  };
}

async function enrollLinux(deviceId, deviceName, completedSteps) {
  const s = await step('generate-sssd-config', () =>
    call('directory', 'POST', '/api/sssd/config', {
      deviceId,
      hostname: deviceName,
      realm: process.env.AD_REALM || 'OPENDIRECTORY.LOCAL',
    })
  );
  completedSteps.push(s);

  const sk = await step('create-kerberos-keytab', () =>
    call('kerberos', 'POST', '/api/keytabs', {
      principal: `host/${deviceName}`,
      deviceId,
    })
  );
  completedSteps.push(sk);

  const sp = await step('push-linux-hardening-policy', () =>
    call('policy', 'POST', '/api/policies/assign', {
      target: deviceId,
      platform: 'linux',
      policyType: 'hardening',
    })
  );
  completedSteps.push(sp);

  return {
    sssdConfig: s.ok ? (s.result.config || '# sssd.conf generated on server') : null,
    keytab: sk.ok ? (sk.result.keytabB64 || null) : null,
    enrollmentUrl: null,
    platformConfig: { sssdConfigured: s.ok, kerberosKeytab: sk.ok, hardeningApplied: sp.ok },
    nextSteps: [
      'Copy sssd.conf to /etc/sssd/sssd.conf',
      'Install the keytab to /etc/krb5.keytab',
      'Restart sssd: systemctl restart sssd',
    ],
  };
}

async function enrollMobile(platform, deviceId, deviceName, assignedUserId, completedSteps) {
  const s = await step('issue-mdm-enrollment-url', () =>
    call('mdm', 'POST', '/api/mdm/enroll', {
      deviceId,
      deviceName,
      platform,
      assignedUserId,
    })
  );
  completedSteps.push(s);

  if (assignedUserId) {
    const sn = await step('send-enrollment-invitation', () =>
      call('auth', 'POST', '/api/notifications', {
        userId: assignedUserId,
        type: 'device_enrollment',
        payload: {
          platform,
          deviceName,
          enrollmentUrl: s.ok ? s.result.enrollmentUrl : null,
        },
      })
    );
    completedSteps.push(sn);
  }

  return {
    enrollmentUrl: s.ok ? (s.result.enrollmentUrl || `mdmenroll://enroll?device=${deviceId}&platform=${platform}`) : null,
    platformConfig: { mdmEnrolled: s.ok },
    nextSteps: ['Open the enrollment URL on the device', 'Follow the MDM profile installation prompts'],
  };
}

// ─── public orchestrators ─────────────────────────────────────────────────────

/**
 * Enroll a device — OS-aware one-click enrollment.
 *
 * @param {object} params
 * @param {string} params.platform       - 'macos' | 'windows' | 'linux' | 'ios' | 'android'
 * @param {string} params.deviceName     - Hostname / device label
 * @param {string} [params.serialNumber] - Hardware serial number
 * @param {string} [params.enrollmentToken]
 * @param {string} [params.assignedUserId]
 * @param {string} [params.ouDn]         - AD OU distinguished name for the computer account
 */
async function enrollDevice({ platform, deviceName, serialNumber, enrollmentToken, assignedUserId, ouDn }) {
  if (!platform)    throw new Error('platform is required');
  if (!deviceName)  throw new Error('deviceName is required');

  const deviceId     = genId();
  const completedSteps = [];
  const defaultOu    = ouDn || 'CN=Computers,DC=opendirectory,DC=local';

  // ── Common step 1: Create device record ──────────────────────────────────
  const s1 = await step('create-device-record', () =>
    call('device', 'POST', '/api/devices', {
      id: deviceId,
      name: deviceName,
      platform,
      serialNumber,
      assignedUserId,
      enrollmentToken,
      status: 'enrolling',
    })
  );
  completedSteps.push(s1);

  // ── Common step 2: Create computer account in AD ──────────────────────
  let computerDn = `CN=${deviceName},${defaultOu}`;
  const s2 = await step('create-ad-computer', async () => {
    const res = await call('samba', 'POST', '/api/computers/join', {
      computerName: deviceName,
      ouDn: defaultOu,
      platform,
    });
    computerDn = res.dn || res.computerDn || computerDn;
    return res;
  });
  completedSteps.push(s2);

  // ── Platform-specific steps ───────────────────────────────────────────
  let platformResult = {};
  switch (platform.toLowerCase()) {
    case 'macos':
      platformResult = await enrollMacos(deviceId, deviceName, completedSteps);
      break;
    case 'windows':
      platformResult = await enrollWindows(deviceId, deviceName, completedSteps);
      break;
    case 'linux':
      platformResult = await enrollLinux(deviceId, deviceName, completedSteps);
      break;
    case 'ios':
    case 'android':
      platformResult = await enrollMobile(platform, deviceId, deviceName, assignedUserId, completedSteps);
      break;
    default:
      console.warn(`[deviceEnrollment] Unknown platform "${platform}", skipping platform-specific steps`);
  }

  const failed = completedSteps.filter(s => !s.ok);
  return {
    success: failed.length === 0,
    deviceId,
    computerDn,
    platform,
    enrollmentUrl:  platformResult.enrollmentUrl  || null,
    platformConfig: platformResult.platformConfig || {},
    nextSteps:      platformResult.nextSteps      || [],
    completedSteps: completedSteps.map(s => ({ name: s.name, ok: s.ok, error: s.error })),
    ...(failed.length > 0 ? {
      failedAt: failed[0].name,
      error: failed[0].error,
      warnings: failed.map(s => `${s.name}: ${s.error}`),
    } : {}),
  };
}

/**
 * Get the enrollment status of a device.
 */
async function getEnrollmentStatus(deviceId) {
  if (!deviceId) throw new Error('deviceId is required');

  try {
    const [deviceRes, mdmRes] = await Promise.allSettled([
      call('device', 'GET', `/api/devices/${encodeURIComponent(deviceId)}`),
      call('mdm', 'GET', `/api/mdm/devices/${encodeURIComponent(deviceId)}/status`),
    ]);

    return {
      success: true,
      deviceId,
      device:       deviceRes.status === 'fulfilled' ? deviceRes.value : null,
      mdmStatus:    mdmRes.status    === 'fulfilled' ? mdmRes.value    : null,
      warnings: [
        deviceRes.status === 'rejected' ? `device-service: ${deviceRes.reason.message}` : null,
        mdmRes.status    === 'rejected' ? `mdm: ${mdmRes.reason.message}`               : null,
      ].filter(Boolean),
    };
  } catch (err) {
    return { success: false, deviceId, error: err.message };
  }
}

/**
 * Unenroll a device — optionally wipe it first.
 */
async function unenrollDevice(deviceId, { wipe = false } = {}) {
  if (!deviceId) throw new Error('deviceId is required');

  const completedSteps = [];

  if (wipe) {
    const sw = await step('wipe-device', () =>
      call('mdm', 'POST', `/api/mdm/devices/${encodeURIComponent(deviceId)}/wipe`, {})
    );
    completedSteps.push(sw);
  }

  const s1 = await step('remove-mdm-enrollment', () =>
    call('mdm', 'DELETE', `/api/mdm/devices/${encodeURIComponent(deviceId)}`)
  );
  completedSteps.push(s1);

  const s2 = await step('remove-device-record', () =>
    call('device', 'DELETE', `/api/devices/${encodeURIComponent(deviceId)}`)
  );
  completedSteps.push(s2);

  const failed = completedSteps.filter(s => !s.ok);
  return {
    success: failed.length === 0,
    deviceId,
    wiped: wipe,
    unenrolledAt: new Date().toISOString(),
    completedSteps: completedSteps.map(s => ({ name: s.name, ok: s.ok, error: s.error })),
    ...(failed.length > 0 ? { warnings: failed.map(s => `${s.name}: ${s.error}`) } : {}),
  };
}

/**
 * Enroll multiple devices in parallel (fleet operation).
 *
 * @param {Array<object>} devices - Array of device enrollment param objects.
 */
async function bulkEnroll(devices) {
  if (!Array.isArray(devices) || devices.length === 0) {
    throw new Error('devices must be a non-empty array');
  }

  const results = await Promise.allSettled(
    devices.map(d => enrollDevice(d))
  );

  const summary = results.map((r, i) => ({
    index: i,
    deviceName: devices[i].deviceName,
    success: r.status === 'fulfilled' ? r.value.success : false,
    result:  r.status === 'fulfilled' ? r.value : null,
    error:   r.status === 'rejected'  ? r.reason.message : null,
  }));

  const succeeded = summary.filter(s => s.success).length;
  return {
    total: devices.length,
    succeeded,
    failed: devices.length - succeeded,
    results: summary,
  };
}

module.exports = {
  enrollDevice,
  getEnrollmentStatus,
  unenrollDevice,
  bulkEnroll,
};
