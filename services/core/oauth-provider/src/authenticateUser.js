'use strict';

async function authenticateUser({ username, password, mfaCode }) {
  if (typeof username !== 'string' || !username.trim() || typeof password !== 'string' || !password
    || username.length > 255 || password.length > 4096 || (mfaCode !== undefined && typeof mfaCode !== 'string')) {
    return { status: 400, error: 'invalid_request' };
  }
  try {
    const baseUrl = process.env.AUTH_SERVICE_URL || 'http://authentication-service';
    const response = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      redirect: 'error',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, ...(mfaCode ? { mfaCode } : {}) }),
      signal: AbortSignal.timeout(5000),
    });
    if (response.status >= 500) return { status: 503, error: 'authentication_unavailable' };
    if (!response.ok) return { status: 401, error: 'invalid_credentials' };
    const data = await response.json();
    if (data?.mfaRequired || data?.requiresMFA || data?.mfa_required) return { status: 401, error: 'mfa_required' };
    const user = data?.user;
    if (response.status !== 200 || data?.success !== true || typeof user?.id !== 'string' || !user.id.trim()
      || user.active === false || user.status === 'disabled') return { status: 401, error: 'invalid_credentials' };
    return { user };
  } catch {
    return { status: 503, error: 'authentication_unavailable' };
  }
}

module.exports = { authenticateUser };
