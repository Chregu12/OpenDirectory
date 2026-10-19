import { ensureSession, getAccessToken, logout } from '../lib/auth';
import { qaPost, qaDelete } from '../lib/quickActionsApi';

const session = () => ({ access_token: 'verified-access', expires_at: Date.now() + 3600000,
  user: { id: 'verified-subject', name: 'Verified User', username: 'verified', email: null, roles: ['user'], role: 'user' } });

beforeEach(async () => {
  Object.defineProperty(navigator, 'locks', { configurable: true, value: { request: jest.fn(async (_name, _options, action) => action()) } });
  if (!AbortSignal.timeout) Object.defineProperty(AbortSignal, 'timeout', { value: () => new AbortController().signal });
  global.fetch = jest.fn(async () => ({ ok: true, json: async () => ({ revoked: true }) } as Response));
  await logout();
  jest.clearAllMocks(); localStorage.clear(); sessionStorage.clear();
  document.cookie = 'od_csrf=browser-csrf';
  (global.fetch as jest.Mock).mockImplementation(async () => ({ ok: true, json: async () => session() }));
});

test('legacy auth_user and stored tokens cannot authenticate without the server', async () => {
  localStorage.setItem('auth_user', JSON.stringify({ role: 'admin' })); localStorage.setItem('access_token', 'forged'); localStorage.setItem('refresh_token', 'stolen');
  expect(getAccessToken()).toBeNull();
  (global.fetch as jest.Mock).mockResolvedValue({ ok: false, status: 401 });
  await expect(ensureSession(true)).rejects.toMatchObject({ status: 401 });
  expect(getAccessToken()).toBeNull(); expect(localStorage.getItem('auth_user')).toBeNull(); expect(localStorage.getItem('refresh_token')).toBeNull();
});
test('a single-flight Web Lock protects rotation, and credentials remain only in memory', async () => {
  const sessions = await Promise.all([ensureSession(true), ensureSession(true), ensureSession(true)]);
  expect(global.fetch).toHaveBeenCalledTimes(1); expect(navigator.locks.request).toHaveBeenCalledTimes(1);
  expect(sessions[0].user.roles).toEqual(['user']); expect(getAccessToken()).toBe('verified-access');
  expect(localStorage.getItem('access_token')).toBeNull(); expect(sessionStorage.length).toBe(0);
  expect(global.fetch).toHaveBeenCalledWith('/api/auth/oidc/session', expect.objectContaining({ method: 'POST', credentials: 'same-origin', headers: { 'X-OD-CSRF': 'browser-csrf' } }));
});
test('heartbeat forwards the in-memory token to avoid rotating a still-live family', async () => {
  await ensureSession(); await ensureSession(true);
  expect(global.fetch).toHaveBeenLastCalledWith('/api/auth/oidc/session', expect.objectContaining({ headers: { 'X-OD-CSRF': 'browser-csrf', Authorization: 'Bearer verified-access' } }));
});
test('authority outages invalidate local access instead of inventing a successful login', async () => {
  await ensureSession(); (global.fetch as jest.Mock).mockResolvedValue({ ok: false, status: 503 });
  await expect(ensureSession(true)).rejects.toMatchObject({ status: 503 }); expect(getAccessToken()).toBeNull();
});
test('unsupported Web Locks fail closed, without an unsafe refresh fallback', async () => {
  Object.defineProperty(navigator, 'locks', { value: undefined, configurable: true });
  await expect(ensureSession(true)).rejects.toMatchObject({ status: 503 }); expect(global.fetch).not.toHaveBeenCalled();
});
test('logout does not report success or erase the usable session on authority outage', async () => {
  await ensureSession(); (global.fetch as jest.Mock).mockResolvedValue({ ok: false, status: 503 });
  await expect(logout()).rejects.toMatchObject({ status: 503 }); expect(getAccessToken()).toBe('verified-access');
});
test.each([qaPost, qaDelete])('unauthorized mutations are never automatically replayed', async mutate => {
  await ensureSession(); (global.fetch as jest.Mock).mockClear().mockResolvedValue({ ok: false, status: 401 });
  await expect(mutate('/api/quick/service-principals/app')).rejects.toThrow('401'); expect(global.fetch).toHaveBeenCalledTimes(1);
  expect(global.fetch).toHaveBeenCalledWith('/api/quick/service-principals/app', expect.objectContaining({ redirect: 'error', credentials: 'same-origin' }));
});
test('quick-actions never sends user credentials to a caller-supplied external URL', async () => {
  await expect(qaPost('https://attacker.test/api/quick/operation')).rejects.toThrow('Invalid'); expect(global.fetch).not.toHaveBeenCalled();
});
