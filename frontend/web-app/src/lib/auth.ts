export interface BrowserSession {
  access_token: string;
  expires_at: number;
  user: { id: string; name: string; username: string; email: string | null; roles: string[]; role: string };
}

export class SessionError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

let current: BrowserSession | null = null;
let pending: Promise<BrowserSession> | null = null;

function forgetLegacyCredentials() {
  for (const name of ['access_token', 'refresh_token', 'auth_user']) localStorage.removeItem(name);
  sessionStorage.removeItem('pkce_verifier');
}

function csrf() {
  const name = window.location.protocol === 'https:' ? '__Host-od_csrf' : 'od_csrf';
  const matches = document.cookie.split(';').map(part => part.trim()).filter(part => part.startsWith(name + '='));
  return matches.length === 1 ? matches[0].slice(name.length + 1) : '';
}

async function locked<Result>(action: () => Promise<Result>): Promise<Result> {
  if (!navigator.locks) throw new SessionError(503, 'Dieser Browser unterstützt keine sichere Sitzungskoordination (Web Locks).');
  return navigator.locks.request('opendirectory-browser-session', { signal: AbortSignal.timeout(20000) }, action);
}

async function request(action: 'session' | 'logout') {
  forgetLegacyCredentials();
  const token = getAccessToken();
  const response = await fetch(`/api/auth/oidc/${action}`, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { 'X-OD-CSRF': csrf(), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  });
  if (!response.ok) throw new SessionError(response.status, response.status === 401 ? 'Bitte erneut anmelden.' : 'Sitzungsprüfung derzeit nicht verfügbar.');
  return response.json();
}

export async function ensureSession(force = false): Promise<BrowserSession> {
  if (!force && current && getAccessToken()) return current;
  if (pending) return pending;
  pending = locked(async () => {
    const session = await request('session');
    if (typeof session.access_token !== 'string' || !session.access_token || !Number.isFinite(session.expires_at)
      || session.expires_at <= Date.now() || typeof session.user?.id !== 'string' || typeof session.user?.name !== 'string'
      || typeof session.user?.role !== 'string' || !Array.isArray(session.user?.roles)) throw new SessionError(503, 'Ungültige Sitzungsantwort.');
    current = session;
    return session;
  }).catch(error => {
    current = null;
    const failure = error instanceof SessionError ? error : new SessionError(503, 'Sitzungsprüfung derzeit nicht verfügbar.');
    window.dispatchEvent(new CustomEvent('od:session-error', { detail: failure }));
    throw failure;
  }).finally(() => { pending = null; });
  return pending;
}

export function getAccessToken(): string | null {
  return current && current.expires_at > Date.now() + 15000 ? current.access_token : null;
}

export function startLogin() {
  current = null;
  forgetLegacyCredentials();
  window.location.assign('/api/auth/oidc/login');
}

export async function logout() {
  await locked(async () => {
    const result = await request('logout');
    if (result.revoked !== true) throw new SessionError(503, 'Abmeldung wurde nicht bestätigt.');
    current = null;
    forgetLegacyCredentials();
  });
}
