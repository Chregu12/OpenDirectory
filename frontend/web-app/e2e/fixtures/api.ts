import type { Page, Route } from '@playwright/test';

/**
 * Fixture data + a page.route() based mock backend.
 *
 * The app talks to several downstream services (device-service,
 * integration-service, auth-service, ...) that are proxied through
 * Next.js rewrites (see next.config.js). None of those services are
 * running in this test environment, so every `/api/**` request made by
 * the browser is intercepted here and answered with static fixtures
 * before it ever reaches the Next.js dev server / rewrite proxy.
 */

export const DEVICE_DRIVERS_FIXTURE = [
  {
    id: 'drv-1',
    name: 'Intel I219-LM Gigabit Network Adapter',
    version: '12.19.1.6',
    vendor: 'Intel',
    deviceType: 'network',
    format: 'inf',
    os: ['Windows 11'],
    architecture: 'x64',
    uploadedAt: '2026-06-01T10:00:00Z',
    source: 'catalog',
  },
  {
    id: 'drv-2',
    name: 'NVIDIA RTX A2000 Display Driver',
    version: '552.22',
    vendor: 'NVIDIA',
    deviceType: 'display',
    format: 'exe',
    os: ['Windows 11'],
    architecture: 'x64',
    uploadedAt: '2026-06-10T08:30:00Z',
    source: 'upload',
  },
  {
    id: 'drv-3',
    name: 'Realtek USB Audio Driver',
    version: '6.0.9375.1',
    vendor: 'Realtek',
    deviceType: 'audio',
    format: 'inf',
    os: ['Windows 10', 'Windows 11'],
    architecture: 'x64',
    source: 'catalog',
  },
];

/** All modules enabled so the sidebar / gated views render fully. */
export const MODULES_FIXTURE = {
  'monitoring-analytics': { enabled: true },
  'secrets-management': { enabled: true },
  'device-management': { enabled: true },
  'network-infrastructure': { enabled: true },
  'security-suite': { enabled: true },
};

interface MockApiOptions {
  /** Response body for GET /api/devices/drivers. Defaults to DEVICE_DRIVERS_FIXTURE. */
  drivers?: unknown[];
}

/**
 * Installs a catch-all route handler for `**\/api/**` that serves fixtures
 * for the endpoints the drivers UI (and the shell it lives in) depends on,
 * and falls back to an empty JSON object for anything else so no request
 * ever escapes to a real (absent) backend.
 */
export async function mockApi(page: Page, options: MockApiOptions = {}) {
  const drivers = options.drivers ?? DEVICE_DRIVERS_FIXTURE;

  await page.route('**/api/**', async (route: Route) => {
    const url = new URL(route.request().url());
    const p = url.pathname;
    const method = route.request().method();

    // ── Device drivers tab ──────────────────────────────────────────────
    if (p === '/api/devices/drivers' && method === 'GET') {
      return route.fulfill({ json: { drivers } });
    }
    if (p === '/api/devices/drivers/upload' && method === 'POST') {
      return route.fulfill({ json: { id: 'drv-new', name: 'uploaded.inf' } });
    }
    if (p.startsWith('/api/devices/drivers/') && method === 'DELETE') {
      return route.fulfill({ json: { ok: true } });
    }
    if (/\/api\/devices\/[^/]+\/driver-recommendations$/.test(p) && method === 'GET') {
      return route.fulfill({ json: { recommendations: [] } });
    }

    // ── Devices list (DevicesView loads this on every mount) ───────────
    if (p === '/api/devices' && method === 'GET') {
      return route.fulfill({ json: { data: [] } });
    }

    // ── App shell (UnifiLayout, ViewPage) background calls ─────────────
    if (p === '/api/config/modules' && method === 'GET') {
      return route.fulfill({ json: MODULES_FIXTURE });
    }
    if (p === '/api/permissions/escalation-alerts') {
      return route.fulfill({ json: [] });
    }
    if (p.startsWith('/api/audit/events')) {
      return route.fulfill({ json: [] });
    }
    if (p === '/api/users' || p === '/api/lldap/users') {
      return route.fulfill({ json: [] });
    }

    // ── Fallback: any other /api/** call gets an empty, well-formed body
    //    instead of hitting the (nonexistent) real backend through the
    //    Next.js rewrite proxy.
    return route.fulfill({ json: {} });
  });
}

/**
 * Seeds localStorage with a fake authenticated session *before* any page
 * script runs, so the `/[view]` route's auth guard (see
 * src/app/[view]/page.tsx) doesn't redirect to /login. This mirrors what
 * `handleCallback()` in src/lib/auth.ts would normally store after a real
 * OIDC login.
 */
export async function seedAuth(page: Page) {
  await page.addInitScript(() => {
    window.localStorage.setItem(
      'auth_user',
      JSON.stringify({ name: 'E2E Test User', role: 'admin' })
    );
    window.localStorage.setItem('access_token', 'e2e-fake-access-token');
    // Skip the first-run onboarding wizard overlay.
    window.localStorage.setItem('od_onboarded', 'true');
  });
}
