const nextConfig = require('../../next.config');
test('canonical policy operations use one non-rewriting receiver rather than a generic backend', async () => {
  const previous = process.env.POLICY_SERVICE_URL; process.env.POLICY_SERVICE_URL = 'http://policy-test:3004';
  try {
    const routes = await nextConfig.rewrites(); const fallback = routes.findIndex(route => route.source === '/api/:path*');
    for (const prefix of ['policies', 'blueprints', 'gpo', 'update-rings']) for (const source of ['/api/' + prefix, '/api/' + prefix + '/:path*']) {
      const index = routes.findIndex(route => route.source === source); expect(index).toBeGreaterThanOrEqual(0); expect(index).toBeLessThan(fallback); expect(routes[index].destination).toBe('http://policy-test:3004' + source);
    }
  } finally { if (previous === undefined) delete process.env.POLICY_SERVICE_URL; else process.env.POLICY_SERVICE_URL = previous; }
});

test('routes identity capabilities and group snapshots to the authoritative identity service', async () => {
  const previous = process.env.IDENTITY_SERVICE_URL;
  process.env.IDENTITY_SERVICE_URL = 'http://identity-test:3001';
  try {
    const routes = await nextConfig.rewrites();
    const fallback = routes.findIndex(route => route.source === '/api/:path*');
    for (const path of ['/api/identity/:path*', '/api/license-groups/:path*', '/api/license-users/:path*']) {
      const index = routes.findIndex(route => route.source === path);
      expect(index).toBeGreaterThanOrEqual(0);
      expect(index).toBeLessThan(fallback);
      expect(routes[index].destination).toBe(`http://identity-test:3001${path}`);
    }
  } finally {
    if (previous === undefined) delete process.env.IDENTITY_SERVICE_URL;
    else process.env.IDENTITY_SERVICE_URL = previous;
  }
});

test('routes license requests to policy-service before the generic API fallback', async () => {
  const previousUrl = process.env.POLICY_SERVICE_URL;
  process.env.POLICY_SERVICE_URL = 'http://policy-test:3004';
  try {
    const routes = await nextConfig.rewrites();
    const licenseRouteIndex = routes.findIndex(route => route.source === '/api/licenses/:path*');
    const fallbackIndex = routes.findIndex(route => route.source === '/api/:path*');
    expect(licenseRouteIndex).toBeGreaterThanOrEqual(0);
    expect(licenseRouteIndex).toBeLessThan(fallbackIndex);
    expect(routes[licenseRouteIndex].destination).toBe('http://policy-test:3004/api/licenses/:path*');
  } finally {
    if (previousUrl === undefined) delete process.env.POLICY_SERVICE_URL;
    else process.env.POLICY_SERVICE_URL = previousUrl;
  }
});

test('legacy license paths reach only the canonical adapter, never the generic backend', async () => {
  const previous = process.env.LICENSE_ADAPTER_URL;
  process.env.LICENSE_ADAPTER_URL = 'http://license-test:3018';
  try {
    const routes = await nextConfig.rewrites();
    const fallback = routes.findIndex(route => route.source === '/api/:path*');
    for (const source of ['/api/license', '/api/license/:path*']) {
      const index = routes.findIndex(route => route.source === source);
      expect(index).toBeGreaterThanOrEqual(0); expect(index).toBeLessThan(fallback);
      expect(routes[index].destination).toBe(`http://license-test:3018${source}`);
    }
  } finally {
    if (previous === undefined) delete process.env.LICENSE_ADAPTER_URL;
    else process.env.LICENSE_ADAPTER_URL = previous;
  }
});

test('gateway control-plane requests reach the verified core gateway before generic backends', async () => {
  const previous = process.env.CORE_GATEWAY_URL;
  process.env.CORE_GATEWAY_URL = 'http://core-control:8080';
  try {
    const routes = await nextConfig.rewrites(); const index = routes.findIndex(route => route.source === '/api/gateway/:path*');
    expect(index).toBeGreaterThanOrEqual(0); expect(index).toBeLessThan(routes.findIndex(route => route.source === '/api/:path*'));
    expect(routes[index].destination).toBe('http://core-control:8080/api/gateway/:path*');
  } finally { if (previous === undefined) delete process.env.CORE_GATEWAY_URL; else process.env.CORE_GATEWAY_URL = previous; }
});
