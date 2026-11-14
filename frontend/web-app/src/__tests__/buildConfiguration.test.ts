const configuration = require('../../next.config');

test('the production build keeps TypeScript checking enabled rather than accepting ignored type errors', () => {
  expect(configuration.typescript).not.toHaveProperty('ignoreBuildErrors', true);
  expect(configuration.typescript).toEqual({ tsconfigPath: process.env.NEXT_TSCONFIG_PATH || 'tsconfig.json' });
});

test('the Next 14 configuration does not keep the obsolete experimental app-directory switch', () => {
  expect(configuration).not.toHaveProperty('experimental.appDir');
  expect(configuration.distDir).toBe(process.env.NEXT_DIST_DIR || '.next');
});

test('device fleet export and lifecycle actions reach the canonical device receiver in production', async () => {
  const rewrites = await configuration.rewrites();
  for (const path of ['/api/devices/fleet/:path*', '/api/devices/:id/lifecycle']) {
    const routes = rewrites.filter((route: { source: string }) => route.source === path);
    expect(routes).toHaveLength(1);
    expect(routes[0].destination).toBe(`${process.env.DEVICE_SERVICE_URL || 'http://device-service:3003'}${path}`);
  }
});
