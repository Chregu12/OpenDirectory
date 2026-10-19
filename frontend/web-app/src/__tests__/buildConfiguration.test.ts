const configuration = require('../../next.config');

test('the production build keeps TypeScript checking enabled rather than accepting ignored type errors', () => {
  expect(configuration.typescript).not.toHaveProperty('ignoreBuildErrors', true);
  expect(configuration.typescript).toEqual({ tsconfigPath: process.env.NEXT_TSCONFIG_PATH || 'tsconfig.json' });
});

test('the Next 14 configuration does not keep the obsolete experimental app-directory switch', () => {
  expect(configuration).not.toHaveProperty('experimental.appDir');
  expect(configuration.distDir).toBe(process.env.NEXT_DIST_DIR || '.next');
});
