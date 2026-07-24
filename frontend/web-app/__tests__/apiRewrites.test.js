'use strict';

/**
 * Routing-contract tests for the Next.js rewrite layer.
 *
 * The rewrites in next.config.js ARE the API gateway for the browser and
 * for the join scripts (they call ${API_BASE}/api/...). A missing or
 * mis-ordered rule silently routes requests into the api-backend catch-all,
 * which answers 404 — exactly the class of bug found during review.
 *
 * These tests load the real next.config.js, resolve the rewrite rules and
 * assert, for every API path the frontend and the scripts actually use,
 * which service the FIRST matching rule targets.
 */

const nextConfig = require('../next.config.js');

// ─── Minimal Next.js source-pattern matcher ───────────────────────────────────
// Supports the syntax used in our config: literal segments, ':name' (one
// segment) and ':name*' (one or more segments — sufficient here, since every
// zero-segment case has its own explicit literal rule).

function sourceToRegex(source) {
  const pattern = source
    .split('/')
    .map(seg => {
      if (/^:[A-Za-z0-9_]+\*$/.test(seg)) return '(?<star>.+)';
      if (/^:[A-Za-z0-9_]+$/.test(seg)) return '[^/]+';
      return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('/');
  return new RegExp(`^${pattern}$`);
}

function resolve(rules, urlPath) {
  for (let i = 0; i < rules.length; i++) {
    if (sourceToRegex(rules[i].source).test(urlPath)) {
      return { index: i, ...rules[i] };
    }
  }
  return null;
}

// Replace only path params (":name" after a slash) — never the port.
function stripParams(destination, replacement) {
  return destination.replace(/\/:[A-Za-z0-9_]+\*?/g, '/' + replacement);
}

function serviceOf(destination) {
  return new URL(stripParams(destination, 'x')).host;
}

// Destination path prefix with :params stripped, for prefix assertions.
function destPathPrefix(destination) {
  return new URL(stripParams(destination, 'PARAM')).pathname.split('PARAM')[0];
}

let rules;

beforeAll(async () => {
  rules = await nextConfig.rewrites();
});

// ─── Helper assertions ────────────────────────────────────────────────────────

function expectRoute(urlPath, expectedHost, expectedPathPrefix) {
  const hit = resolve(rules, urlPath);
  expect(hit).not.toBeNull();
  expect(serviceOf(hit.destination)).toBe(expectedHost);
  if (expectedPathPrefix) {
    expect(destPathPrefix(hit.destination).startsWith(expectedPathPrefix)).toBe(true);
  }
  return hit;
}

// ─── Device-service routes (driver management & hardware detection) ──────────

describe('device-service routing', () => {
  test.each([
    ['/api/devices/drivers',                        '/api/drivers'],
    ['/api/devices/drivers/upload',                 '/api/drivers'],
    ['/api/devices/drivers/import-url',             '/api/drivers'],
    ['/api/devices/drivers/abc123/deploy',          '/api/drivers'],
    ['/api/devices/report-hardware',                '/api/devices/report-hardware'],
    ['/api/devices/report-hardware/pc-01',          '/api/devices/report-hardware'],
    ['/api/devices/PC-01/driver-recommendations',   '/api/devices'],
    ['/api/devices/PC-01/detect-drivers',           '/api/devices'],
  ])('%s → device-service %s', (urlPath, pathPrefix) => {
    expectRoute(urlPath, 'device-service:3003', pathPrefix);
  });

  test('generic device CRUD still reaches api-backend (catch-all)', () => {
    expectRoute('/api/devices', 'api-backend:8080');
    expectRoute('/api/devices/device-123', 'api-backend:8080');
    expectRoute('/api/devices/device-123/lock', 'api-backend:8080');
  });
});

// ─── Samba AD DC routes (join scripts + Domain Setup Wizard) ──────────────────

describe('samba-ad-dc routing', () => {
  test('computer join (used by Join-OpenDirectory.ps1/.sh) maps to the un-prefixed backend mount', () => {
    // samba-ad-dc mounts this as /api/computers/join — WITHOUT /samba prefix
    const hit = expectRoute('/api/samba/computers/join', 'samba-ad-dc:3010');
    expect(destPathPrefix(hit.destination)).toBe('/api/computers/');
  });

  test('domain provisioning (Domain Setup Wizard) keeps the /api/samba prefix', () => {
    const hit = expectRoute('/api/samba/domain/provision', 'samba-ad-dc:3010');
    expect(destPathPrefix(hit.destination)).toBe('/api/samba/');
  });
});

// ─── Printer-service routes ───────────────────────────────────────────────────

describe('printer-service routing', () => {
  test.each([
    '/api/printer/drivers',
    '/api/printer/drivers/upload',
    '/api/printer/catalog/search',
    '/api/printer/catalog/vendors',
    '/api/printer/catalog/dell',
    '/api/printer/catalog/import',
    '/api/printer/catalog/import-url',
  ])('%s → printer-service', urlPath => {
    expectRoute(urlPath, 'printer-service:3006', '/api/printer');
  });
});

// ─── Compliance-engine routes ──────────────────────────────────────────────────

describe('compliance-engine routing', () => {
  test.each([
    '/api/compliance/dashboard',
    '/api/compliance/baselines',
    '/api/compliance/baselines/abc123',
    '/api/compliance/waivers',
    '/api/compliance/waivers/w1',
    '/api/compliance/evaluate/device-1',
    '/api/compliance/score/fleet',
    '/api/compliance/trend/device-1',
    '/api/compliance/reports/generate',
    '/api/compliance/frameworks',
  ])('%s → compliance-engine', urlPath => {
    expectRoute(urlPath, 'compliance-engine:3907', '/api/compliance');
  });
});

// ─── DNS routes (path-rewritten to network-infrastructure) ────────────────────

describe('DNS routing', () => {
  test.each([
    ['/api/dns/records',            '/api/network/dns/records'],
    ['/api/dns/records/abc123',     '/api/network/dns/records'],
    ['/api/dns/zones',              '/api/network/dns/zones'],
  ])('%s → network-infrastructure %s (path rewritten, not just host)', (urlPath, expectedPath) => {
    const hit = expectRoute(urlPath, 'network-infrastructure:3007');
    expect(destPathPrefix(hit.destination).startsWith('/api/network/dns/')).toBe(true);
  });
});

// ─── Network infrastructure routes (DHCP/shares/discovery/monitoring) ─────────

describe('network-infrastructure routing', () => {
  test.each([
    '/api/network/dns/zones',
    '/api/network/dns/records',
    '/api/network/dhcp/scopes',
    '/api/network/dhcp/leases',
    '/api/network/dhcp/reservations',
    '/api/network/shares',
    '/api/network/devices',
    '/api/network/discovery/scan',
    '/api/network/discovery/devices',
    '/api/network/discovery/topology',
    '/api/network/monitoring/status',
    '/api/network/monitoring/metrics',
    '/api/network/monitoring/alerts',
    '/api/network/monitoring/bandwidth',
  ])('%s → network-infrastructure (host + path unchanged)', urlPath => {
    // Unlike the /api/dns/* rewrite, /api/network/* is a straight host swap:
    // the path is not rewritten.
    expectRoute(urlPath, 'network-infrastructure:3007', '/api/network/');
  });

  test('the /api/network rule precedes the /api/:path* catch-all', () => {
    const networkRule = rules.findIndex(r => r.source === '/api/network/:path*');
    const catchAllIndex = rules.findIndex(r => r.source === '/api/:path*');
    expect(networkRule).toBeGreaterThan(-1);
    expect(networkRule).toBeLessThan(catchAllIndex);
  });
});

// ─── Audit routes (split between enterprise-directory and audit-service) ──────

describe('audit routing', () => {
  test.each([
    ['/api/audit/log',                          '/api/audit/log'],
    ['/api/audit/objects/ZG49...base64/history', '/api/audit/objects'],
    ['/api/audit/actors/user-1/activity',        '/api/audit/actors'],
  ])('%s → enterprise-directory', (urlPath, pathPrefix) => {
    expectRoute(urlPath, 'enterprise-directory:3000', pathPrefix);
  });

  test.each([
    '/api/audit/events',
    '/api/audit/events/abc-123',
    '/api/audit/events/correlation/corr-1',
    '/api/audit/timeline/device/device-1',
    '/api/audit/stats',
    '/api/audit/categories',
    '/api/audit/search',
    '/api/audit/integrity',
    '/api/audit/reports/pdf',
    '/api/audit/alerts',
    '/api/audit/retention',
    '/api/audit/siem/test',
  ])('%s → audit-service', urlPath => {
    expectRoute(urlPath, 'audit-service:3908', '/api/audit');
  });

  test('enterprise-directory audit rules precede the audit-service catch-all', () => {
    const log = rules.findIndex(r => r.source === '/api/audit/log');
    const objects = rules.findIndex(r => r.source === '/api/audit/objects/:path*');
    const actors = rules.findIndex(r => r.source === '/api/audit/actors/:path*');
    const generic = rules.findIndex(r => r.source === '/api/audit/:path*');
    expect(log).toBeGreaterThan(-1);
    expect(objects).toBeGreaterThan(-1);
    expect(actors).toBeGreaterThan(-1);
    expect(generic).toBeGreaterThan(-1);
    expect(log).toBeLessThan(generic);
    expect(objects).toBeLessThan(generic);
    expect(actors).toBeLessThan(generic);
  });
});

// ─── Rule ordering ────────────────────────────────────────────────────────────

describe('rule ordering', () => {
  test('the /api/:path* catch-all is the LAST /api rule', () => {
    const apiRules = rules.filter(r => r.source.startsWith('/api/'));
    expect(apiRules[apiRules.length - 1].source).toBe('/api/:path*');
  });

  test('every specific rule wins over the catch-all (never shadowed)', () => {
    const catchAllIndex = rules.findIndex(r => r.source === '/api/:path*');
    expect(catchAllIndex).toBeGreaterThan(-1);
    for (const r of rules) {
      if (r.source.startsWith('/api/') && r.source !== '/api/:path*') {
        expect(rules.indexOf(r)).toBeLessThan(catchAllIndex);
      }
    }
  });

  test('the samba computers rule precedes the generic /api/samba rule', () => {
    const computers = rules.findIndex(r => r.source === '/api/samba/computers/:path*');
    const generic = rules.findIndex(r => r.source === '/api/samba/:path*');
    expect(computers).toBeGreaterThan(-1);
    expect(generic).toBeGreaterThan(-1);
    expect(computers).toBeLessThan(generic);
  });
});

// ─── Fallback behaviour ───────────────────────────────────────────────────────

describe('fallback', () => {
  test('unknown API paths land on api-backend', () => {
    expectRoute('/api/definitely-not-a-real-route', 'api-backend:8080');
  });

  test('every rewrite destination is a syntactically valid URL', () => {
    for (const r of rules) {
      expect(() => new URL(r.destination.replace(/:[A-Za-z0-9_]+\*?/g, 'x'))).not.toThrow();
    }
  });
});
