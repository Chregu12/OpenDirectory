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
