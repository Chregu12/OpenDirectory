'use strict';

/**
 * Proves the third level of src/index.js's EventBusClient resolution IIFE:
 *
 *   try { require('@opendirectory/grpc-event-bus') }
 *   catch { try { require('../../../../packages/grpc-event-bus/src') }
 *     catch { return class NoopEventBusClient { ... } } }
 *
 * The Dockerfile only copies this service's own directory, so packages/ is
 * absent in the container and BOTH requires fail there. Without the
 * NoopEventBusClient fallback, the uncaught throw from that second require
 * would escape the IIFE and kill the service at module load — i.e.
 * `require('./index')` itself would throw. This test simulates exactly
 * that "both requires fail" condition (both @opendirectory/grpc-event-bus
 * — not installed as a real package under that name in this repo anyway —
 * and the in-repo packages/grpc-event-bus/src path, which DOES normally
 * resolve here in dev) and asserts the module still loads and the HTTP
 * server still boots and serves traffic.
 *
 * jest.mock() resolves module specifiers to an absolute path and keys its
 * mock registry on that path, so mocking the *relative* path below (as
 * seen from this test file, 5 levels up) applies equally to src/index.js's
 * own differently-phrased relative require of the same file (4 levels up
 * from src/) — both resolve to the identical
 * <repo>/packages/grpc-event-bus/src/index.js.
 */

jest.mock('@opendirectory/grpc-event-bus', () => {
  throw new Error("Cannot find module '@opendirectory/grpc-event-bus' (simulated)");
}, { virtual: true });

jest.mock('../../../../../packages/grpc-event-bus/src', () => {
  throw new Error('Cannot find module (simulated: no packages/ dir, as in the Dockerfile image)');
});

// Also mock `pg` so this test doesn't depend on / wait on a real Postgres
// connection attempt — irrelevant to what's under test here.
jest.mock('pg', () => {
  const mockPool = {
    query: jest.fn().mockRejectedValue(new Error('No DB in tests')),
    connect: jest.fn().mockRejectedValue(new Error('No DB in tests')),
    end: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
  };
  return { Pool: jest.fn().mockImplementation(() => mockPool) };
});

const request = require('supertest');
let mod;

beforeAll(async () => {
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
  mod = require('../index');
  await new Promise((resolve) => setTimeout(resolve, 50));
});

afterAll(() => {
  jest.restoreAllMocks();
});

it('require("../index") does not throw when both grpc-event-bus requires fail', () => {
  expect(mod).toBeDefined();
  expect(mod.app).toBeDefined();
  expect(typeof mod.start).toBe('function');
});

it('GET /health is still reachable — the service boots on the NoopEventBusClient fallback', async () => {
  const res = await request(mod.app).get('/health');
  // 200 or 503 — see the comment on the equivalent assertion in
  // api.e2e.test.js; unreachable dependent-service health checks
  // legitimately produce 503 in a test environment. What this test is
  // actually proving is that the request completes and returns the
  // expected shape at all, i.e. the app didn't fail to boot.
  expect([200, 503]).toContain(res.status);
  expect(res.body.service).toBe('monitoring-service');
});
