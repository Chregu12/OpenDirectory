'use strict';

/**
 * Unit tests for the ServiceDiscovery path/ID logic — the piece that decides
 * under which gateway path a discovered service is exposed. A wrong mapping
 * here silently routes an entire service into nowhere.
 */

jest.mock('../logger', () => ({
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
}));

const ServiceDiscovery = require('../serviceDiscovery');

describe('sanitizeServiceId', () => {
  const sd = new ServiceDiscovery();

  test.each([
    ['device-service', 'device-service'],
    ['Device Service', 'device-service'],
    ['DEVICE_SERVICE', 'device-service'],
    ['printer--service', 'printer-service'],
    ['-auth-service-', 'auth-service'],
    ['Mobile App Management!', 'mobile-app-management'],
  ])('%s → %s', (input, expected) => {
    expect(sd.sanitizeServiceId(input)).toBe(expected);
  });
});

describe('determineServicePath', () => {
  const sd = new ServiceDiscovery();

  test.each([
    ['device-service', '/api/devices'],
    ['auth-service', '/api/auth'],
    ['authentication-service', '/api/auth'],
    ['network-infrastructure', '/api/network'],
    ['monitoring-service', '/api/monitoring'],
    ['notification-service', '/api/notifications'],
    ['ios-management-service', '/api/mobile/ios'],
    ['mobile-threat-defense', '/api/mobile/mtd'],
  ])('%s → %s', (id, expectedPath) => {
    expect(sd.determineServicePath({ id, name: id })).toBe(expectedPath);
  });

  test('unknown services get an empty path (proxy strips the /api/<id> prefix)', () => {
    expect(sd.determineServicePath({ id: 'brand-new-service', name: 'brand-new-service' })).toBe('');
  });

  test('falls back to the name when the id has no mapping', () => {
    expect(sd.determineServicePath({ id: 'x', name: 'device-service' })).toBe('/api/devices');
  });
});

describe('parseServiceInfo', () => {
  const sd = new ServiceDiscovery();

  test('builds a complete service record from a health response', () => {
    const svc = sd.parseServiceInfo(
      { service: 'Device Service', version: '2.1.0', uptime: 42, capabilities: ['mdm'] },
      3003
    );
    expect(svc.id).toBe('device-service');
    expect(svc.name).toBe('Device Service');
    expect(svc.host).toBe('localhost');
    expect(svc.port).toBe(3003);
    expect(svc.path).toBe('/api/devices');
    expect(svc.version).toBe('2.1.0');
    expect(svc.status).toBe('healthy');
    expect(svc.metadata.capabilities).toEqual(['mdm']);
  });

  test('defaults version and environment when the health payload is minimal', () => {
    const svc = sd.parseServiceInfo({ service: 'printer-service' }, 3006);
    expect(svc.version).toBe('1.0.0');
    expect(svc.metadata.environment).toBe('unknown');
    expect(svc.path).toBe('');
  });
});
