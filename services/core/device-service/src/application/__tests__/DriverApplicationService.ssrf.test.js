'use strict';

// Unit tests for the SSRF-protection helper used by
// DriverApplicationService#importFromUrl (see DriverApplicationService.js
// "SSRF protection" section). isPrivateAddress() is a pure function so it
// can be exercised directly here without spinning up any HTTP server.

const DriverApplicationService = require('../DriverApplicationService');

const { isPrivateAddress } = DriverApplicationService;

describe('isPrivateAddress', () => {
  test('is exported as a function', () => {
    expect(typeof isPrivateAddress).toBe('function');
  });

  describe('IPv4 loopback / private / link-local ranges are blocked', () => {
    test.each([
      ['127.0.0.1', 'loopback'],
      ['127.255.255.255', 'loopback range'],
      ['10.0.0.1', '10.0.0.0/8'],
      ['10.255.255.255', '10.0.0.0/8 upper bound'],
      ['172.16.0.1', '172.16.0.0/12 lower bound'],
      ['172.31.255.255', '172.16.0.0/12 upper bound'],
      ['192.168.0.1', '192.168.0.0/16'],
      ['192.168.255.255', '192.168.0.0/16 upper bound'],
      ['169.254.0.1', '169.254.0.0/16 link-local'],
      ['169.254.169.254', 'cloud metadata endpoint'],
      ['0.0.0.0', 'unspecified'],
    ])('%s (%s) is blocked', (ip) => {
      expect(isPrivateAddress(ip)).toBe(true);
    });
  });

  describe('IPv4 addresses just outside the blocked ranges are allowed', () => {
    test.each([
      ['8.8.8.8', 'public DNS'],
      ['1.1.1.1', 'public DNS'],
      ['172.15.255.255', 'just below 172.16.0.0/12'],
      ['172.32.0.0', 'just above 172.16.0.0/12'],
      ['192.167.255.255', 'just below 192.168.0.0/16'],
      ['192.169.0.0', 'just above 192.168.0.0/16'],
      ['169.253.255.255', 'just below 169.254.0.0/16'],
      ['11.0.0.1', 'just above 10.0.0.0/8'],
    ])('%s (%s) is allowed', (ip) => {
      expect(isPrivateAddress(ip)).toBe(false);
    });
  });

  describe('IPv6', () => {
    test.each([
      ['::1', 'loopback'],
      ['::', 'unspecified'],
      ['fc00::1', 'unique local fc00::/7'],
      ['fd12:3456:789a::1', 'unique local fd00::/8'],
      ['fe80::1', 'link-local fe80::/10'],
      ['febf:ffff::1', 'link-local upper bound'],
      ['::ffff:127.0.0.1', 'IPv4-mapped loopback'],
      ['::ffff:10.0.0.5', 'IPv4-mapped private'],
    ])('%s (%s) is blocked', (ip) => {
      expect(isPrivateAddress(ip)).toBe(true);
    });

    test.each([
      ['2001:4860:4860::8888', 'public (Google DNS)'],
      ['2606:4700:4700::1111', 'public (Cloudflare DNS)'],
    ])('%s (%s) is allowed', (ip) => {
      expect(isPrivateAddress(ip)).toBe(false);
    });
  });

  describe('invalid / missing input fails closed (blocked)', () => {
    test.each([
      [undefined],
      [null],
      [''],
      ['not-an-ip'],
      ['999.999.999.999'],
    ])('%p is blocked', (ip) => {
      expect(isPrivateAddress(ip)).toBe(true);
    });
  });
});
