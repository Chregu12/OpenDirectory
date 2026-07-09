'use strict';

// Unit tests for the SSRF guard (isPrivateAddress) and the size-limit /
// cleanup behavior of downloadFile() in ../httpDownload.js.
//
//   npx jest src/infrastructure/__tests__/httpDownload.test.js

const os = require('os');
const fs = require('fs');
const path = require('path');
const http = require('http');

const { isPrivateAddress, downloadFile } = require('../httpDownload');

describe('isPrivateAddress', () => {
  test('flags loopback addresses', () => {
    expect(isPrivateAddress('127.0.0.1')).toBe(true);
    expect(isPrivateAddress('127.255.255.255')).toBe(true);
    expect(isPrivateAddress('::1')).toBe(true);
  });

  test('flags RFC1918 private ranges', () => {
    expect(isPrivateAddress('10.0.0.5')).toBe(true);
    expect(isPrivateAddress('172.16.0.1')).toBe(true);
    expect(isPrivateAddress('172.31.255.255')).toBe(true);
    expect(isPrivateAddress('192.168.1.10')).toBe(true);
  });

  test('flags link-local and cloud metadata addresses', () => {
    expect(isPrivateAddress('169.254.169.254')).toBe(true); // AWS/GCP/Azure metadata endpoint
    expect(isPrivateAddress('169.254.0.1')).toBe(true);
    expect(isPrivateAddress('fe80::1')).toBe(true);
  });

  test('flags unique-local IPv6 and unspecified/zero addresses', () => {
    expect(isPrivateAddress('fc00::1')).toBe(true);
    expect(isPrivateAddress('fd12:3456:789a::1')).toBe(true);
    expect(isPrivateAddress('0.0.0.0')).toBe(true);
    expect(isPrivateAddress('::')).toBe(true);
  });

  test('unwraps IPv4-mapped IPv6 addresses before checking', () => {
    expect(isPrivateAddress('::ffff:127.0.0.1')).toBe(true);
    expect(isPrivateAddress('::ffff:8.8.8.8')).toBe(false);
  });

  test('does not flag public addresses', () => {
    expect(isPrivateAddress('8.8.8.8')).toBe(false);
    expect(isPrivateAddress('1.1.1.1')).toBe(false);
    expect(isPrivateAddress('2001:4860:4860::8888')).toBe(false);
  });

  test('treats unparseable input as unsafe (fail closed)', () => {
    expect(isPrivateAddress('')).toBe(true);
    expect(isPrivateAddress(null)).toBe(true);
    expect(isPrivateAddress('not-an-ip')).toBe(true);
  });
});

describe('downloadFile size limit', () => {
  let server;
  let port;
  let destPath;

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
      // Stream 1 MB of data — well over the tiny maxBytes used below.
      const chunk = Buffer.alloc(64 * 1024, 'x');
      let sent = 0;
      const interval = setInterval(() => {
        if (sent >= 1024 * 1024 || res.writableEnded) { clearInterval(interval); return res.end(); }
        res.write(chunk);
        sent += chunk.length;
      }, 0);
      req.on('close', () => clearInterval(interval));
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = server.address().port;
  });

  afterAll(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  beforeEach(() => {
    destPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'httpdownload-test-')), 'out.bin');
  });

  test('aborts and deletes the partial file once the byte limit is exceeded', async () => {
    await expect(
      downloadFile(`http://127.0.0.1:${port}/big`, destPath, { maxBytes: 32 * 1024 })
    ).rejects.toThrow(/byte limit/);
    expect(fs.existsSync(destPath)).toBe(false);
  });
});
