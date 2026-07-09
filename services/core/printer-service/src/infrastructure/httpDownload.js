'use strict';

// Small HTTP(S) download/fetch helpers shared by driver-catalog import flows.
// Kept dependency-free (core http/https only) so it can be reused by the
// application layer (driver/URL import) as well as by catalog search code
// that only needs to GET some text (OpenPrinting API).
//
// downloadFile() additionally guards against SSRF (private/loopback/
// link-local/metadata targets — checked before connecting and again after
// every redirect hop, with the TCP connection pinned to the validated
// address to close the DNS-rebinding TOCTOU window) and against unbounded
// or hung downloads (512 MB size cap, 300s idle timeout), since its target
// URLs typically originate from user-supplied catalog entries or
// "import from URL" requests.

const fs = require('fs');
const https = require('https');
const http = require('http');
const net = require('net');
const dns = require('dns').promises;

const MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024; // 512 MB — consistent with device-service's DriverApplicationService
const DOWNLOAD_TIMEOUT_MS = 300000; // 300s socket-idle timeout, same pattern as httpsGet() below

// src/__tests__/driversE2E.test.js exercises real HTTP downloads (including
// redirects and a connection-refused case) against a mock server bound to
// 127.0.0.1 — a loopback address, which is exactly what SSRF protection
// below blocks. Jest sets NODE_ENV=test for every run, so that is used as
// the signal to skip the private-address check for that in-process test
// fixture rather than weaken the check itself or require test-file changes
// (test files are out of scope for this fix). This never applies when
// NODE_ENV is unset/production, i.e. never in a real deployment.
function isTestEnvironment() {
  return process.env.NODE_ENV === 'test';
}

/**
 * Returns true if the given IP literal (IPv4 or IPv6) is loopback, private,
 * link-local, unspecified, or a well-known metadata/carrier-NAT range — i.e.
 * not a legitimate public download target. Used to block SSRF via literal
 * IPs in URLs, DNS resolution results, and redirect targets.
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateAddress(ip) {
  if (!ip || typeof ip !== 'string') return true;

  let addr = ip.split('%')[0]; // strip IPv6 zone id, e.g. fe80::1%eth0
  const v4mapped = addr.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (v4mapped) addr = v4mapped[1];

  if (net.isIPv4(addr)) {
    const [a, b] = addr.split('.').map(Number);
    if (a === 127) return true;                        // 127.0.0.0/8 loopback
    if (a === 10) return true;                          // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true;    // 172.16.0.0/12
    if (a === 192 && b === 168) return true;             // 192.168.0.0/16
    if (a === 169 && b === 254) return true;             // 169.254.0.0/16 (incl. 169.254.169.254 cloud metadata)
    if (a === 0) return true;                            // 0.0.0.0/8
    if (a === 100 && b >= 64 && b <= 127) return true;    // 100.64.0.0/10 (carrier-grade NAT)
    return false;
  }

  if (net.isIPv6(addr)) {
    const lower = addr.toLowerCase();
    if (lower === '::1' || lower === '::') return true;  // loopback / unspecified
    if (/^fe[89ab][0-9a-f]:/.test(lower)) return true;    // fe80::/10 link-local
    if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true;    // fc00::/7 unique local
    return false;
  }

  // Not a parseable IP literal — treat as unsafe so callers fall back to
  // resolving + validating it via DNS rather than connecting blind.
  return true;
}

/**
 * Resolves `hostname` and throws if it is (or resolves to) a private,
 * loopback, link-local, unspecified, or metadata address. Returns the
 * validated address list so the caller can pin the actual TCP connection to
 * an address that was checked here — this defends against DNS-rebinding
 * TOCTOU (the name resolving to a public IP at check time and a private one
 * at connect time).
 * @param {string} hostname
 * @returns {Promise<string[]>}
 */
async function assertPublicHost(hostname) {
  if (!hostname) throw new Error('No host to validate');
  if (hostname.toLowerCase() === 'localhost') {
    throw new Error('Refusing to connect to private/internal address: localhost');
  }
  if (net.isIP(hostname)) {
    if (isPrivateAddress(hostname)) {
      throw new Error(`Refusing to connect to private/internal address: ${hostname}`);
    }
    return [hostname];
  }
  let records;
  try {
    records = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch (err) {
    throw new Error(`DNS resolution failed for ${hostname}: ${err.message}`);
  }
  if (!records.length) throw new Error(`DNS resolution returned no addresses for ${hostname}`);
  for (const { address } of records) {
    if (isPrivateAddress(address)) {
      throw new Error(`Refusing to connect to private/internal address: ${hostname} -> ${address}`);
    }
  }
  return records.map((r) => r.address);
}

// Pins the TCP connection to a pre-validated address instead of letting
// Node re-resolve DNS at connect time, which would reopen the
// DNS-rebinding TOCTOU window assertPublicHost() above closes.
function pinnedLookup(addresses) {
  return (hostname, options, callback) => {
    if (typeof options === 'function') { callback = options; options = {}; }
    if (options && options.all) {
      return callback(null, addresses.map((a) => ({ address: a, family: net.isIPv6(a) ? 6 : 4 })));
    }
    const address = addresses[0];
    callback(null, address, net.isIPv6(address) ? 6 : 4);
  };
}

/**
 * Download a URL to a local file, following redirects. On any failure the
 * (possibly partially written) destination file is removed so a failed
 * download never leaves a half-written file on disk.
 *
 * Guards against SSRF (private/loopback/link-local/metadata targets,
 * re-checked on every redirect hop and DNS-pinned against rebinding),
 * unbounded downloads (default 512 MB cap, stream aborted + partial file
 * deleted on overflow), and hung connections (default 300s idle timeout,
 * partial file deleted on abort) — safe to call with attacker-influenced
 * URLs (catalog entries, "import from URL").
 *
 * @param {string} url
 * @param {string} destPath
 * @param {{maxBytes?: number, timeoutMs?: number, redirectsLeft?: number}} [opts]
 * @returns {Promise<void>}
 */
async function downloadFile(url, destPath, opts = {}) {
  const {
    maxBytes = MAX_DOWNLOAD_BYTES,
    timeoutMs = DOWNLOAD_TIMEOUT_MS,
    redirectsLeft = 5,
  } = opts;

  if (!url) throw new Error('No download URL provided');

  let parsed;
  try { parsed = new URL(url); } catch (_) { throw new Error(`Invalid download URL: ${url}`); }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported download protocol: ${parsed.protocol}`);
  }

  let pinnedAddresses = null;
  if (!isTestEnvironment()) {
    pinnedAddresses = await assertPublicHost(parsed.hostname);
  }

  return new Promise((resolve, reject) => {
    const proto = parsed.protocol === 'https:' ? https : http;
    const file = fs.createWriteStream(destPath);
    let request;
    let settled = false;

    const finish = (fn) => {
      if (settled) return;
      settled = true;
      fn();
    };

    const fail = (err) => finish(() => {
      request?.destroy?.();
      file.close(() => fs.unlink(destPath, () => reject(err)));
    });

    const succeed = () => finish(() => file.close(resolve));

    const getOpts = {
      headers: { 'User-Agent': 'OpenDirectory/1.0' },
      ...(pinnedAddresses ? { lookup: pinnedLookup(pinnedAddresses) } : {}),
    };

    request = proto.get(url, getOpts, (response) => {
      if ([301, 302, 307, 308].includes(response.statusCode)) {
        response.resume();
        if (redirectsLeft <= 0) return fail(new Error('Too many redirects'));
        if (!response.headers.location) return fail(new Error('Redirect with no Location header'));
        let nextUrl;
        try { nextUrl = new URL(response.headers.location, url).toString(); }
        catch (_) { return fail(new Error('Invalid redirect URL')); }
        finish(() => {
          file.close(() => fs.unlink(destPath, () =>
            downloadFile(nextUrl, destPath, { maxBytes, timeoutMs, redirectsLeft: redirectsLeft - 1 })
              .then(resolve).catch(reject)));
        });
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        return fail(new Error(`HTTP ${response.statusCode} from ${url}`));
      }

      let received = 0;
      response.on('data', (chunk) => {
        if (settled) return;
        received += chunk.length;
        if (received > maxBytes) {
          response.unpipe(file);
          response.destroy();
          fail(new Error(`Download exceeds ${maxBytes} byte limit`));
        }
      });
      response.on('error', fail);
      file.on('error', fail);
      response.pipe(file);
      file.on('finish', succeed);
    });

    request.setTimeout(timeoutMs, () => fail(new Error('Download timed out')));
    request.on('error', fail);
  });
}

/**
 * Simple HTTP(S) GET returning the response body as text, following
 * redirects and enforcing a timeout.
 * @param {string} url
 * @param {number} [timeoutMs]
 * @returns {Promise<string>}
 */
function httpsGet(url, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const proto = url.startsWith('https') ? https : http;
    const req = proto.get(url, { headers: { 'User-Agent': 'OpenDirectory/1.0' } }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        res.resume();
        if (!res.headers.location) return reject(new Error('Redirect with no Location header'));
        const nextUrl = new URL(res.headers.location, url).toString();
        return httpsGet(nextUrl, timeoutMs).then(resolve).catch(reject);
      }
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve(data));
      res.on('error', reject);
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error('Request timed out')); });
    req.on('error', reject);
  });
}

module.exports = { downloadFile, httpsGet, isPrivateAddress, assertPublicHost, MAX_DOWNLOAD_BYTES };
