'use strict';

// Small HTTP(S) download/fetch helpers shared by driver-catalog import flows.
// Kept dependency-free (core http/https only) so it can be reused by the
// application layer (driver/URL import) as well as by catalog search code
// that only needs to GET some text (OpenPrinting API).

const fs = require('fs');
const https = require('https');
const http = require('http');

/**
 * Download a URL to a local file, following redirects. On any failure the
 * (possibly partially written) destination file is removed so a failed
 * download never leaves a half-written file on disk.
 * @param {string} url
 * @param {string} destPath
 * @returns {Promise<void>}
 */
async function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    if (!url) return reject(new Error('No download URL provided'));
    const proto = url.startsWith('https') ? https : http;
    const file = fs.createWriteStream(destPath);
    const fail = (err) => { file.close(() => fs.unlink(destPath, () => reject(err))); };
    proto.get(url, { headers: { 'User-Agent': 'OpenDirectory/1.0' } }, (response) => {
      if (response.statusCode === 301 || response.statusCode === 302) {
        response.resume();
        if (!response.headers.location) return fail(new Error('Redirect with no Location header'));
        const nextUrl = new URL(response.headers.location, url).toString();
        file.close(() => fs.unlink(destPath, () => downloadFile(nextUrl, destPath).then(resolve).catch(reject)));
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        return fail(new Error(`HTTP ${response.statusCode} from ${url}`));
      }
      response.on('error', fail);
      file.on('error', fail);
      response.pipe(file);
      file.on('finish', () => file.close(resolve));
    }).on('error', fail);
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

module.exports = { downloadFile, httpsGet };
