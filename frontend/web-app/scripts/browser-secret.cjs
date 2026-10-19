'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function generate(kind, filename) {
  if (!['cookie', 'client'].includes(kind) || !path.isAbsolute(filename || '')) throw new Error('Absolute path and cookie|client required');
  const parent = path.dirname(filename); const directory = fs.statSync(parent);
  if (typeof process.getuid !== 'function' || !directory.isDirectory() || directory.uid !== process.getuid() || (directory.mode & 0o077)) throw new Error('An owned private directory (0700) is required');
  const descriptor = fs.openSync(filename, 'wx', 0o600);
  try {
    fs.fchmodSync(descriptor, 0o600);
    fs.writeFileSync(descriptor, kind === 'cookie' ? crypto.randomBytes(32) : crypto.randomBytes(32).toString('base64url'));
    fs.fsyncSync(descriptor);
  } finally { fs.closeSync(descriptor); }
  const parentDescriptor = fs.openSync(parent, fs.constants.O_RDONLY);
  try { fs.fsyncSync(parentDescriptor); } finally { fs.closeSync(parentDescriptor); }
}

if (require.main === module) {
  try {
    if (process.argv.length !== 4) throw new Error('Invalid arguments');
    generate(process.argv[2], process.argv[3]);
    process.stdout.write('Protected secret created; no secret material is printed.\n');
  } catch { process.stderr.write('Secret creation failed. Use cookie|client and a new absolute filename in an owned 0700 directory. Existing files are never overwritten.\n'); process.exitCode = 1; }
}

module.exports = { generate };
