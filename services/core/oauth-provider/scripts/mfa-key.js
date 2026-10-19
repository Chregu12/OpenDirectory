'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { MfaCipher } = require('../src/MfaAuthority');

function generate(filename) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename)) throw new Error('Absolute file path required');
  const parent = path.dirname(filename); const directory = fs.statSync(parent);
  if (typeof process.getuid !== 'function' || !directory.isDirectory() || directory.uid !== process.getuid() || (directory.mode & 0o077) !== 0) throw new Error('Private service-owned directory required');
  const descriptor = fs.openSync(filename, 'wx', 0o600);
  try { fs.fchmodSync(descriptor, 0o600); fs.writeFileSync(descriptor, crypto.randomBytes(32).toString('hex') + '\n'); fs.fsyncSync(descriptor); }
  finally { fs.closeSync(descriptor); }
  const parentDescriptor = fs.openSync(parent, fs.constants.O_RDONLY);
  try { fs.fsyncSync(parentDescriptor); } finally { fs.closeSync(parentDescriptor); }
  return new MfaCipher({ keyFile: filename, production: true }).kid;
}

if (require.main === module) {
  try {
    if (process.argv.length !== 3) throw new Error('One absolute destination path required');
    process.stdout.write('MFA encryption key created; key ID: ' + generate(process.argv[2]) + '\n');
  } catch { process.stderr.write('MFA key creation failed. Existing files are never overwritten; check private directory and permissions.\n'); process.exitCode = 1; }
}

module.exports = { generate };
