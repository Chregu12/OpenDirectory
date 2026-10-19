'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { SigningKeys } = require('../src/SigningKeys');

function generate(filename) {
  const parent = path.dirname(filename);
  const directory = fs.statSync(parent);
  if (typeof process.getuid !== 'function' || !directory.isDirectory() || directory.uid !== process.getuid() || (directory.mode & 0o077) !== 0) throw new Error('Use an existing private directory owned by the current service user (0700)');
  if (fs.existsSync(filename)) throw new Error('An existing key cannot be overwritten');
  const material = crypto.generateKeyPairSync('rsa', { modulusLength: 3072,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
  const descriptor = fs.openSync(filename, 'wx', 0o600);
  try { fs.fchmodSync(descriptor, 0o600); fs.writeFileSync(descriptor, material.privateKey, 'utf8'); fs.fsyncSync(descriptor); }
  finally { fs.closeSync(descriptor); }
  const parentDescriptor = fs.openSync(parent, fs.constants.O_RDONLY);
  try { fs.fsyncSync(parentDescriptor); } finally { fs.closeSync(parentDescriptor); }
}

function main(args) {
  if (args.length !== 2 || !['generate', 'export-public'].includes(args[0]) || !args[1]) throw new Error('Usage: node scripts/signing-keys.js generate|export-public /absolute/path/to/private-key.pem');
  const filename = path.resolve(args[1]);
  if (args[0] === 'generate') generate(filename);
  const keys = new SigningKeys({ privateKeyFile: filename, verificationJwksFile: null, ephemeral: false, production: true });
  process.stdout.write(JSON.stringify(keys.jwks(), null, 2) + '\n');
}

if (require.main === module) {
  try { main(process.argv.slice(2)); }
  catch { process.stderr.write('Signing key operation failed; no existing key is overwritten. Check arguments, private directory, permissions and key format.\n'); process.exitCode = 1; }
}

module.exports = { generate, main };
