'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const LIMIT = 65536;
const PUBLIC_FIELDS = new Set(['kty', 'n', 'e', 'kid', 'alg', 'use', 'key_ops']);

function readKeyFile(filename, privateMaterial) {
  let descriptor;
  try {
    if (typeof filename !== 'string' || !path.isAbsolute(filename)) throw new Error('Absolute file path required');
    descriptor = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0));
    const info = fs.fstatSync(descriptor);
    if (!info.isFile() || info.size < 1 || info.size > LIMIT) throw new Error('Invalid key file');
    if (typeof process.getuid !== 'function') throw new Error('POSIX key permissions are required');
    if (info.uid !== process.getuid() && info.uid !== 0) throw new Error('Untrusted key file owner');
    if (privateMaterial ? (info.mode & 0o077) !== 0 : (info.mode & 0o022) !== 0) throw new Error('Unsafe key file permissions');
    const buffer = Buffer.alloc(LIMIT + 1); let length = 0;
    while (length < buffer.length) {
      const read = fs.readSync(descriptor, buffer, length, buffer.length - length, null);
      if (!read) break;
      length += read;
    }
    if (length > LIMIT) throw new Error('Oversized key file');
    return buffer.subarray(0, length).toString('utf8');
  } catch { throw new Error(privateMaterial ? 'Cannot load protected OAuth signing key file' : 'Cannot load trusted OAuth verification key file'); }
  finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}

function publicMaterial(key) {
  if (key.asymmetricKeyType !== 'rsa' || !key.asymmetricKeyDetails || key.asymmetricKeyDetails.modulusLength < 2048
    || key.asymmetricKeyDetails.modulusLength > 8192 || key.asymmetricKeyDetails.publicExponent !== 65537n) throw new Error('OAuth keys must be RSA 2048-8192 with exponent 65537');
  return key.export({ format: 'jwk' });
}

function thumbprint(jwk) {
  return crypto.createHash('sha256').update(JSON.stringify({ e: jwk.e, kty: 'RSA', n: jwk.n })).digest('base64url');
}

class SigningKeys {
  #keys = new Map();

  constructor({ privateKeyFile = process.env.OAUTH_SIGNING_KEY_FILE || undefined,
    verificationJwksFile = process.env.OAUTH_VERIFICATION_JWKS_FILE || undefined,
    ephemeral = process.env.OAUTH_EPHEMERAL_SIGNING_KEYS === 'true', production = process.env.NODE_ENV === 'production' } = {}) {
    if (production && ephemeral) throw new Error('Ephemeral OAuth signing keys are forbidden in production');
    let privateKey;
    if (privateKeyFile) {
      try {
        const pem = readKeyFile(privateKeyFile, true).trim();
        if (!/^-----BEGIN (RSA PRIVATE KEY|PRIVATE KEY)-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END \1-----$/.test(pem)) throw new Error('A single unencrypted PEM private key is required');
        privateKey = crypto.createPrivateKey(pem);
      }
      catch { throw new Error('Cannot load protected OAuth signing key file'); }
    } else {
      if (!ephemeral) throw new Error('A protected OAuth signing key file is required');
      privateKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
    }
    const publicKey = crypto.createPublicKey(privateKey);
    const active = publicMaterial(publicKey);
    this.kid = thumbprint(active);
    Object.defineProperty(this, 'privateKey', { value: privateKey });
    this.#add({ ...active, kid: this.kid }, publicKey);
    if (verificationJwksFile) {
      let document;
      try { document = JSON.parse(readKeyFile(verificationJwksFile, false)); }
      catch { throw new Error('Cannot load trusted OAuth verification key file'); }
      if (!document || Object.keys(document).some(field => field !== 'keys') || !Array.isArray(document.keys) || document.keys.length > 8) throw new Error('Invalid OAuth verification JWKS');
      for (const candidate of document.keys) this.#add(candidate);
    }
    if (this.#keys.size > 8) throw new Error('OAuth verification key limit exceeded');
  }

  #add(candidate, knownKey) {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate) || Object.keys(candidate).some(field => !PUBLIC_FIELDS.has(field))
      || candidate.kty !== 'RSA' || typeof candidate.n !== 'string' || typeof candidate.e !== 'string'
      || !/^[A-Za-z0-9_-]+$/.test(candidate.n) || !/^[A-Za-z0-9_-]+$/.test(candidate.e)
      || (candidate.alg !== undefined && candidate.alg !== 'RS256') || (candidate.use !== undefined && candidate.use !== 'sig')
      || (candidate.key_ops !== undefined && (!Array.isArray(candidate.key_ops) || candidate.key_ops.length !== 1 || candidate.key_ops[0] !== 'verify'))) throw new Error('Only public RS256 verification keys are accepted');
    let key; let material;
    try { key = knownKey || crypto.createPublicKey({ key: candidate, format: 'jwk' }); material = publicMaterial(key); }
    catch { throw new Error('Invalid RSA verification key'); }
    if (material.n !== candidate.n || material.e !== candidate.e) throw new Error('Noncanonical RSA verification key');
    const kid = candidate.kid === undefined ? thumbprint(material) : candidate.kid;
    if (typeof kid !== 'string' || !/^[A-Za-z0-9._~-]{1,128}$/.test(kid)) throw new Error('Invalid OAuth verification key ID');
    const previous = this.#keys.get(kid);
    if (previous && thumbprint(previous.jwk) !== thumbprint(material)) throw new Error('Ambiguous OAuth verification key ID');
    this.#keys.set(kid, { key, jwk: { kty: 'RSA', n: material.n, e: material.e, alg: 'RS256', use: 'sig', kid } });
  }

  jwks() { return { keys: [...this.#keys.values()].map(record => ({ ...record.jwk })) }; }

  verify(token, options = {}) {
    const decoded = jwt.decode(token, { complete: true });
    const header = decoded?.header;
    if (!header || Object.keys(header).some(field => !['alg', 'kid', 'typ'].includes(field)) || header.alg !== 'RS256'
      || (header.typ !== undefined && header.typ !== 'JWT') || typeof header.kid !== 'string' || !this.#keys.has(header.kid)) throw new jwt.JsonWebTokenError('Untrusted OAuth signing key');
    return jwt.verify(token, this.#keys.get(header.kid).key, { ...options, algorithms: ['RS256'] });
  }
}

module.exports = { SigningKeys, thumbprint, readKeyFile };
