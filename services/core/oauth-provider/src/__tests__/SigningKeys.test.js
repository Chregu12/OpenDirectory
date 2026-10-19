'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const jwt = require('jsonwebtoken');
const { SigningKeys } = require('../SigningKeys');
const first = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const second = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
let directory; let privateFile; let publicFile;

beforeEach(() => {
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'od-signing-unit-'));
  privateFile = path.join(directory, 'active.pem'); publicFile = path.join(directory, 'verification.json');
  fs.writeFileSync(privateFile, first.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
});
afterEach(() => fs.rmSync(directory, { recursive: true, force: true }));

function keys(overrides = {}) {
  return new SigningKeys({ privateKeyFile: privateFile, verificationJwksFile: null, ephemeral: false, production: true, ...overrides });
}
function metadata(values) { fs.writeFileSync(publicFile, JSON.stringify({ keys: values }), { mode: 0o644 }); return { verificationJwksFile: publicFile }; }
function sign(material = first.privateKey, kid = keys().kid, overrides = {}) {
  return jwt.sign({ sub: 'operator' }, material, { algorithm: 'RS256', keyid: kid, expiresIn: '1h', ...overrides });
}

test('protected files retain the same identity and signature verification across instances and PEM encodings', async () => {
  const original = keys(); const signed = sign();
  fs.writeFileSync(privateFile, first.privateKey.export({ type: 'pkcs1', format: 'pem' }));
  const reopened = keys();
  expect(reopened.kid).toBe(original.kid); expect(reopened.verify(signed).sub).toBe('operator');
  expect(reopened.kid).toBe(await require('jose').calculateJwkThumbprint(original.jwks().keys[0]));
});

test('production refuses missing keys and ephemeral mode even if a valid key file was provided', () => {
  expect(() => keys({ privateKeyFile: null })).toThrow(/required/);
  expect(() => keys({ ephemeral: true })).toThrow(/forbidden/);
});

test('a known ID never permits a different signature, an HMAC substitution, or a missing key ID', () => {
  const ring = keys();
  expect(() => ring.verify(sign(second.privateKey, ring.kid))).toThrow(/signature/);
  const symmetric = jwt.sign({ sub: 'operator' }, 'untrusted-symmetric-secret', { algorithm: 'HS256', keyid: ring.kid });
  expect(() => ring.verify(symmetric)).toThrow(/Untrusted/);
  expect(() => ring.verify(jwt.sign({ sub: 'operator' }, first.privateKey, { algorithm: 'RS256' }))).toThrow(/Untrusted/);
});

test('nonproduction generation requires an explicit opt-in and never masks an invalid configured file', () => {
  expect(() => keys({ privateKeyFile: null, production: false })).toThrow(/required/);
  expect(new SigningKeys({ privateKeyFile: null, verificationJwksFile: null, ephemeral: true, production: false }).jwks().keys).toHaveLength(1);
  expect(() => keys({ privateKeyFile: path.join(directory, 'missing'), ephemeral: true, production: false })).toThrow(/Cannot load/);
});

test.each([0o644, 0o640, 0o622, 0o666])('rejects private material with unsafe mode %s', mode => {
  fs.chmodSync(privateFile, mode); expect(() => keys()).toThrow(/protected/);
});

test.each(['relative.pem', 'https://issuer.test/key.pem'])('rejects nonabsolute or remote private-key references %s', filename => {
  expect(() => keys({ privateKeyFile: filename })).toThrow(/Cannot load/);
});

test('rejects directories, oversized files, public-only files, bundles and malformed private material', () => {
  expect(() => keys({ privateKeyFile: directory })).toThrow(/Cannot load/);
  for (const invalid of ['bad private material', 'a'.repeat(65537), first.publicKey.export({ type: 'spki', format: 'pem' }),
    first.privateKey.export({ type: 'pkcs8', format: 'pem' }) + second.privateKey.export({ type: 'pkcs8', format: 'pem' })]) {
    fs.writeFileSync(privateFile, invalid); expect(() => keys()).toThrow(/Cannot load/);
  }
});

test.each([['ec', { namedCurve: 'prime256v1' }], ['rsa', { modulusLength: 1024 }]])('rejects unsupported or weak %s signing material', (type, options) => {
  fs.writeFileSync(privateFile, crypto.generateKeyPairSync(type, options).privateKey.export({ type: 'pkcs8', format: 'pem' }));
  expect(() => keys()).toThrow(/RSA/);
});

test('publishes only public parameters, deduplicates equal keys, and does not expose the private object through serialization', () => {
  const ring = keys(metadata([keys().jwks().keys[0]]));
  expect(ring.jwks().keys).toHaveLength(1);
  expect(Object.keys(ring.jwks().keys[0]).sort()).toEqual(['kty', 'n', 'e', 'alg', 'use', 'kid'].sort());
  expect(JSON.stringify(ring)).not.toContain('PRIVATE KEY'); expect(Object.keys(ring)).not.toContain('privateKey');
  const projection = ring.jwks(); projection.keys[0].n = 'changed';
  expect(ring.verify(sign()).sub).toBe('operator'); expect(ring.jwks().keys[0].n).not.toBe('changed');
});

test('supports explicit public-only overlap and legacy public key-ID aliases without signing with them', () => {
  const retired = { ...second.publicKey.export({ format: 'jwk' }), kid: 'previous-key', alg: 'RS256', use: 'sig' };
  const ring = keys(metadata([retired]));
  expect(ring.verify(sign(second.privateKey, 'previous-key')).sub).toBe('operator');
  expect(ring.kid).not.toBe('previous-key');
  expect(() => keys().verify(sign(second.privateKey, 'previous-key'))).toThrow(/Untrusted/);
});

test.each([{ d: 'secret' }, { p: 'secret' }, { alg: 'HS256' }, { use: 'enc' }, { key_ops: ['sign'] }, { jku: 'https://untrusted.test/jwks' }])('rejects private parameters and unapproved verification metadata %j', override => {
  const candidate = { ...second.publicKey.export({ format: 'jwk' }), kid: 'retired', ...override };
  expect(() => keys(metadata([candidate]))).toThrow(/public/);
});

test('ambiguous IDs, untrusted metadata permissions and oversized key inventories fail closed', () => {
  expect(() => keys(metadata([{ ...second.publicKey.export({ format: 'jwk' }), kid: keys().kid }]))).toThrow(/Ambiguous/);
  metadata([]); fs.chmodSync(publicFile, 0o666); expect(() => keys({ verificationJwksFile: publicFile })).toThrow(/trusted/);
  fs.chmodSync(publicFile, 0o644); metadata(Array.from({ length: 9 }, (_unused, index) => ({ ...second.publicKey.export({ format: 'jwk' }), kid: 'key-' + index })));
  expect(() => keys({ verificationJwksFile: publicFile })).toThrow(/JWKS/);
});

test.each([{ kid: 'unknown' }, { jku: 'https://untrusted.test/jwks' }, { jwk: first.publicKey.export({ format: 'jwk' }) }, { crit: ['untrusted'] }])('never follows token-provided trust metadata %j', header => {
  const signed = jwt.sign({ sub: 'operator' }, first.privateKey, { algorithm: 'RS256', keyid: keys().kid, header });
  expect(() => keys().verify(signed)).toThrow(/Untrusted/);
});

test('CLI creates a private nonoverwriting key and writes only public JWKS to stdout', () => {
  const filename = path.join(directory, 'generated.pem');
  const cli = path.join(__dirname, '../../scripts/signing-keys.js');
  const generated = spawnSync(process.execPath, [cli, 'generate', filename], { encoding: 'utf8', timeout: 15000 });
  expect(generated.status).toBe(0); expect(generated.stdout).not.toContain('PRIVATE'); expect(JSON.parse(generated.stdout).keys).toHaveLength(1);
  expect(fs.statSync(filename).mode & 0o777).toBe(0o600);
  const original = crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
  expect(spawnSync(process.execPath, [cli, 'generate', filename], { encoding: 'utf8', timeout: 5000 }).status).toBe(1);
  expect(crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex')).toBe(original);
  const exported = spawnSync(process.execPath, [cli, 'export-public', filename], { encoding: 'utf8', timeout: 5000 });
  expect(exported.status).toBe(0); expect(exported.stdout).toBe(generated.stdout);
});

test('the real issuer refuses production module initialization with missing protected key material', () => {
  const result = spawnSync(process.execPath, ['-e', "require('./src');process.stdout.write('ACCEPTED')"], {
    cwd: path.join(__dirname, '../..'), encoding: 'utf8', timeout: 5000,
    env: { ...process.env, NODE_ENV: 'production', OAUTH_REVOCATION_DEMO_MODE: 'false', OAUTH_EPHEMERAL_SIGNING_KEYS: 'false',
      OAUTH_SIGNING_KEY_FILE: path.join(directory, 'missing.pem'), OAUTH_VERIFICATION_JWKS_FILE: '' },
  });
  expect(result.status).toBe(1); expect(result.stdout).not.toContain('ACCEPTED');
  expect(result.stderr).toContain('Cannot load protected OAuth signing key file');
  expect(fs.readdirSync(directory).sort()).toEqual(['active.pem']);
});
