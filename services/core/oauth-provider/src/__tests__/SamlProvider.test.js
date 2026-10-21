'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const crypto = require('crypto');
const { SignedXml } = require('xml-crypto');
const express = require('express');
const request = require('supertest');
const { SamlProvider, mountSaml } = require('../samlRoutes');
let temp; let settings; let provider;
beforeAll(() => {
  temp = fs.mkdtempSync(path.join(os.tmpdir(), 'od-saml-'));
  const keyFile = path.join(temp, 'key.pem'); const certFile = path.join(temp, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', certFile, '-days', '1', '-subj', '/CN=opendirectory-test'], { stdio: 'ignore' });
  fs.chmodSync(keyFile, 0o600);
  settings = { keyFile, certFile, apps: { example: { entityId: 'https://sp.test/entity', acsUrl: 'https://sp.test/acs', clientId: 'registered-client' } } };
  provider = new SamlProvider('https://idp.test', settings);
});
afterAll(() => fs.rmSync(temp, { recursive: true, force: true }));
const payload = () => ({ sub: 'canonical-user', actor_type: 'user', sid: crypto.randomUUID(), auth_time: Math.floor(Date.now() / 1000) });
test('real X.509 metadata and independently verified response and assertion signatures', async () => {
  const result = await provider.response(provider.apps.get('example'), payload());
  const document = Buffer.from(result.context, 'base64').toString();
  expect(document).toContain('Recipient="https://sp.test/acs"');
  expect(document).toContain('<saml:Audience>https://sp.test/entity</saml:Audience>');
  expect(document).toContain('canonical-user'); expect(document).toContain('<saml:AuthnStatement');
  expect(document).not.toContain('InResponseTo=');
  const signatures = document.match(/<ds:Signature[\s\S]*?<\/ds:Signature>/g);
  expect(signatures).toHaveLength(2);
  for (const signature of signatures) {
    const verifier = new SignedXml({ publicCert: provider.cert, getCertFromKeyInfo: () => null });
    verifier.loadSignature(signature);
    expect(verifier.checkSignature(document)).toBe(true);
    expect(verifier.checkSignature(document.replace('canonical-user', 'attacker'))).toBe(false);
  }
  const certBody = provider.cert.replace(/-----[^-]+-----|\s/g, '');
  expect(provider.idp.getMetadata()).toContain(certBody);
});
test('unsafe ACS, mismatched signing key and missing authentication fail closed', async () => {
  expect(() => new SamlProvider('https://idp.test', { ...settings, apps: { bad: { ...settings.apps.example, acsUrl: 'http://attacker.test/acs' } } })).toThrow();
  const other = path.join(temp, 'other.pem');
  fs.writeFileSync(other, crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  expect(() => new SamlProvider('https://idp.test', { ...settings, keyFile: other })).toThrow();
  await expect(provider.response(provider.apps.get('example'), { ...payload(), auth_time: undefined })).rejects.toThrow();
});
function routes(configured = true, user = payload(), assigned = true) {
  const filename = path.join(temp, 'config.json'); fs.writeFileSync(filename, JSON.stringify(settings), { mode: 0o600 });
  if (configured) process.env.OAUTH_SAML_CONFIG_FILE = filename; else delete process.env.OAUTH_SAML_CONFIG_FILE;
  const app = express(); app.use(express.json());
  const adminAuth = (req, res, next) => { if (!req.headers.authorization) return res.sendStatus(401); req.user = user; next(); };
  const protocol = handler => async (req, res) => { try { await handler(req, res); } catch { res.sendStatus(403); } };
  mountSaml(app, { issuer: 'https://idp.test', adminAuth, protocol,
    clientRegistry: { get: async () => ({ enabled: true }), current: async () => true },
    identityAuthority: { state: async () => ({}), verifiedState: async () => ({}) },
    applicationAccess: { context: async () => { if (!assigned) throw new Error('Not assigned'); }, matches: async () => assigned } });
  delete process.env.OAUTH_SAML_CONFIG_FILE;
  return app;
}
test('no anonymous or application-principal assertions; no arbitrary ACS or XML requests', async () => {
  const app = routes();
  expect((await request(app).post('/saml/sso').send({ appId: 'example' })).status).toBe(401);
  for (const body of [{ appId: 'example', redirect_uri: 'https://attacker.test' }, { appId: 'unknown' }, { appId: 'example', SAMLRequest: 'xml' }]) {
    expect((await request(app).post('/saml/sso').set('Authorization', 'Bearer verified').send(body)).status).toBe(400);
  }
  expect((await request(routes(true, { ...payload(), actor_type: 'application' })).post('/saml/sso').set('Authorization', 'Bearer verified').send({ appId: 'example' })).status).toBe(403);
  expect((await request(routes(true, payload(), false)).post('/saml/sso').set('Authorization', 'Bearer verified').send({ appId: 'example' })).status).toBe(403);
});
test('configured launch reaches only registered ACS; missing configuration is explicitly unavailable', async () => {
  const response = await request(routes()).post('/saml/sso').set('Authorization', 'Bearer verified').send({ appId: 'example' });
  expect(response.status).toBe(200); expect(response.text).toContain('action="https://sp.test/acs"');
  expect(response.text).toContain('name="SAMLResponse"');
  expect((await request(routes(false)).get('/saml/metadata')).status).toBe(503);
});
