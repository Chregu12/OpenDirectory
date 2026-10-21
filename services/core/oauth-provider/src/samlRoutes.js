'use strict';

const crypto = require('crypto');
const samlify = require('samlify');
const { readKeyFile } = require('./SigningKeys');
const { trustedUrl } = require('./OidcAdapter');
const { acceptsAuthentication } = require('./applicationAuthentication');

const POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
const PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
function xml(value) { return String(value).replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' })[c]); }

class SamlProvider {
  constructor(issuer, { keyFile, certFile, apps }) {
    this.key = readKeyFile(keyFile, true);
    this.cert = readKeyFile(certFile, false);
    const certificate = new crypto.X509Certificate(this.cert);
    const key = crypto.createPrivateKey(this.key);
    if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength < 2048 || !certificate.checkPrivateKey(key)
      || Date.parse(certificate.validFrom) > Date.now() || Date.parse(certificate.validTo) <= Date.now()) throw new Error('Invalid SAML signing certificate');
    this.certificate = certificate;
    this.issuer = trustedUrl(issuer).replace(/\/$/, '');
    this.idp = samlify.IdentityProvider({ entityID: this.issuer, privateKey: this.key, signingCert: this.cert,
      nameIDFormat: [PERSISTENT], singleSignOnService: [{ Binding: POST, Location: this.issuer + '/saml/sso' }] });
    if (!apps || typeof apps !== 'object' || Array.isArray(apps) || Object.keys(apps).length > 100) throw new Error('Invalid SAML applications');
    this.apps = new Map(Object.entries(apps).map(([id, app]) => {
      if (!/^[a-z][a-z0-9-]{0,31}$/.test(id) || typeof app.entityId !== 'string' || !app.entityId || app.entityId.length > 2048
        || typeof app.clientId !== 'string' || !app.clientId) throw new Error('Invalid SAML application');
      const acsUrl = trustedUrl(app.acsUrl);
      const sp = samlify.ServiceProvider({ entityID: app.entityId, wantAssertionsSigned: true, wantMessageSigned: true,
        assertionConsumerService: [{ Binding: POST, Location: acsUrl }] });
      return [id, { ...app, acsUrl, sp }];
    }));
  }

  async response(app, payload) {
    if (Date.parse(this.certificate.validTo) <= Date.now() || typeof payload.sub !== 'string' || !payload.sub
      || !Number.isInteger(payload.auth_time) || payload.auth_time > Date.now() / 1000 + 5) throw new Error('Invalid SAML identity');
    const now = new Date().toISOString(); const expiry = new Date(Date.now() + 300000).toISOString();
    const values = { ID: '_' + crypto.randomUUID(), AssertionID: '_' + crypto.randomUUID(), Destination: app.acsUrl,
      Issuer: this.issuer, IssueInstant: now, StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success', NameIDFormat: PERSISTENT,
      NameID: payload.sub, SubjectRecipient: app.acsUrl, SubjectConfirmationDataNotOnOrAfter: expiry,
      ConditionsNotBefore: now, ConditionsNotOnOrAfter: expiry, Audience: app.entityId, AttributeStatement: '' };
    return this.idp.createLoginResponse(app.sp, null, 'post', {}, template => ({ id: values.ID,
      context: template.replace(/ InResponseTo="\{InResponseTo\}"/g, '').replace(/\{([A-Za-z]+)\}/g, (_, key) => {
        if (key === 'AuthnStatement') return `<saml:AuthnStatement AuthnInstant="${new Date(payload.auth_time * 1000).toISOString()}" SessionIndex="${xml(payload.sid)}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`;
        if (!Object.hasOwn(values, key)) throw new Error('Unknown SAML template field');
        return xml(values[key]);
      }) }));
  }
}

function mountSaml(app, { issuer, adminAuth, protocol, clientRegistry, identityAuthority, applicationAccess }) {
  const filename = process.env.OAUTH_SAML_CONFIG_FILE;
  const provider = filename ? new SamlProvider(issuer, JSON.parse(readKeyFile(filename, true))) : null;
  const available = (_req, res, next) => { res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' }); return provider ? next() : res.status(503).json({ error: 'saml_not_configured' }); };
  app.get('/saml/metadata', available, (_req, res) => res.type('application/xml').send(provider.idp.getMetadata()));
  app.get('/saml/certificate', available, (_req, res) => res.type('text/plain').send(provider.cert));
  // This first supported flow is an authenticated IdP-initiated launch. No untrusted XML is parsed.
  app.get('/saml/sso', available, (_req, res) => res.status(400).json({ error: 'authenticated_idp_launch_required' }));
  app.post('/saml/sso', available, adminAuth, protocol(async (req, res) => {
    if (req.user.actor_type !== 'user') return res.status(403).json({ error: 'user_required' });
    if (Object.keys(req.query).length || Object.keys(req.body).some(key => key !== 'appId')) return res.status(400).json({ error: 'registered_saml_application_required' });
    const target = typeof req.body.appId === 'string' && provider.apps.get(req.body.appId);
    if (!target) return res.status(400).json({ error: 'unknown_saml_application' });
    const client = await clientRegistry.get(target.clientId);
    if (!client?.enabled || !acceptsAuthentication(client, req.user)) return res.status(403).json({ error: 'application_access_denied' });
    const state = await identityAuthority.state(req.user.sub);
    const assignment = await applicationAccess.context(target.clientId, state);
    const result = await provider.response(target, req.user);
    const currentState = await identityAuthority.verifiedState(req.user);
    if (!await clientRegistry.current(client) || !currentState || !await applicationAccess.matches(target.clientId, currentState, assignment)) return res.status(403).json({ error: 'application_access_denied' });
    // Explicit submit works with CSP and avoids an inline auto-submit script.
    res.type('html').send(`<!doctype html><html lang="de"><meta charset="utf-8"><title>SAML Anmeldung</title><body><form method="post" action="${xml(target.acsUrl)}"><input type="hidden" name="SAMLResponse" value="${xml(result.context)}"><button>Bei Anwendung anmelden</button></form></body></html>`);
  }, false));
}

module.exports = { SamlProvider, mountSaml };
