'use strict';

const crypto = require('crypto');
const { loadOidcAdapters } = require('./OidcAdapter');
const { escapeHtml } = require('./oauthScopes');

function mountFederation(app, { issuer, protocol, validate, authorize }) {
  const adapters = loadOidcAdapters(issuer);
  const pending = new Map();
  const cookieName = 'od_federation';
  const cookieOptions = { httpOnly: true, secure: issuer.startsWith('https:'), sameSite: 'lax', path: '/oauth/federation', maxAge: 300000 };
  function binding(req) {
    const values = (req.headers.cookie || '').split(';').map(value => value.trim()).filter(value => value.startsWith(cookieName + '='));
    return values.length === 1 ? values[0].slice(cookieName.length + 1) : '';
  }
  function take(req, key, stage) {
    const record = typeof key === 'string' && pending.get(key);
    if (!record || record.provider !== req.params.provider || record.stage !== stage || record.binding !== binding(req) || record.expiresAt <= Date.now()) throw new Error('Invalid federation transaction');
    pending.delete(key);
    return record;
  }
  const safe = handler => async (req, res) => {
    res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
    try { await handler(req, res); }
    catch { res.status(400).json({ error: 'federation_login_failed' }); }
  };
  app.get('/oauth/federation/providers', (_req, res) => res.json({ providers: [...adapters.keys()] }));
  app.get('/oauth/federation/:provider', protocol(safe(async (req, res) => {
    const adapter = adapters.get(req.params.provider);
    if (!adapter) return res.status(404).json({ error: 'unknown_oidc_provider' });
    const approvedScope = validate(req, res, req.query);
    if (approvedScope === null) return;
    for (const [key, record] of pending) if (record.expiresAt <= Date.now()) pending.delete(key);
    if (pending.size >= 1000) return res.status(503).json({ error: 'federation_busy' });
    const { url, transaction } = await adapter.begin();
    const browserBinding = crypto.randomBytes(32).toString('base64url');
    const params = Object.fromEntries(['client_id', 'redirect_uri', 'state', 'nonce', 'code_challenge', 'code_challenge_method', 'device_id'].filter(key => typeof req.query[key] === 'string').map(key => [key, req.query[key]]));
    params.scope = approvedScope;
    pending.set(transaction.state, { transaction, params, provider: req.params.provider, binding: browserBinding, expiresAt: Date.now() + 300000, stage: 'callback' });
    res.cookie(cookieName, browserBinding, cookieOptions);
    res.redirect(url);
  })));
  app.get('/oauth/federation/:provider/callback', safe(async (req, res) => {
    const record = take(req, req.query.state, 'callback');
    const user = await adapters.get(req.params.provider).complete(req.query, record.transaction);
    const ticket = crypto.randomBytes(32).toString('base64url');
    pending.set(ticket, { ...record, user, transaction: undefined, expiresAt: Date.now() + 60000, stage: 'complete' });
    res.type('html').send(`<!doctype html><html lang="de"><meta charset="utf-8"><title>OpenDirectory Anmeldung</title><body><h1>Anmeldung abschliessen</h1><form method="post" action="/oauth/federation/${req.params.provider}/complete"><input type="hidden" name="ticket" value="${ticket}"><label>OpenDirectory-Einmalcode (falls eingerichtet)<input name="otpCode" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6"></label><button>Anmelden</button></form></body></html>`);
  }));
  app.post('/oauth/federation/:provider/complete', safe(async (req, res) => {
    const record = take(req, req.body.ticket, 'complete');
    req.body = { ...record.params, otpCode: req.body.otpCode };
    res.clearCookie(cookieName, { ...cookieOptions, maxAge: undefined });
    await protocol(async (request, response) => {
      if (validate(request, response, request.body) === null) return;
      await authorize(request, response, request.oauthClient, record.user, 'federated');
    })(req, res);
  }));
  return params => [...adapters.keys()].map(id => `<p><a href="/oauth/federation/${id}?${escapeHtml(new URLSearchParams(params).toString())}">Mit ${escapeHtml(id)} anmelden</a></p>`).join('');
}

module.exports = { mountFederation };
