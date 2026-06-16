'use strict';

/**
 * OIDC Interaction Router
 *
 * Handles the human-facing part of the authorization code flow:
 *   GET  /interaction/:uid        — render the login form
 *   POST /interaction/:uid/login  — submit credentials, finish interaction
 *   POST /interaction/:uid/abort  — cancel the interaction
 */

const express = require('express');

/**
 * Build the interactions router.
 * The OIDC provider instance must be passed in so that
 * interactionDetails / interactionFinished / interactionResult
 * can be called with access to provider internals.
 *
 * @param {import('node-oidc-provider').Provider} provider
 * @param {object} deps - Service dependencies
 * @param {object} deps.authManager   - AuthenticationManager instance
 * @param {object} deps.userService   - UserService instance
 * @param {object} deps.auditService  - AuditService instance
 * @returns {express.Router}
 */
function buildInteractionsRouter(provider, { authManager, userService, auditService }) {
  const router = express.Router();

  // ── Helper: inline HTML login form ──────────────────────────────────────────
  function renderLoginPage({ uid, error, params }) {
    const clientId = params?.client_id || '';
    const errorHtml = error
      ? `<p class="error">${escapeHtml(error)}</p>`
      : '';

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In — OpenDirectory</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f3f4f6;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: #fff;
      border-radius: 8px;
      box-shadow: 0 2px 12px rgba(0,0,0,.12);
      padding: 2.5rem 2rem;
      width: 100%;
      max-width: 380px;
    }
    h1 { font-size: 1.4rem; font-weight: 600; margin-bottom: .25rem; }
    .subtitle { color: #6b7280; font-size: .875rem; margin-bottom: 1.5rem; }
    label { display: block; font-size: .875rem; font-weight: 500; margin-bottom: .25rem; }
    input {
      width: 100%; border: 1px solid #d1d5db; border-radius: 6px;
      padding: .5rem .75rem; font-size: .875rem; margin-bottom: 1rem; outline: none;
    }
    input:focus { border-color: #4f46e5; box-shadow: 0 0 0 2px rgba(79,70,229,.2); }
    button {
      width: 100%; background: #4f46e5; color: #fff; border: none;
      border-radius: 6px; padding: .6rem; font-size: .875rem;
      font-weight: 600; cursor: pointer;
    }
    button:hover { background: #4338ca; }
    .error { color: #dc2626; font-size: .875rem; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Sign in</h1>
    <p class="subtitle">OpenDirectory${clientId ? ' &mdash; ' + escapeHtml(clientId) : ''}</p>
    ${errorHtml}
    <form method="POST" action="/interaction/${escapeHtml(uid)}/login">
      <label for="username">Username</label>
      <input id="username" name="username" type="text" autocomplete="username" required autofocus>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>`;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // ── GET /interaction/:uid — show login form ──────────────────────────────────
  router.get('/interaction/:uid', async (req, res, next) => {
    try {
      const interactionDetails = await provider.interactionDetails(req, res);
      const { uid, prompt, params } = interactionDetails;

      if (prompt.name !== 'login') {
        // For consent / other prompts just auto-grant for now
        const result = { consent: { rejectedScopes: [], rejectedClaims: [] } };
        return provider.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
      }

      res.set('Content-Type', 'text/html');
      return res.send(renderLoginPage({ uid, params }));
    } catch (err) {
      return next(err);
    }
  });

  // ── POST /interaction/:uid/login — process credentials ──────────────────────
  router.post('/interaction/:uid/login', express.urlencoded({ extended: false }), async (req, res, next) => {
    try {
      const { uid } = req.params;
      const { username, password } = req.body;

      // Re-fetch interaction so we have params for error rendering
      const interactionDetails = await provider.interactionDetails(req, res);
      const { params } = interactionDetails;

      // Validate input
      if (!username || !password) {
        res.set('Content-Type', 'text/html');
        return res.status(400).send(
          renderLoginPage({ uid, params, error: 'Username and password are required.' })
        );
      }

      // Authenticate via existing AuthenticationManager
      let user = null;
      try {
        user = await authManager.authenticateLocal(username, password);
      } catch (authErr) {
        // Log and fall through to invalid-credentials response
        if (auditService) {
          await auditService.logFailedAuth(username, req, authErr.message).catch(() => {});
        }
      }

      if (!user) {
        if (auditService) {
          await auditService.logFailedAuth(username, req, 'Invalid credentials').catch(() => {});
        }
        res.set('Content-Type', 'text/html');
        return res.status(401).send(
          renderLoginPage({ uid, params, error: 'Invalid username or password.' })
        );
      }

      // Success — log and finish the interaction
      if (auditService) {
        await auditService.logSuccessfulAuth(user.id, req, 'oidc').catch(() => {});
      }

      const result = {
        login: {
          accountId: String(user.id),
        },
      };

      return provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
      return next(err);
    }
  });

  // ── POST /interaction/:uid/abort — cancel the flow ──────────────────────────
  router.post('/interaction/:uid/abort', async (req, res, next) => {
    try {
      const result = {
        error: 'access_denied',
        error_description: 'End-User aborted interaction',
      };
      await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

module.exports = { buildInteractionsRouter };
