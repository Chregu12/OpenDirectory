'use strict';
const { Router } = require('express');
const { validate } = require('../middleware/validate');
const auditDb = require('../db');
const config = require('../utils/config');
const logger = require('../utils/logger');

// ─── Password History ────────────────────────────────────────────────────────
const HISTORY_COUNT = 5;

async function checkPasswordHistory(userId, newPlaintextPassword) {
  if (!auditDb.isAvailable()) return true;
  try {
    const result = await auditDb.query(
      'SELECT password_hash FROM password_history WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2',
      [userId, HISTORY_COUNT]
    );
    const bcrypt = require('bcrypt');
    for (const row of result.rows) {
      const matches = await bcrypt.compare(newPlaintextPassword, row.password_hash);
      if (matches) return false;
    }
    return true;
  } catch { return true; }
}

async function recordPasswordHash(userId, plaintextPassword) {
  if (!auditDb.isAvailable()) return;
  try {
    const bcrypt = require('bcrypt');
    const hash = await bcrypt.hash(plaintextPassword, 12);
    await auditDb.query(
      'INSERT INTO password_history(user_id, password_hash) VALUES($1,$2)',
      [userId, hash]
    );
    await auditDb.query(
      `DELETE FROM password_history WHERE user_id=$1 AND id NOT IN (
        SELECT id FROM password_history WHERE user_id=$1 ORDER BY created_at DESC LIMIT 10
      )`,
      [userId]
    );
  } catch {}
}

// ─── Nodemailer transport (lazy, config-driven) ───────────────────────────────
let mailer = null;
function getMailer() {
  if (mailer) return mailer;
  if (!process.env.SMTP_HOST) return null;
  try {
    const nodemailer = require('nodemailer');
    mailer = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true',
      auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD } : undefined,
    });
    return mailer;
  } catch { return null; }
}

function createUserRoutes(services) {
  const router = Router();
  const { authManager, userService, sessionManager, auditService, passwordAppService, requireAuth, requireAdmin } = services;
  const auth = requireAuth();
  const admin = requireAdmin(); // returns [requireAuth(), adminCheck] array

  // ─── Profile ──────────────────────────────────────────────────────────────

  // GET /api/auth/profile
  router.get('/api/auth/profile', auth, async (req, res) => {
    try {
      const userId = req.user.id;

      const user = await userService.getUserById(userId);

      res.json({
        id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        roles: user.roles,
        permissions: user.permissions,
        mfaEnabled: user.mfaEnabled,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      });
    } catch (error) {
      logger.error('Get profile error:', error);
      res.status(500).json({ error: 'Failed to get profile' });
    }
  });

  // PUT /api/auth/profile
  router.put('/api/auth/profile', auth, async (req, res) => {
    try {
      const userId = req.user.id;
      const updates = req.body;

      // Remove protected fields
      delete updates.id;
      delete updates.username;
      delete updates.password;
      delete updates.roles;
      delete updates.permissions;

      const user = await userService.updateUser(userId, updates);
      await auditService.logUserEvent('profile_updated', userId, req);

      res.json({
        success: true,
        user
      });
    } catch (error) {
      logger.error('Update profile error:', error);
      res.status(500).json({ error: 'Failed to update profile' });
    }
  });

  // ─── Registration ─────────────────────────────────────────────────────────

  // POST /api/auth/register
  router.post('/api/auth/register', validate('register'), async (req, res) => {
    try {
      const { username, email, password, firstName, lastName } = req.body;

      // Validate input
      const validation = await userService.validateRegistration(req.body);
      if (!validation.valid) {
        return res.status(400).json({
          error: 'Validation failed',
          details: validation.errors
        });
      }

      // Check if user exists
      const existingUser = await userService.getUserByUsername(username);
      if (existingUser) {
        return res.status(409).json({
          error: 'User already exists'
        });
      }

      // Create user
      const user = await userService.createUser({
        username,
        email,
        password,
        firstName,
        lastName,
        provider: 'local'
      });

      // Record initial password in history
      recordPasswordHash(user.id || user.username, password).catch(() => {});

      // Create in LDAP if configured
      if (config.ldap.syncNewUsers) {
        await authManager.createLdapUser(user);
      }

      // Sync to Kerberos KDC. kerberos-kdc now requires auth on every route
      // (P0 fix — it previously accepted unauthenticated principal/password
      // writes); this call runs server-to-server with no end-user JWT in
      // hand, so it presents the shared KDC_INTERNAL_TOKEN instead (see
      // services/core/kerberos-kdc/src/middleware/oidcAuth.js
      // internalServicePaths, scoped to exactly this route).
      const KDC_API = process.env.KDC_API_URL || 'http://kerberos-kdc:3013';
      const kdcHeaders = { 'Content-Type': 'application/json' };
      if (process.env.KDC_INTERNAL_TOKEN) {
        kdcHeaders['x-kdc-internal-token'] = process.env.KDC_INTERNAL_TOKEN;
      }
      fetch(`${KDC_API}/api/kerberos/sync-user`, {
        method: 'POST',
        headers: kdcHeaders,
        body: JSON.stringify({ username: user.username || username, password })
      }).catch(err => console.warn('[kerberos-sync]', err.message));

      // Log registration
      await auditService.logUserEvent('user_registered', user.id, req);

      res.status(201).json({
        success: true,
        message: 'Registration successful',
        userId: user.id
      });
    } catch (error) {
      logger.error('Registration error:', error);
      res.status(500).json({ error: 'Registration failed' });
    }
  });

  // ─── Password change & reset ──────────────────────────────────────────────

  // POST /api/auth/change-password
  router.post('/api/auth/change-password', auth, validate('changePassword'), async (req, res) => {
    try {
      const userId = req.user.id;
      const { currentPassword, newPassword } = req.body;

      const user = await userService.getUserById(userId);
      if (!user) {
        // Falls into the catch block below -> 500 "Failed to change password",
        // matching this route's existing behavior for an unresolvable user id
        // (previously an accidental TypeError from `user.password` on null).
        throw new Error('User not found');
      }

      // NOTE: user.password is never populated — UserService._toPublic()
      // intentionally omits the password hash from every user object it
      // returns, to avoid leaking it through profile/read APIs. Comparing
      // against user.password here used to always be `undefined`, so
      // verifyPassword() short-circuited to false and this endpoint returned
      // 401 for every user regardless of the submitted currentPassword.
      // verifyCurrentPassword() fetches the hash internally and never
      // returns it, so the hash stays out of this route entirely.
      const validPassword = await userService.verifyCurrentPassword(userId, currentPassword);

      if (!validPassword) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }

      const historyOk = await checkPasswordHistory(userId, newPassword);
      if (!historyOk) {
        return res.status(400).json({ error: 'Dieses Passwort wurde bereits verwendet. Bitte wählen Sie ein anderes.' });
      }

      await userService.changePassword(userId, newPassword);
      recordPasswordHash(userId, newPassword).catch(() => {});
      await sessionManager.revokeAllUserSessions(userId);
      await auditService.logSecurityEvent('password_changed', userId, req);

      // Sync new password to Kerberos KDC (see the registration-route
      // comment above re: KDC_INTERNAL_TOKEN — same server-to-server auth
      // requirement applies here).
      const KDC_API_CP = process.env.KDC_API_URL || 'http://kerberos-kdc:3013';
      const kdcCpHeaders = { 'Content-Type': 'application/json' };
      if (process.env.KDC_INTERNAL_TOKEN) {
        kdcCpHeaders['x-kdc-internal-token'] = process.env.KDC_INTERNAL_TOKEN;
      }
      fetch(`${KDC_API_CP}/api/kerberos/sync-user`, {
        method: 'POST',
        headers: kdcCpHeaders,
        body: JSON.stringify({ username: user.username, password: newPassword })
      }).catch(err => console.warn('[kerberos-sync]', err.message));

      res.json({
        success: true,
        message: 'Password changed successfully. Please login again.'
      });
    } catch (error) {
      logger.error('Change password error:', error);
      res.status(500).json({ error: 'Failed to change password' });
    }
  });

  // POST /api/auth/reset-password
  router.post('/api/auth/reset-password', async (req, res) => {
    try {
      const { email } = req.body;

      // PasswordApplicationService.requestReset() looks up the user, mints a
      // token (same 32-byte-hex format the route used to mint itself — see
      // index.js's tokenGenerator wiring) and stores it (1h TTL). Returns
      // null silently when the user doesn't exist, matching the previous
      // no-enumeration behavior.
      const result = await passwordAppService.requestReset(email);
      if (result) {
        await auditService.logUserEvent('password_reset_requested', result.userId, req);

        const transport = getMailer();
        if (transport) {
          try {
            const resetUrl = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password?token=${result.token}`;
            await transport.sendMail({
              from: process.env.SMTP_FROM || 'OpenDirectory <noreply@opendirectory.local>',
              to: result.email,
              subject: 'Passwort zurücksetzen — OpenDirectory',
              html: `
                <div style="font-family:sans-serif;max-width:480px;margin:0 auto">
                  <h2 style="color:#1e293b">Passwort zurücksetzen</h2>
                  <p>Hallo ${result.username},</p>
                  <p>Sie haben eine Passwort-Zurücksetzung angefordert. Klicken Sie auf den folgenden Link:</p>
                  <a href="${resetUrl}" style="display:inline-block;margin:16px 0;padding:12px 24px;background:#3b82f6;color:#fff;text-decoration:none;border-radius:8px">Passwort zurücksetzen</a>
                  <p style="color:#64748b;font-size:12px">Dieser Link ist 1 Stunde gültig. Falls Sie keine Zurücksetzung angefordert haben, ignorieren Sie diese E-Mail.</p>
                </div>
              `,
            });
            console.log(`[password-reset] Email sent to ${result.email}`);
          } catch (err) {
            console.error('[password-reset] Email send error:', err.message);
          }
        }
      }

      // Always return success to prevent email enumeration
      res.json({
        success: true,
        message: 'If the email exists, a password reset link has been sent'
      });
    } catch (error) {
      logger.error('Reset password error:', error);
      res.status(500).json({ error: 'Failed to process password reset' });
    }
  });

  // POST /api/auth/password-reset/confirm
  router.post('/api/auth/password-reset/confirm', async (req, res) => {
    try {
      const { token, newPassword } = req.body;
      if (!token || !newPassword) {
        return res.status(400).json({ error: 'token and newPassword required' });
      }

      // Read-only lookup first (does not consume the token) so we can run
      // policy/history validation — and know the target userId for the audit
      // log below — before the token is actually spent by resetWithToken().
      const resetRecord = await passwordAppService.peekToken(token);
      if (!resetRecord || resetRecord.expiry < Date.now()) {
        return res.status(400).json({ error: 'Ungültiger oder abgelaufener Token' });
      }

      // Validate new password against policy
      // eslint-disable-next-line no-underscore-dangle
      const policy = global.__od_passwordPolicy;
      if (policy) {
        const errors = [];
        if (policy.minLength && newPassword.length < policy.minLength) {
          errors.push(`Mindestlänge ${policy.minLength} Zeichen erforderlich`);
        }
        if (policy.requireUppercase && !/[A-Z]/.test(newPassword)) {
          errors.push('Grossbuchstabe erforderlich');
        }
        if (policy.requireNumbers && !/[0-9]/.test(newPassword)) {
          errors.push('Ziffer erforderlich');
        }
        if ((policy.requireSymbols || policy.requireSpecial) && !/[^A-Za-z0-9]/.test(newPassword)) {
          errors.push('Sonderzeichen erforderlich');
        }
        if (errors.length > 0) {
          return res.status(400).json({ error: 'Passwortrichtlinie nicht erfüllt', details: errors });
        }
      }

      const historyOk = await checkPasswordHistory(resetRecord.userId, newPassword);
      if (!historyOk) {
        return res.status(400).json({ error: 'Dieses Passwort wurde bereits verwendet. Bitte wählen Sie ein anderes.' });
      }

      // Delegates the actual password mutation + token consumption to
      // PasswordApplicationService.resetWithToken(), which writes a scrypt
      // hash via the DDD Password value object (domain/value-objects/Password.js).
      //
      // This used to be routed around resetWithToken() and hand-rolled here
      // with userService.changePassword() (bcrypt) instead, because
      // resetWithToken() had a pre-existing bug (`const { Password } =
      // require(...)` against a module that exports the class directly, so
      // `Password` was always undefined) that made every real call throw —
      // AND because the rest of the service (verifyCurrentPassword /
      // authenticateLocal / login) used to be bcrypt-only, so a scrypt hash
      // written here would have made every subsequent change-password /
      // login attempt fail with no way to recover. Both blockers are now
      // fixed: the destructuring bug is gone (resetWithToken() uses a plain
      // `require`), and hash-format detection is centralized in
      // utils/passwordHash and used by every verification path in this
      // service (login, verifyCurrentPassword, verifyPassword/
      // authenticateLocal) — so a scrypt hash written by a reset is now
      // verifiable everywhere a bcrypt hash would have been.
      // resetWithToken() re-validates + deletes the cache token itself, so
      // there's no separate consumeToken() call needed here anymore.
      await passwordAppService.resetWithToken(token, newPassword);
      recordPasswordHash(resetRecord.userId, newPassword).catch(() => {});

      await auditService.logUserEvent('password_reset_completed', resetRecord.userId, req);

      res.json({ success: true, message: 'Passwort erfolgreich zurückgesetzt' });
    } catch (error) {
      logger.error('Confirm password reset error:', error);
      res.status(500).json({ error: 'Failed to reset password' });
    }
  });

  // ─── Admin user management ─────────────────────────────────────────────────

  // GET /api/auth/users
  router.get('/api/auth/users', ...admin, async (req, res) => {
    try {
      const { page = 1, limit = 50, search } = req.query;

      const users = await userService.listUsers({
        page: parseInt(page),
        limit: parseInt(limit),
        search
      });

      res.json(users);
    } catch (error) {
      logger.error('List users error:', error);
      res.status(500).json({ error: 'Failed to list users' });
    }
  });

  // GET /api/auth/users/:userId
  router.get('/api/auth/users/:userId', ...admin, async (req, res) => {
    try {
      const { userId } = req.params;

      const user = await userService.getUserById(userId);

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json(user);
    } catch (error) {
      logger.error('Get user error:', error);
      res.status(500).json({ error: 'Failed to get user' });
    }
  });

  // PUT /api/auth/users/:userId
  router.put('/api/auth/users/:userId', ...admin, async (req, res) => {
    try {
      const { userId } = req.params;
      const updates = req.body;

      const user = await userService.updateUser(userId, updates);
      await auditService.logAdminAction('user_updated', req.user.id, { targetUserId: userId, updates }, req);

      res.json({
        success: true,
        user
      });
    } catch (error) {
      logger.error('Update user error:', error);
      res.status(500).json({ error: 'Failed to update user' });
    }
  });

  // DELETE /api/auth/users/:userId
  router.delete('/api/auth/users/:userId', ...admin, async (req, res) => {
    try {
      const { userId } = req.params;

      await userService.deleteUser(userId);
      await sessionManager.revokeAllUserSessions(userId);
      await auditService.logAdminAction('user_deleted', req.user.id, { targetUserId: userId }, req);

      res.json({
        success: true,
        message: 'User deleted successfully'
      });
    } catch (error) {
      logger.error('Delete user error:', error);
      res.status(500).json({ error: 'Failed to delete user' });
    }
  });

  // POST /api/auth/users/:userId/lock
  router.post('/api/auth/users/:userId/lock', ...admin, async (req, res) => {
    try {
      const { userId } = req.params;
      const { reason, duration } = req.body;

      await userService.lockUser(userId, reason, duration);
      await sessionManager.revokeAllUserSessions(userId);
      await auditService.logAdminAction('user_locked', req.user.id, { targetUserId: userId, reason, duration }, req);

      res.json({
        success: true,
        message: 'User locked successfully'
      });
    } catch (error) {
      logger.error('Lock user error:', error);
      res.status(500).json({ error: 'Failed to lock user' });
    }
  });

  // POST /api/auth/users/:userId/unlock
  router.post('/api/auth/users/:userId/unlock', ...admin, async (req, res) => {
    try {
      const { userId } = req.params;

      await userService.unlockUser(userId);
      await auditService.logAdminAction('user_unlocked', req.user.id, { targetUserId: userId }, req);

      res.json({
        success: true,
        message: 'User unlocked successfully'
      });
    } catch (error) {
      logger.error('Unlock user error:', error);
      res.status(500).json({ error: 'Failed to unlock user' });
    }
  });

  return router;
}

module.exports = { createUserRoutes };
