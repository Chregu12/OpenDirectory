'use strict';
const { Router } = require('express');
const passport = require('passport');
const { validate } = require('../middleware/validate');
const config = require('../utils/config');
const logger = require('../utils/logger');

function createAuthRoutes(services) {
  const router = Router();
  const { authManager, tokenService, mfaService, sessionManager, auditService, zeroTrust, loginAttemptsCounter } = services;

  // POST /api/auth/login
  router.post('/api/auth/login', validate('login'), async (req, res, next) => {
    try {
      const { username, password, mfaCode, deviceId, provider = 'local' } = req.body;

      // Select authentication strategy
      const strategy = provider === 'ldap' ? 'ldap' : 'local';

      passport.authenticate(strategy, async (err, user, info) => {
        if (err) {
          return next(err);
        }

        if (!user) {
          if (loginAttemptsCounter) loginAttemptsCounter.inc({ result: 'failure' });
          await auditService.logFailedAuth(username, req, info?.message);
          return res.status(401).json({
            error: 'Authentication failed',
            message: info?.message || 'Invalid credentials'
          });
        }

        // Check if TOTP MFA is required (in-memory TOTP secrets)
        const totpSecrets = global.__od_userMfaSecrets;
        const hasTotpMfa = totpSecrets && totpSecrets.has(user.id || user.userId);
        if (hasTotpMfa && !mfaCode) {
          return res.status(202).json({ mfaRequired: true, userId: user.id || user.userId });
        }
        if (hasTotpMfa && mfaCode) {
          const speakeasyLib = global.__od_speakeasy;
          if (speakeasyLib) {
            const totpSecret = totpSecrets.get(user.id || user.userId);
            const totpValid = speakeasyLib.totp.verify({ secret: totpSecret, encoding: 'base32', token: mfaCode, window: 2 });
            if (!totpValid) {
              await auditService.logFailedAuth(username, req, 'Invalid TOTP code');
              return res.status(401).json({ error: 'Ungültiger TOTP-Code' });
            }
          }
        }

        // Check if MFA is required (class-based mfaService)
        if (user.mfaEnabled && !mfaCode) {
          return res.status(200).json({
            requiresMFA: true,
            tempToken: await tokenService.generateTempToken(user.id)
          });
        }

        // Verify MFA if provided (class-based mfaService, only if no in-memory TOTP)
        if (user.mfaEnabled && mfaCode && !hasTotpMfa) {
          const mfaValid = await mfaService.verifyCode(user.id, mfaCode);
          if (!mfaValid) {
            await auditService.logFailedAuth(username, req, 'Invalid MFA code');
            return res.status(401).json({
              error: 'Invalid MFA code'
            });
          }
        }

        // Generate tokens
        const accessToken = await tokenService.generateAccessToken(user);
        const refreshToken = await tokenService.generateRefreshToken(user);

        // Create session
        const session = await sessionManager.createSession(user.id, {
          ip: req.ip,
          userAgent: req.headers['user-agent'],
          deviceId,
          provider
        });

        // Log successful authentication
        if (loginAttemptsCounter) loginAttemptsCounter.inc({ result: 'success' });
        await auditService.logSuccessfulAuth(user.id, req, provider);

        res.json({
          success: true,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            roles: user.roles,
            permissions: user.permissions
          },
          tokens: {
            accessToken,
            refreshToken,
            expiresIn: config.jwt.expiresIn
          },
          session: {
            id: session.id,
            expiresAt: session.expiresAt
          }
        });
      })(req, res, next);
    } catch (error) {
      logger.error('Login error:', error);
      next(error);
    }
  });

  // POST /api/auth/logout
  router.post('/api/auth/logout', async (req, res) => {
    try {
      const { sessionId, allSessions = false } = req.body;
      const userId = req.user?.id;

      if (allSessions && userId) {
        await sessionManager.revokeAllUserSessions(userId);
        await auditService.logSecurityEvent('all_sessions_revoked', userId, req);
      } else if (sessionId) {
        await sessionManager.revokeSession(sessionId);
        await auditService.logSecurityEvent('session_revoked', userId, req);
      }

      // Clear session
      req.logout((err) => {
        if (err) {
          logger.error('Logout error:', err);
        }
      });

      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (error) {
      logger.error('Logout error:', error);
      res.status(500).json({ error: 'Logout failed' });
    }
  });

  // POST /api/auth/refresh
  router.post('/api/auth/refresh', async (req, res) => {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(400).json({ error: 'Refresh token required' });
      }

      const result = await tokenService.refreshAccessToken(refreshToken);

      if (!result) {
        return res.status(401).json({ error: 'Invalid refresh token' });
      }

      res.json({
        accessToken: result.accessToken,
        expiresIn: config.jwt.expiresIn
      });
    } catch (error) {
      logger.error('Token refresh error:', error);
      res.status(500).json({ error: 'Token refresh failed' });
    }
  });

  // POST /api/auth/validate
  router.post('/api/auth/validate', async (req, res) => {
    try {
      const { token } = req.body;

      if (!token) {
        return res.status(400).json({ error: 'Token required' });
      }

      const valid = await tokenService.validateToken(token);

      res.json({ valid });
    } catch (error) {
      res.json({ valid: false });
    }
  });

  return router;
}

module.exports = { createAuthRoutes };
