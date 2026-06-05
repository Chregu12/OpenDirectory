const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const passport = require('passport');
const rateLimit = require('express-rate-limit');

const promClient = require('prom-client');
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

// HTTP request counter
const httpRequestsTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status'],
  registers: [register],
});

// HTTP request duration
const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
  registers: [register],
});

const loginAttemptsCounter = new promClient.Counter({ name: 'auth_login_attempts_total', help: 'Login attempts', labelNames: ['result'], registers: [register] });
const activeSessionsGauge = new promClient.Gauge({ name: 'auth_active_sessions', help: 'Active user sessions', registers: [register] });
const lockedAccountsGauge = new promClient.Gauge({ name: 'auth_locked_accounts', help: 'Currently locked accounts', registers: [register] });

const { validate } = require('./middleware/validate');
const auditDb = require('./db');

// ─── Password History ─────────────────────────────────────────────────────────
const HISTORY_COUNT = 5; // prevent reuse of last 5 passwords

async function checkPasswordHistory(userId, newPlaintextPassword) {
  if (!auditDb.isAvailable()) return true; // skip check if DB unavailable
  try {
    const result = await auditDb.query(
      'SELECT password_hash FROM password_history WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2',
      [userId, HISTORY_COUNT]
    );
    const bcrypt = require('bcrypt');
    for (const row of result.rows) {
      const matches = await bcrypt.compare(newPlaintextPassword, row.password_hash);
      if (matches) return false; // password was used before
    }
    return true;
  } catch { return true; } // fail open
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
    // Keep only last 10 entries per user
    await auditDb.query(
      `DELETE FROM password_history WHERE user_id=$1 AND id NOT IN (
        SELECT id FROM password_history WHERE user_id=$1 ORDER BY created_at DESC LIMIT 10
      )`,
      [userId]
    );
  } catch {}
}

const AuthenticationManager = require('./services/authenticationManager');
const TokenService = require('./services/tokenService');
const MFAService = require('./services/mfaService');
const ZeroTrustService = require('./services/zeroTrustService');
const SessionManager = require('./services/sessionManager');
const UserService = require('./services/userService');
const AuditService = require('./services/auditService');

const logger = require('./utils/logger');
const config = require('./utils/config');

// ─── Event Bus ────────────────────────────────────────────────────────────────
const EventBusClient = (() => {
  try { return require('@opendirectory/grpc-event-bus').EventBusClient; }
  catch (_) { return require('../../../../packages/grpc-event-bus/src').EventBusClient; }
})();

const _bus = new EventBusClient({ source: 'authentication-service' });
async function connectBus() { await _bus.connect(); }
function publish(routingKey, payload) { _bus.publish(routingKey, payload).catch(() => {}); }

// ─── Password Reset Token Store ───────────────────────────────────────────────
const passwordResetTokens = new Map(); // token → { userId, email, expiresAt }

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

class UnifiedAuthenticationService {
  constructor() {
    this.app = express();
    this.authManager = new AuthenticationManager();
    this.tokenService = new TokenService();
    this.mfaService = new MFAService();
    this.zeroTrust = new ZeroTrustService();
    this.sessionManager = new SessionManager();
    this.userService = new UserService();
    this.auditService = new AuditService();
    
    this.initializeMiddleware();
    this.initializePassport();
    this.initializeRoutes();
  }

  initializeMiddleware() {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
        },
      },
    }));

    // CORS
    this.app.use(cors({
      origin: config.cors.origins,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-Id', 'X-Session-Id'],
    }));

    // Rate limiting per IP
    const authLimiterByIp = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 20,
      standardHeaders: true,
      legacyHeaders: false,
      message: 'Too many authentication attempts, please try again later.',
      keyGenerator: (req) => req.ip,
    });

    // Rate limiting per username — prevents distributed brute-force bypassing IP limits
    const usernameStore = new Map();
    const authLimiter = (req, res, next) => {
      const username = (req.body?.username || '').toLowerCase().trim();
      if (!username) return authLimiterByIp(req, res, next);

      const key = `auth:${username}`;
      const now = Date.now();
      const windowMs = 15 * 60 * 1000;
      const maxAttempts = 5;

      const record = usernameStore.get(key) || { count: 0, resetAt: now + windowMs };
      if (now > record.resetAt) {
        record.count = 0;
        record.resetAt = now + windowMs;
      }
      record.count += 1;
      usernameStore.set(key, record);

      if (record.count > maxAttempts) {
        return res.status(429).json({
          error: 'Too many authentication attempts for this account, please try again later.',
        });
      }
      return authLimiterByIp(req, res, next);
    };

    // Body parsing
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));

    // Session management with Redis
    const RedisClient = require('ioredis');
    const redisClient = new RedisClient({
      host: config.redis.host,
      port: config.redis.port,
      password: config.redis.password,
    });

    this.app.use(session({
      store: new RedisStore({ client: redisClient }),
      secret: config.session.secret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: config.environment === 'production',
        httpOnly: true,
        maxAge: config.session.maxAge,
        sameSite: 'strict'
      }
    }));

    // Passport initialization
    this.app.use(passport.initialize());
    this.app.use(passport.session());

    // Apply rate limiting to auth endpoints
    this.app.use('/api/auth/login', authLimiter);
    this.app.use('/api/auth/register', authLimiter);

    // Prometheus metrics middleware
    this.app.use((req, res, next) => {
      const start = Date.now();
      res.on('finish', () => {
        const route = req.route?.path ?? req.path ?? 'unknown';
        const duration = (Date.now() - start) / 1000;
        httpRequestsTotal.inc({ method: req.method, route, status: res.statusCode });
        httpRequestDuration.observe({ method: req.method, route }, duration);
      });
      next();
    });
  }

  initializePassport() {
    // Configure Passport strategies
    const LocalStrategy = require('passport-local').Strategy;
    const JwtStrategy = require('passport-jwt').Strategy;
    const LdapStrategy = require('passport-ldapauth');
    const { ExtractJwt } = require('passport-jwt');

    // Local strategy
    passport.use('local', new LocalStrategy({
      usernameField: 'username',
      passwordField: 'password',
      passReqToCallback: true
    }, async (req, username, password, done) => {
      try {
        // ─── Account Lockout Check ─────────────────────────────────────────────
        const _attempts = (global.__od_loginAttempts || new Map()).get(username) || { count: 0, lockedUntil: null };
        if (_attempts.lockedUntil && _attempts.lockedUntil > Date.now()) {
          const remaining = Math.ceil((_attempts.lockedUntil - Date.now()) / 60000);
          return done(null, false, { message: `Konto gesperrt. Versuche es in ${remaining} Minuten erneut.` });
        }

        const user = await this.authManager.authenticateLocal(username, password);
        if (!user) {
          auditDb.logAuditEvent({ eventType: 'login_failed', actor: username, message: `Failed login attempt for ${username}`, severity: 'warning' }).catch(() => {});
          // ─── Increment lockout counter ────────────────────────────────────────
          if (global.__od_loginAttempts) {
            const att = global.__od_loginAttempts.get(username) || { count: 0, lockedUntil: null };
            att.count++;
            if (att.count >= (global.__od_MAX_ATTEMPTS || 5)) {
              att.lockedUntil = Date.now() + (global.__od_LOCKOUT_MINUTES || 15) * 60_000;
              att.count = 0;
              auditDb.logAuditEvent({ eventType: 'account_locked', actor: username, message: `Account ${username} locked after ${global.__od_MAX_ATTEMPTS || 5} failed attempts`, severity: 'warning' }).catch(() => {});
              try { publish('identity.account.locked', { username, ip: req.ip, lockUntil: new Date(att.lockedUntil).toISOString() }); } catch (e) {}
            }
            global.__od_loginAttempts.set(username, att);
          }
          return done(null, false, { message: 'Invalid credentials' });
        }

        // Password policy enforcement at login
        const policy = _passwordPolicy;
        if (policy) {
          const pwd = password;
          const errors = [];
          if (policy.minLength && pwd.length < policy.minLength) {
            errors.push(`Mindestlänge ${policy.minLength} Zeichen erforderlich`);
          }
          if (policy.requireUppercase && !/[A-Z]/.test(pwd)) {
            errors.push('Grossbuchstabe erforderlich');
          }
          if (policy.requireLowercase && !/[a-z]/.test(pwd)) {
            errors.push('Kleinbuchstabe erforderlich');
          }
          if (policy.requireNumbers && !/[0-9]/.test(pwd)) {
            errors.push('Ziffer erforderlich');
          }
          if (policy.requireSpecial && !/[^A-Za-z0-9]/.test(pwd)) {
            errors.push('Sonderzeichen erforderlich');
          }
          if (errors.length > 0) {
            return done(null, false, { message: errors.join('; ') });
          }
        }

        // Zero-Trust verification
        const trustScore = await this.zeroTrust.evaluateTrust(req, user);
        if (trustScore < config.zeroTrust.minTrustScore) {
          await this.auditService.logFailedAuth(username, req, 'Low trust score');
          return done(null, false, { message: 'Additional verification required' });
        }

        auditDb.logAuditEvent({ eventType: 'login_success', actor: username, message: `User ${username} logged in`, severity: 'info' }).catch(() => {});
        // ─── Clear lockout on successful login ────────────────────────────────
        if (global.__od_loginAttempts) global.__od_loginAttempts.delete(username);
        return done(null, user);
      } catch (error) {
        logger.error('Local auth error:', error);
        return done(error);
      }
    }));

    // JWT strategy
    passport.use('jwt', new JwtStrategy({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.jwt.secret,
      passReqToCallback: true
    }, async (req, payload, done) => {
      try {
        const user = await this.userService.getUserById(payload.sub);
        if (!user) {
          return done(null, false);
        }
        
        // Continuous Zero-Trust verification
        const trustScore = await this.zeroTrust.evaluateTrust(req, user);
        if (trustScore < config.zeroTrust.minTrustScore) {
          await this.auditService.logSecurityEvent('jwt_trust_failed', user.id, req);
          return done(null, false, { message: 'Re-authentication required' });
        }
        
        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }));

    // LDAP strategy (LLDAP integration)
    passport.use('ldap', new LdapStrategy({
      server: {
        url: config.ldap.url,
        bindDN: config.ldap.bindDN,
        bindCredentials: config.ldap.bindPassword,
        searchBase: config.ldap.searchBase,
        searchFilter: config.ldap.searchFilter,
      },
      passReqToCallback: true
    }, async (req, ldapUser, done) => {
      try {
        // Map LDAP user to local user
        const user = await this.authManager.mapLdapUser(ldapUser);
        
        // Zero-Trust verification
        const trustScore = await this.zeroTrust.evaluateTrust(req, user);
        if (trustScore < config.zeroTrust.minTrustScore) {
          return done(null, false, { message: 'Additional verification required' });
        }
        
        return done(null, user);
      } catch (error) {
        logger.error('LDAP auth error:', error);
        return done(error);
      }
    }));

    // Serialize/Deserialize user for sessions
    passport.serializeUser((user, done) => {
      done(null, user.id);
    });

    passport.deserializeUser(async (id, done) => {
      try {
        const user = await this.userService.getUserById(id);
        done(null, user);
      } catch (error) {
        done(error);
      }
    });
  }

  initializeRoutes() {
    // Metrics endpoint
    this.app.get('/metrics', async (req, res) => {
      res.setHeader('Content-Type', register.contentType);
      res.send(await register.metrics());
    });

    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        service: 'authentication-service',
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
      });
    });

    // Authentication endpoints
    this.app.post('/api/auth/login',    validate('login'),          this.login.bind(this));
    this.app.post('/api/auth/logout',   this.logout.bind(this));
    this.app.post('/api/auth/register', validate('register'),       this.register.bind(this));
    this.app.post('/api/auth/refresh',  this.refreshToken.bind(this));
    this.app.post('/api/auth/validate', this.validateToken.bind(this));
    
    // MFA endpoints
    this.app.post('/api/auth/mfa/setup', this.setupMFA.bind(this));
    this.app.post('/api/auth/mfa/verify', this.verifyMFA.bind(this));
    this.app.post('/api/auth/mfa/disable', this.disableMFA.bind(this));
    this.app.get('/api/auth/mfa/recovery-codes', this.getRecoveryCodes.bind(this));
    
    // Zero-Trust endpoints
    this.app.post('/api/auth/verify-device', this.verifyDevice.bind(this));
    this.app.post('/api/auth/verify-location', this.verifyLocation.bind(this));
    this.app.get('/api/auth/trust-score', this.getTrustScore.bind(this));
    this.app.post('/api/auth/step-up', this.stepUpAuthentication.bind(this));
    
    // Session management
    this.app.get('/api/auth/sessions', this.getSessions.bind(this));
    this.app.delete('/api/auth/sessions/:sessionId', this.revokeSession.bind(this));
    this.app.post('/api/auth/sessions/revoke-all', this.revokeAllSessions.bind(this));
    
    // User management
    this.app.get('/api/auth/profile', this.getProfile.bind(this));
    this.app.put('/api/auth/profile', this.updateProfile.bind(this));
    this.app.post('/api/auth/change-password', validate('changePassword'), this.changePassword.bind(this));
    this.app.post('/api/auth/reset-password', this.resetPassword.bind(this));
    this.app.post('/api/auth/password-reset/confirm', this.confirmPasswordReset.bind(this));
    
    // SSO endpoints
    this.app.get('/api/auth/sso/providers', this.getSSOProviders.bind(this));
    this.app.get('/api/auth/sso/:provider', this.initiateSSOLogin.bind(this));
    this.app.get('/api/auth/sso/:provider/callback', this.handleSSOCallback.bind(this));
    
    // Admin endpoints
    this.app.get('/api/auth/users', this.requireAdmin(), this.listUsers.bind(this));
    this.app.get('/api/auth/users/:userId', this.requireAdmin(), this.getUser.bind(this));
    this.app.put('/api/auth/users/:userId', this.requireAdmin(), this.updateUser.bind(this));
    this.app.delete('/api/auth/users/:userId', this.requireAdmin(), this.deleteUser.bind(this));
    this.app.post('/api/auth/users/:userId/lock', this.requireAdmin(), this.lockUser.bind(this));
    this.app.post('/api/auth/users/:userId/unlock', this.requireAdmin(), this.unlockUser.bind(this));
    
    // Audit endpoints
    this.app.get('/api/auth/audit/login-history', this.getLoginHistory.bind(this));
    this.app.get('/api/auth/audit/security-events', this.requireAdmin(), this.getSecurityEvents.bind(this));

    // Error handling
    this.app.use(this.errorHandler.bind(this));
  }

  // Authentication handlers
  async login(req, res, next) {
    try {
      const { username, password, mfaCode, deviceId, provider = 'local' } = req.body;
      
      // Select authentication strategy
      const strategy = provider === 'ldap' ? 'ldap' : 'local';
      
      passport.authenticate(strategy, async (err, user, info) => {
        if (err) {
          return next(err);
        }
        
        if (!user) {
          loginAttemptsCounter.inc({ result: 'failure' });
          await this.auditService.logFailedAuth(username, req, info?.message);
          try { publish('identity.login.failed', { username, ip: req.ip, reason: 'invalid_password' }); } catch (e) {}
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
              await this.auditService.logFailedAuth(username, req, 'Invalid TOTP code');
              return res.status(401).json({ error: 'Ungültiger TOTP-Code' });
            }
          }
        }

        // Check if MFA is required (class-based mfaService)
        if (user.mfaEnabled && !mfaCode) {
          return res.status(200).json({
            requiresMFA: true,
            tempToken: await this.tokenService.generateTempToken(user.id)
          });
        }

        // Verify MFA if provided (class-based mfaService, only if no in-memory TOTP)
        if (user.mfaEnabled && mfaCode && !hasTotpMfa) {
          const mfaValid = await this.mfaService.verifyCode(user.id, mfaCode);
          if (!mfaValid) {
            await this.auditService.logFailedAuth(username, req, 'Invalid MFA code');
            return res.status(401).json({
              error: 'Invalid MFA code'
            });
          }
        }

        // Generate tokens
        const accessToken = await this.tokenService.generateAccessToken(user);
        const refreshToken = await this.tokenService.generateRefreshToken(user);
        
        // Create session
        const session = await this.sessionManager.createSession(user.id, {
          ip: req.ip,
          userAgent: req.headers['user-agent'],
          deviceId,
          provider
        });
        
        // Log successful authentication
        loginAttemptsCounter.inc({ result: 'success' });
        await this.auditService.logSuccessfulAuth(user.id, req, provider);
        try { publish('identity.login.success', { userId: user.id, username: user.username, ip: req.ip, deviceId, provider }); } catch (e) {}

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
  }

  async logout(req, res) {
    try {
      const { sessionId, allSessions = false } = req.body;
      const userId = req.user?.id;
      
      if (allSessions && userId) {
        await this.sessionManager.revokeAllUserSessions(userId);
        await this.auditService.logSecurityEvent('all_sessions_revoked', userId, req);
      } else if (sessionId) {
        await this.sessionManager.revokeSession(sessionId);
        await this.auditService.logSecurityEvent('session_revoked', userId, req);
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
  }

  async register(req, res) {
    try {
      const { username, email, password, firstName, lastName } = req.body;
      
      // Validate input
      const validation = await this.userService.validateRegistration(req.body);
      if (!validation.valid) {
        return res.status(400).json({
          error: 'Validation failed',
          details: validation.errors
        });
      }
      
      // Check if user exists
      const existingUser = await this.userService.getUserByUsername(username);
      if (existingUser) {
        return res.status(409).json({
          error: 'User already exists'
        });
      }
      
      // Create user
      const user = await this.userService.createUser({
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
        await this.authManager.createLdapUser(user);
      }

      // Sync to Kerberos KDC
      const KDC_API = process.env.KDC_API_URL || 'http://kerberos-kdc';
      fetch(`${KDC_API}/api/kerberos/sync-user`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user.username || username, password })
      }).catch(err => console.warn('[kerberos-sync]', err.message));

      // Log registration
      await this.auditService.logUserEvent('user_registered', user.id, req);
      try { publish('identity.user.created', { userId: user.id, username: user.username || username, role: user.roles?.[0] || 'user', createdBy: 'self-registration' }); } catch (e) {}

      res.status(201).json({
        success: true,
        message: 'Registration successful',
        userId: user.id
      });
    } catch (error) {
      logger.error('Registration error:', error);
      res.status(500).json({ error: 'Registration failed' });
    }
  }

  async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body;
      
      if (!refreshToken) {
        return res.status(400).json({ error: 'Refresh token required' });
      }
      
      const result = await this.tokenService.refreshAccessToken(refreshToken);
      
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
  }

  async validateToken(req, res) {
    try {
      const { token } = req.body;
      
      if (!token) {
        return res.status(400).json({ error: 'Token required' });
      }
      
      const valid = await this.tokenService.validateToken(token);
      
      res.json({ valid });
    } catch (error) {
      res.json({ valid: false });
    }
  }

  // MFA handlers
  async setupMFA(req, res) {
    try {
      const userId = req.user.id;
      
      const { secret, qrCode, recoveryCodes } = await this.mfaService.setupMFA(userId);
      
      res.json({
        secret,
        qrCode,
        recoveryCodes,
        instructions: 'Scan the QR code with your authenticator app and save the recovery codes'
      });
    } catch (error) {
      logger.error('MFA setup error:', error);
      res.status(500).json({ error: 'MFA setup failed' });
    }
  }

  async verifyMFA(req, res) {
    try {
      const userId = req.user.id;
      const { code } = req.body;
      
      const valid = await this.mfaService.verifyCode(userId, code);
      
      if (valid) {
        await this.mfaService.enableMFA(userId);
        await this.auditService.logSecurityEvent('mfa_enabled', userId, req);
        try { publish('identity.mfa.enabled', { userId, method: 'totp' }); } catch (e) {}
      }

      res.json({ valid });
    } catch (error) {
      logger.error('MFA verification error:', error);
      res.status(500).json({ error: 'MFA verification failed' });
    }
  }

  async disableMFA(req, res) {
    try {
      const userId = req.user.id;
      const { password } = req.body;
      
      // Verify password before disabling MFA
      const user = await this.userService.getUserById(userId);
      const validPassword = await this.authManager.verifyPassword(password, user.password);
      
      if (!validPassword) {
        return res.status(401).json({ error: 'Invalid password' });
      }
      
      await this.mfaService.disableMFA(userId);
      await this.auditService.logSecurityEvent('mfa_disabled', userId, req);
      
      res.json({
        success: true,
        message: 'MFA disabled successfully'
      });
    } catch (error) {
      logger.error('MFA disable error:', error);
      res.status(500).json({ error: 'Failed to disable MFA' });
    }
  }

  async getRecoveryCodes(req, res) {
    try {
      const userId = req.user.id;
      
      const codes = await this.mfaService.getRecoveryCodes(userId);
      
      res.json({ recoveryCodes: codes });
    } catch (error) {
      logger.error('Recovery codes error:', error);
      res.status(500).json({ error: 'Failed to get recovery codes' });
    }
  }

  // Zero-Trust handlers
  async verifyDevice(req, res) {
    try {
      const userId = req.user.id;
      const { deviceId, deviceInfo } = req.body;
      
      const verified = await this.zeroTrust.verifyDevice(userId, deviceId, deviceInfo);
      
      res.json({ verified });
    } catch (error) {
      logger.error('Device verification error:', error);
      res.status(500).json({ error: 'Device verification failed' });
    }
  }

  async verifyLocation(req, res) {
    try {
      const userId = req.user.id;
      const location = {
        ip: req.ip,
        country: req.headers['cf-ipcountry'],
        ...req.body
      };
      
      const verified = await this.zeroTrust.verifyLocation(userId, location);
      
      res.json({ verified });
    } catch (error) {
      logger.error('Location verification error:', error);
      res.status(500).json({ error: 'Location verification failed' });
    }
  }

  async getTrustScore(req, res) {
    try {
      const userId = req.user.id;
      
      const score = await this.zeroTrust.calculateTrustScore(req, req.user);
      
      res.json({
        score,
        factors: await this.zeroTrust.getTrustFactors(userId),
        threshold: config.zeroTrust.minTrustScore
      });
    } catch (error) {
      logger.error('Trust score error:', error);
      res.status(500).json({ error: 'Failed to calculate trust score' });
    }
  }

  async stepUpAuthentication(req, res) {
    try {
      const userId = req.user.id;
      const { method, value } = req.body;
      
      const result = await this.zeroTrust.performStepUp(userId, method, value);
      
      if (result.success) {
        await this.auditService.logSecurityEvent('step_up_success', userId, req);
      }
      
      res.json(result);
    } catch (error) {
      logger.error('Step-up auth error:', error);
      res.status(500).json({ error: 'Step-up authentication failed' });
    }
  }

  // Session handlers
  async getSessions(req, res) {
    try {
      const userId = req.user.id;
      
      const sessions = await this.sessionManager.getUserSessions(userId);
      
      res.json({ sessions });
    } catch (error) {
      logger.error('Get sessions error:', error);
      res.status(500).json({ error: 'Failed to get sessions' });
    }
  }

  async revokeSession(req, res) {
    try {
      const { sessionId } = req.params;
      const userId = req.user.id;
      
      await this.sessionManager.revokeSession(sessionId, userId);
      await this.auditService.logSecurityEvent('session_revoked', userId, req);
      
      res.json({
        success: true,
        message: 'Session revoked'
      });
    } catch (error) {
      logger.error('Revoke session error:', error);
      res.status(500).json({ error: 'Failed to revoke session' });
    }
  }

  async revokeAllSessions(req, res) {
    try {
      const userId = req.user.id;
      
      await this.sessionManager.revokeAllUserSessions(userId);
      await this.auditService.logSecurityEvent('all_sessions_revoked', userId, req);
      
      res.json({
        success: true,
        message: 'All sessions revoked'
      });
    } catch (error) {
      logger.error('Revoke all sessions error:', error);
      res.status(500).json({ error: 'Failed to revoke sessions' });
    }
  }

  // User management handlers
  async getProfile(req, res) {
    try {
      const userId = req.user.id;
      
      const user = await this.userService.getUserById(userId);
      
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
  }

  async updateProfile(req, res) {
    try {
      const userId = req.user.id;
      const updates = req.body;
      
      // Remove protected fields
      delete updates.id;
      delete updates.username;
      delete updates.password;
      delete updates.roles;
      delete updates.permissions;
      
      const user = await this.userService.updateUser(userId, updates);
      await this.auditService.logUserEvent('profile_updated', userId, req);
      
      res.json({
        success: true,
        user
      });
    } catch (error) {
      logger.error('Update profile error:', error);
      res.status(500).json({ error: 'Failed to update profile' });
    }
  }

  async changePassword(req, res) {
    try {
      const userId = req.user.id;
      const { currentPassword, newPassword } = req.body;

      const user = await this.userService.getUserById(userId);
      const validPassword = await this.authManager.verifyPassword(currentPassword, user.password);

      if (!validPassword) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }

      const historyOk = await checkPasswordHistory(userId, newPassword);
      if (!historyOk) {
        return res.status(400).json({ error: 'Dieses Passwort wurde bereits verwendet. Bitte wählen Sie ein anderes.' });
      }

      await this.userService.changePassword(userId, newPassword);
      recordPasswordHash(userId, newPassword).catch(() => {});
      await this.sessionManager.revokeAllUserSessions(userId);
      await this.auditService.logSecurityEvent('password_changed', userId, req);

      // Sync new password to Kerberos KDC
      const KDC_API_CP = process.env.KDC_API_URL || 'http://kerberos-kdc';
      fetch(`${KDC_API_CP}/api/kerberos/sync-user`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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
  }

  async resetPassword(req, res) {
    try {
      const { email } = req.body;

      const user = await this.userService.getUserByEmail(email);
      if (user) {
        // Generate a cryptographically random reset token
        const crypto = require('crypto');
        const resetToken = crypto.randomBytes(32).toString('hex');
        const expiresAt = Date.now() + 3600_000; // 1 hour

        // Store reset token
        passwordResetTokens.set(resetToken, { userId: user.id, email: user.email, expiresAt });

        await this.auditService.logUserEvent('password_reset_requested', user.id, req);

        // Send password reset email
        const transport = getMailer();
        if (transport) {
          try {
            const resetUrl = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
            await transport.sendMail({
              from: process.env.SMTP_FROM || 'OpenDirectory <noreply@opendirectory.local>',
              to: user.email,
              subject: 'Passwort zurücksetzen — OpenDirectory',
              html: `
                <div style="font-family:sans-serif;max-width:480px;margin:0 auto">
                  <h2 style="color:#1e293b">Passwort zurücksetzen</h2>
                  <p>Hallo ${user.name || user.username},</p>
                  <p>Sie haben eine Passwort-Zurücksetzung angefordert. Klicken Sie auf den folgenden Link:</p>
                  <a href="${resetUrl}" style="display:inline-block;margin:16px 0;padding:12px 24px;background:#3b82f6;color:#fff;text-decoration:none;border-radius:8px">Passwort zurücksetzen</a>
                  <p style="color:#64748b;font-size:12px">Dieser Link ist 1 Stunde gültig. Falls Sie keine Zurücksetzung angefordert haben, ignorieren Sie diese E-Mail.</p>
                </div>
              `,
            });
            console.log(`[password-reset] Email sent to ${user.email}`);
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
  }

  async confirmPasswordReset(req, res) {
    try {
      const { token, newPassword } = req.body;
      if (!token || !newPassword) {
        return res.status(400).json({ error: 'token and newPassword required' });
      }

      const resetRecord = passwordResetTokens.get(token);
      if (!resetRecord || resetRecord.expiresAt < Date.now()) {
        return res.status(400).json({ error: 'Ungültiger oder abgelaufener Token' });
      }

      // Validate new password against policy
      const policy = _passwordPolicy;
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

      // Check password history
      const historyOk = await checkPasswordHistory(resetRecord.userId, newPassword);
      if (!historyOk) {
        return res.status(400).json({ error: 'Dieses Passwort wurde bereits verwendet. Bitte wählen Sie ein anderes.' });
      }

      // Update password via userService
      await this.userService.changePassword(resetRecord.userId, newPassword);
      recordPasswordHash(resetRecord.userId, newPassword).catch(() => {});

      // Consume the token
      passwordResetTokens.delete(token);

      await this.auditService.logUserEvent('password_reset_completed', resetRecord.userId, req);
      try { publish('identity.password.reset', { userId: resetRecord.userId, ip: req.ip }); } catch (e) {}

      res.json({ success: true, message: 'Passwort erfolgreich zurückgesetzt' });
    } catch (error) {
      logger.error('Confirm password reset error:', error);
      res.status(500).json({ error: 'Failed to reset password' });
    }
  }

  // SSO handlers
  async getSSOProviders(req, res) {
    try {
      const providers = await this.authManager.getSSOProviders();
      
      res.json({ providers });
    } catch (error) {
      logger.error('Get SSO providers error:', error);
      res.status(500).json({ error: 'Failed to get SSO providers' });
    }
  }

  async initiateSSOLogin(req, res) {
    try {
      const { provider } = req.params;
      
      const authUrl = await this.authManager.initiateSSOLogin(provider);
      
      res.redirect(authUrl);
    } catch (error) {
      logger.error('SSO login error:', error);
      res.status(500).json({ error: 'SSO login failed' });
    }
  }

  async handleSSOCallback(req, res) {
    try {
      const { provider } = req.params;
      
      const result = await this.authManager.handleSSOCallback(provider, req.query);
      
      if (result.success) {
        res.redirect(`${config.frontend.url}/auth/success?token=${result.token}`);
      } else {
        res.redirect(`${config.frontend.url}/auth/error`);
      }
    } catch (error) {
      logger.error('SSO callback error:', error);
      res.redirect(`${config.frontend.url}/auth/error`);
    }
  }

  // Admin handlers
  async listUsers(req, res) {
    try {
      const { page = 1, limit = 50, search } = req.query;
      
      const users = await this.userService.listUsers({
        page: parseInt(page),
        limit: parseInt(limit),
        search
      });
      
      res.json(users);
    } catch (error) {
      logger.error('List users error:', error);
      res.status(500).json({ error: 'Failed to list users' });
    }
  }

  async getUser(req, res) {
    try {
      const { userId } = req.params;
      
      const user = await this.userService.getUserById(userId);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      res.json(user);
    } catch (error) {
      logger.error('Get user error:', error);
      res.status(500).json({ error: 'Failed to get user' });
    }
  }

  async updateUser(req, res) {
    try {
      const { userId } = req.params;
      const updates = req.body;
      
      const user = await this.userService.updateUser(userId, updates);
      await this.auditService.logAdminAction('user_updated', req.user.id, { targetUserId: userId, updates }, req);
      
      res.json({
        success: true,
        user
      });
    } catch (error) {
      logger.error('Update user error:', error);
      res.status(500).json({ error: 'Failed to update user' });
    }
  }

  async deleteUser(req, res) {
    try {
      const { userId } = req.params;
      
      await this.userService.deleteUser(userId);
      await this.sessionManager.revokeAllUserSessions(userId);
      await this.auditService.logAdminAction('user_deleted', req.user.id, { targetUserId: userId }, req);
      
      res.json({
        success: true,
        message: 'User deleted successfully'
      });
    } catch (error) {
      logger.error('Delete user error:', error);
      res.status(500).json({ error: 'Failed to delete user' });
    }
  }

  async lockUser(req, res) {
    try {
      const { userId } = req.params;
      const { reason, duration } = req.body;
      
      await this.userService.lockUser(userId, reason, duration);
      await this.sessionManager.revokeAllUserSessions(userId);
      await this.auditService.logAdminAction('user_locked', req.user.id, { targetUserId: userId, reason, duration }, req);
      
      res.json({
        success: true,
        message: 'User locked successfully'
      });
    } catch (error) {
      logger.error('Lock user error:', error);
      res.status(500).json({ error: 'Failed to lock user' });
    }
  }

  async unlockUser(req, res) {
    try {
      const { userId } = req.params;
      
      await this.userService.unlockUser(userId);
      await this.auditService.logAdminAction('user_unlocked', req.user.id, { targetUserId: userId }, req);
      
      res.json({
        success: true,
        message: 'User unlocked successfully'
      });
    } catch (error) {
      logger.error('Unlock user error:', error);
      res.status(500).json({ error: 'Failed to unlock user' });
    }
  }

  // Audit handlers
  async getLoginHistory(req, res) {
    try {
      const userId = req.user.id;
      const { limit = 50 } = req.query;
      
      const history = await this.auditService.getLoginHistory(userId, parseInt(limit));
      
      res.json({ history });
    } catch (error) {
      logger.error('Get login history error:', error);
      res.status(500).json({ error: 'Failed to get login history' });
    }
  }

  async getSecurityEvents(req, res) {
    try {
      const { userId, eventType, startDate, endDate, limit = 100 } = req.query;
      
      const events = await this.auditService.getSecurityEvents({
        userId,
        eventType,
        startDate,
        endDate,
        limit: parseInt(limit)
      });
      
      res.json({ events });
    } catch (error) {
      logger.error('Get security events error:', error);
      res.status(500).json({ error: 'Failed to get security events' });
    }
  }

  // Middleware
  requireAuth() {
    return passport.authenticate('jwt', { session: false });
  }

  requireAdmin() {
    return [
      this.requireAuth(),
      (req, res, next) => {
        if (!req.user.roles?.includes('admin')) {
          return res.status(403).json({ error: 'Admin access required' });
        }
        next();
      }
    ];
  }

  errorHandler(error, req, res, next) {
    logger.error('Unhandled error:', error);
    
    res.status(error.status || 500).json({
      error: error.message || 'Internal server error',
      requestId: req.id,
      timestamp: new Date().toISOString()
    });
  }

  start(port = process.env.PORT || 3001) {
    auditDb.initDb().catch(() => {});
    try { connectBus(); } catch (e) { console.warn('[bus] startup connect error:', e.message); }
    // User onboarding saga
    const { UserOnboardingSaga } = require('../../../../packages/service-contracts/src');
    const MessageBusSingleton = require('../../../../packages/service-contracts/src/messageBus');
    const _userSaga = new UserOnboardingSaga(MessageBusSingleton.getInstance(), { logger });
    setTimeout(() => _userSaga.launch().catch(e => logger.warn('[UserOnboardingSaga] ' + e.message)), 5000);
    this.server = this.app.listen(port, () => {
      logger.info(`🔐 Unified Authentication Service started on port ${port}`);
      logger.info(`📊 Health check: http://localhost:${port}/health`);
      logger.info(`🔑 Auth providers: Local, LDAP, JWT, SSO`);
      logger.info(`🛡️ Zero-Trust: ${config.zeroTrust.enabled ? 'Enabled' : 'Disabled'}`);
      logger.info(`📱 MFA: ${config.mfa.enabled ? 'Enabled' : 'Disabled'}`);
      seedAuditEvents().catch(() => {});
    });
  }

  stop() {
    if (this.server) this.server.close(() => logger.info('Authentication service stopped'));
  }
}

// Start the service
const authService = new UnifiedAuthenticationService();
authService.start();

function shutdown(signal) {
  logger.info(`Received ${signal}, shutting down gracefully`);
  authService.stop();
  setTimeout(() => { logger.error('Forced shutdown after timeout'); process.exit(1); }, 10000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

module.exports = UnifiedAuthenticationService;

// ─── Audit seed helper ───────────────────────────────────────────────────────────────
async function seedAuditEvents() {
  const events = await auditDb.getRecentEvents(1);
  if (events.length === 0) {
    const seeds = [
      { eventType: 'system_start', actor: 'system', message: 'OpenDirectory authentication service started', severity: 'info' },
      { eventType: 'login_success', actor: 'admin', message: 'User admin logged in', severity: 'info' },
      { eventType: 'user_created', actor: 'admin', target: 'alice@company.local', message: 'User alice@company.local created', severity: 'info' },
      { eventType: 'device_enrolled', actor: 'system', target: 'LAPTOP-001', message: 'Device LAPTOP-001 enrolled via Windows agent', severity: 'info' },
      { eventType: 'permission_changed', actor: 'admin', target: 'bob', message: 'Permission updated: bob → users_admin=write', severity: 'info' },
    ];
    for (const e of seeds) {
      await auditDb.logAuditEvent(e).catch(() => {});
    }
  }
}

// ─── Phase 3: Directory Service API ─────────────────────────────────────────────────
// Appended in-memory Directory endpoints: OUs, Groups, Password Policies, Service Accounts

// Module-level password policy — accessible by passport LocalStrategy
let _passwordPolicy = { minLength: 12, requireUppercase: true, requireNumbers: true, requireSymbols: true, rotationDays: 90, historyDepth: 10 };

(function attachDirectoryApi() {
  const crypto = require('crypto');
  const jwt = require('jsonwebtoken');
  const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';
  const app = authService.app;

  // ─── In-Memory Stores ──────────────────────────────────────────────────────────

  const ous = new Map();
  const groups = new Map();
  const groupMembers = new Map(); // groupId -> Set<userId>
  // Reference the module-level policy so LocalStrategy can read it
  let passwordPolicy = _passwordPolicy;
  const serviceAccounts = new Map();

  // ─── TOTP MFA Stores ──────────────────────────────────────────────────────────
  const pendingMfaSecrets = new Map(); // userId → base32 secret (not yet verified)
  const userMfaSecrets = new Map();    // userId → base32 secret (active)

  // ─── Account Lockout Stores ───────────────────────────────────────────────────
  const loginAttempts = new Map(); // username → { count, lockedUntil }
  const MAX_ATTEMPTS = 5;
  const LOCKOUT_MINUTES = 15;

  // Expose lockout map module-level so LocalStrategy can access it
  global.__od_loginAttempts = loginAttempts;
  global.__od_MAX_ATTEMPTS = MAX_ATTEMPTS;
  global.__od_LOCKOUT_MINUTES = LOCKOUT_MINUTES;

  // ─── Seed Data ─────────────────────────────────────────────────────────────────

  const ouSeed = [
    { id: 'ou-1', name: 'Engineering', parentId: null,  description: 'Engineering department', deleted: false, createdAt: new Date().toISOString() },
    { id: 'ou-2', name: 'Marketing',   parentId: null,  description: 'Marketing department',   deleted: false, createdAt: new Date().toISOString() },
    { id: 'ou-3', name: 'IT',          parentId: null,  description: 'IT Operations',           deleted: false, createdAt: new Date().toISOString() },
    { id: 'ou-4', name: 'Backend',     parentId: 'ou-1',description: 'Backend engineering',    deleted: false, createdAt: new Date().toISOString() },
  ];
  ouSeed.forEach(o => ous.set(o.id, o));

  const groupSeed = [
    { id: 'g-developers', name: 'Developers',    description: 'Software developers', ouId: 'ou-1', createdAt: new Date().toISOString() },
    { id: 'g-devops',     name: 'DevOps',        description: 'DevOps engineers',    ouId: 'ou-1', createdAt: new Date().toISOString() },
    { id: 'g-marketing',  name: 'Marketing Team',description: 'Marketing team',      ouId: 'ou-2', createdAt: new Date().toISOString() },
  ];
  groupSeed.forEach(g => { groups.set(g.id, g); groupMembers.set(g.id, new Set()); });

  const saSeed = [
    { id: 'sa-ci-runner', name: 'ci-runner', description: 'CI/CD pipeline service account', scopes: ['devices:read', 'policies:read'], createdAt: new Date().toISOString(), token: jwt.sign(
      {
        sub: 'sa-ci-runner',
        type: 'service_account',
        name: 'ci-runner',
        permissions: ['devices:read', 'policies:read'],
        iss: 'opendirectory',
        aud: 'opendirectory-services',
      },
      JWT_SECRET,
      { expiresIn: '90d', algorithm: 'HS256' }
    ) },
  ];
  saSeed.forEach(s => serviceAccounts.set(s.id, s));

  // ─── SCIM users reference (from oauth-provider; mirrored here for bulk import) ─
  // We keep our own map for bulk-imported users
  const scimUsers = new Map();

  // ─── Auth middleware: require Bearer token on all /api/* except /api/enrollment/* ─

  app.use('/api', (req, res, next) => {
    // Exclude enrollment endpoints and health
    if (req.path.startsWith('/enrollment/')) return next();
    // Exclude auth endpoints (they handle their own auth)
    if (req.path.startsWith('/auth/')) return next();
    // Exclude audit read endpoint (dashboard reads this without user auth)
    if (req.path.startsWith('/audit/')) return next();
    const authHeader = req.headers['authorization'] ?? '';
    if (!authHeader || !authHeader.trim()) {
      return res.status(401).json({ error: 'Authorization: Bearer token required' });
    }
    next();
  });

  // ─── Helper: build OU tree ─────────────────────────────────────────────────────

  function buildTree(parentId = null) {
    return [...ous.values()].filter(o => !o.deleted && o.parentId === parentId).map(o => ({ ...o, children: buildTree(o.id) }));
  }

  // ─── OUs ──────────────────────────────────────────────────────────────────────

  app.get('/api/ous', (req, res) => res.json(buildTree()));

  app.post('/api/ous', (req, res) => {
    const { name, parentId, description } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });
    const id = `ou-${Date.now()}`;
    const ouData = { id, name, parentId: parentId ?? null, description: description ?? '', deleted: false, createdAt: new Date().toISOString() };
    ous.set(id, ouData);

    // Sync to LLDAP
    const LLDAP_URL = process.env.LLDAP_URL || 'http://localhost:3890';
    const LLDAP_ADMIN = process.env.LLDAP_ADMIN_USER || 'admin';
    const LLDAP_PASS = process.env.LLDAP_ADMIN_PASSWORD || '';
    fetch(`${LLDAP_URL}/api/graphql`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Basic ${Buffer.from(`${LLDAP_ADMIN}:${LLDAP_PASS}`).toString('base64')}` },
      body: JSON.stringify({
        query: `mutation CreateGroup($name: String!) { createGroup(name: $name) { id } }`,
        variables: { name: ouData.name }
      })
    }).catch(() => {});

    res.status(201).json(ouData);
  });

  app.put('/api/ous/:id', (req, res) => {
    const ou = ous.get(req.params.id);
    if (!ou || ou.deleted) return res.status(404).json({ error: 'OU not found' });
    const { name, parentId, description } = req.body;
    Object.assign(ou, { ...(name && { name }), ...(parentId !== undefined && { parentId }), ...(description !== undefined && { description }) });
    res.json(ou);
  });

  app.delete('/api/ous/:id', (req, res) => {
    const ou = ous.get(req.params.id);
    if (!ou) return res.status(404).json({ error: 'OU not found' });
    ou.deleted = true;
    res.status(204).send();
  });

  // ─── Groups ───────────────────────────────────────────────────────────────────

  app.get('/api/groups', (req, res) => {
    const list = [...groups.values()].map(g => ({ ...g, memberCount: (groupMembers.get(g.id) ?? new Set()).size }));
    res.json(list);
  });

  app.post('/api/groups', (req, res) => {
    const { name, description, ouId } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });
    const id = `g-${Date.now()}`;
    const group = { id, name, description: description ?? '', ouId: ouId ?? null, createdAt: new Date().toISOString() };
    groups.set(id, group);
    groupMembers.set(id, new Set());

    // Sync to LLDAP
    const LLDAP_URL = process.env.LLDAP_URL || 'http://localhost:3890';
    const LLDAP_ADMIN = process.env.LLDAP_ADMIN_USER || 'admin';
    const LLDAP_PASS = process.env.LLDAP_ADMIN_PASSWORD || '';
    fetch(`${LLDAP_URL}/api/graphql`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Basic ${Buffer.from(`${LLDAP_ADMIN}:${LLDAP_PASS}`).toString('base64')}` },
      body: JSON.stringify({
        query: `mutation CreateGroup($name: String!) { createGroup(name: $name) { id } }`,
        variables: { name: group.name }
      })
    }).catch(() => {});

    res.status(201).json(group);
  });

  app.get('/api/groups/:id', (req, res) => {
    const g = groups.get(req.params.id);
    if (!g) return res.status(404).json({ error: 'Group not found' });
    res.json({ ...g, members: [...(groupMembers.get(req.params.id) ?? new Set())] });
  });

  app.post('/api/groups/:id/members', (req, res) => {
    if (!groups.has(req.params.id)) return res.status(404).json({ error: 'Group not found' });
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId required' });
    groupMembers.get(req.params.id).add(userId);
    res.status(201).json({ groupId: req.params.id, userId });
  });

  app.delete('/api/groups/:id/members/:userId', (req, res) => {
    if (!groups.has(req.params.id)) return res.status(404).json({ error: 'Group not found' });
    groupMembers.get(req.params.id).delete(req.params.userId);
    res.status(204).send();
  });

  app.get('/api/groups/:id/apps', (req, res) => {
    // Mock app assignments
    res.json({ groupId: req.params.id, apps: [] });
  });

  // ─── Password Policy ──────────────────────────────────────────────────────────

  app.get('/api/password-policy', (req, res) => res.json(passwordPolicy));

  app.put('/api/password-policy', (req, res) => {
    const { minLength, requireUppercase, requireNumbers, requireSymbols, rotationDays, historyDepth } = req.body;
    Object.assign(passwordPolicy, { ...(minLength !== undefined && { minLength }), ...(requireUppercase !== undefined && { requireUppercase }), ...(requireNumbers !== undefined && { requireNumbers }), ...(requireSymbols !== undefined && { requireSymbols }), ...(rotationDays !== undefined && { rotationDays }), ...(historyDepth !== undefined && { historyDepth }) });
    res.json(passwordPolicy);
  });

  // ─── Service Accounts ─────────────────────────────────────────────────────────

  app.get('/api/service-accounts', (req, res) => {
    const list = [...serviceAccounts.values()].map(({ token: _, ...s }) => s);
    res.json(list);
  });

  app.post('/api/service-accounts', (req, res) => {
    const { name, scopes, description } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });
    const id = `sa-${Date.now()}`;
    const saData = { name, permissions: scopes ?? [] };
    const token = jwt.sign(
      {
        sub: id,
        type: 'service_account',
        name: saData.name,
        permissions: saData.permissions,
        iss: 'opendirectory',
        aud: 'opendirectory-services',
      },
      JWT_SECRET,
      { expiresIn: '90d', algorithm: 'HS256' }
    );
    const sa = { id, name, description: description ?? '', scopes: scopes ?? [], createdAt: new Date().toISOString(), token };
    serviceAccounts.set(id, sa);
    res.status(201).json(sa); // Include token on creation only
  });

  app.delete('/api/service-accounts/:id', (req, res) => {
    if (!serviceAccounts.has(req.params.id)) return res.status(404).json({ error: 'Service account not found' });
    serviceAccounts.delete(req.params.id);
    res.status(204).send();
  });

  app.get('/api/service-accounts/:id/token', (req, res) => {
    const sa = serviceAccounts.get(req.params.id);
    if (!sa) return res.status(404).json({ error: 'Service account not found' });
    // Issue a fresh short-lived JWT rather than returning the stored token
    const freshToken = jwt.sign(
      { sub: sa.id, type: 'service_account', name: sa.name, permissions: sa.scopes || [], iss: 'opendirectory', aud: 'opendirectory-services' },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.json({ token: freshToken, expiresIn: '24h' });
  });

  // ─── Bulk Import ──────────────────────────────────────────────────────────────

  app.post('/api/users/bulk-import', async (req, res) => {
    const { users } = req.body;
    if (!Array.isArray(users)) return res.status(400).json({ error: 'users array required' });
    const errors = [];
    const createdUsers = [];
    for (const [i, u] of users.entries()) {
      if (!u.name || !u.email) {
        errors.push({ index: i, error: 'name and email required', entry: u });
        continue;
      }
      const id = `user-${Date.now()}-${i}`;
      const username = u.username || u.email.split('@')[0];
      const userRecord = {
        id,
        userName: u.email,
        username,
        displayName: u.name,
        name: u.name,
        email: u.email,
        emails: [{ value: u.email, primary: true }],
        active: true,
        role: u.role ?? 'user',
        group: u.group ?? null,
        createdAt: new Date().toISOString(),
      };
      scimUsers.set(id, userRecord);
      createdUsers.push(userRecord);
    }

    // Try to sync to LLDAP via GraphQL API
    const LLDAP_URL = process.env.LLDAP_URL || 'http://localhost:3890';
    const LLDAP_ADMIN = process.env.LLDAP_ADMIN_USER || 'admin';
    const LLDAP_PASS = process.env.LLDAP_ADMIN_PASSWORD || process.env.LLDAP_ADMIN_PASS || '';
    const lldapSynced = [];
    const lldapErrors = [];

    for (const user of createdUsers) {
      try {
        const lldapRes = await fetch(`${LLDAP_URL}/api/graphql`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Basic ${Buffer.from(`${LLDAP_ADMIN}:${LLDAP_PASS}`).toString('base64')}`,
          },
          body: JSON.stringify({
            query: `mutation CreateUser($user: CreateUserInput!) { createUser(user: $user) { id } }`,
            variables: {
              user: {
                id: user.username,
                email: user.email || `${user.username}@opendirectory.local`,
                displayName: user.name || user.username,
              }
            }
          })
        });
        if (lldapRes.ok) {
          lldapSynced.push(user.username);
        }
      } catch (err) {
        lldapErrors.push({ username: user.username, error: err.message });
      }
    }

    res.status(207).json({ created: createdUsers.length, errors, lldapSynced, lldapErrors });
  });

  // ─── Domain Config ────────────────────────────────────────────────────────────

  app.post('/api/config/domain', (req, res) => {
    const authHeader = req.headers['authorization'] ?? '';
    if (!authHeader || !authHeader.trim()) {
      return res.status(401).json({ error: 'Authorization: Bearer token required' });
    }
    const { domain, issuer } = req.body;
    if (!domain) return res.status(400).json({ error: 'domain required' });
    // Store in memory (production: write to DB/config file)
    global.__od_domain_config = { domain, issuer, configuredAt: new Date().toISOString() };
    res.json({ success: true, domain, issuer });
  });

  app.get('/api/config/domain', (req, res) => {
    const authHeader = req.headers['authorization'] ?? '';
    if (!authHeader || !authHeader.trim()) {
      return res.status(401).json({ error: 'Authorization: Bearer token required' });
    }
    res.json(global.__od_domain_config || { domain: null, issuer: null });
  });

  // ─── Audit log endpoints ──────────────────────────────────────────────────────
  app.get('/api/audit/events', async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 20;
      const events = await auditDb.getRecentEvents(limit);
      res.json(events);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/audit/log', async (req, res) => {
    const { eventType, actor, target, message, severity, metadata } = req.body;
    if (!message) return res.status(400).json({ error: 'message required' });
    const ip = req.ip || req.connection?.remoteAddress;
    await auditDb.logAuditEvent({ eventType: eventType || 'manual', actor, target, message, severity, ipAddress: ip, metadata });
    res.json({ success: true });
  });

  // ─── TOTP MFA Endpoints ───────────────────────────────────────────────────────

  let speakeasy, QRCode;
  try { speakeasy = require('speakeasy'); } catch (_) {}
  try { QRCode = require('qrcode'); } catch (_) {}

  // Expose for login handler (class scope cannot access IIFE-scope Maps directly)
  global.__od_userMfaSecrets = userMfaSecrets;
  global.__od_speakeasy = speakeasy;

  // Middleware: require JWT auth for MFA management endpoints
  const requireJwt = authService.requireAuth();

  app.post('/api/auth/mfa/setup', requireJwt, async (req, res) => {
    if (!speakeasy) return res.status(501).json({ error: 'TOTP library not installed' });
    const userId = req.user?.id || req.user?.userId;
    const secret = speakeasy.generateSecret({ name: `OpenDirectory (${req.user?.username || userId})`, issuer: 'OpenDirectory', length: 20 });
    pendingMfaSecrets.set(userId, secret.base32);
    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);
    res.json({ secret: secret.base32, qrDataUrl, otpauthUrl: secret.otpauth_url });
  });

  app.post('/api/auth/mfa/verify-setup', requireJwt, async (req, res) => {
    if (!speakeasy) return res.status(501).json({ error: 'TOTP library not installed' });
    const { token } = req.body;
    const userId = req.user?.id || req.user?.userId;
    const secret = pendingMfaSecrets.get(userId);
    if (!secret) return res.status(400).json({ error: 'No pending MFA setup' });
    const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 2 });
    if (!valid) return res.status(400).json({ error: 'Ungültiger Code' });
    userMfaSecrets.set(userId, secret);
    pendingMfaSecrets.delete(userId);
    try { publish('identity.mfa.enabled', { userId, method: 'totp' }); } catch (e) {}
    res.json({ success: true, message: 'MFA aktiviert' });
  });

  app.post('/api/auth/mfa/validate', async (req, res) => {
    if (!speakeasy) return res.status(501).json({ error: 'TOTP library not installed' });
    const { userId, token } = req.body;
    if (!userId || !token) return res.status(400).json({ error: 'userId and token required' });
    const secret = userMfaSecrets.get(userId);
    if (!secret) return res.status(400).json({ error: 'MFA not configured for user' });
    const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 2 });
    if (!valid) return res.status(401).json({ error: 'Ungültiger TOTP-Code' });
    res.json({ valid: true });
  });

  app.delete('/api/auth/mfa/disable', requireJwt, (req, res) => {
    const userId = req.user?.id || req.user?.userId;
    userMfaSecrets.delete(userId);
    pendingMfaSecrets.delete(userId);
    res.json({ success: true });
  });

  app.get('/api/auth/mfa/status', requireJwt, (req, res) => {
    const userId = req.user?.id || req.user?.userId;
    res.json({ enabled: userMfaSecrets.has(userId) });
  });

  // ─── Account Lockout Admin Endpoints ─────────────────────────────────────────

  app.get('/api/auth/lockouts', authService.requireAdmin(), (req, res) => {
    const locked = [];
    for (const [username, att] of loginAttempts.entries()) {
      if (att.lockedUntil && att.lockedUntil > Date.now()) {
        locked.push({ username, lockedUntil: new Date(att.lockedUntil).toISOString(), remaining: Math.ceil((att.lockedUntil - Date.now()) / 60000) });
      }
    }
    res.json(locked);
  });

  app.delete('/api/auth/lockouts/:username', authService.requireAdmin(), (req, res) => {
    loginAttempts.delete(req.params.username);
    res.json({ success: true });
  });

  // ─── DNS Management ───────────────────────────────────────────────────────────
  // In-memory DNS record store (production: use PowerDNS/Bind API)
  const dnsRecords = new Map();

  // Helper: require Bearer token
  const requireBearer = (req, res, next) => {
    const authHeader = req.headers['authorization'] ?? '';
    if (!authHeader.trim()) return res.status(401).json({ error: 'Authorization: Bearer token required' });
    next();
  };

  const { v4: uuidv4 } = require('uuid');

  // Seed some defaults
  ['opendirectory.local', 'auth.opendirectory.local', 'ldap.opendirectory.local', 'ca.opendirectory.local'].forEach((name, i) => {
    dnsRecords.set(name, { id: `dns-${i+1}`, name, type: 'A', value: `192.168.1.${10+i}`, ttl: 300, zone: 'opendirectory.local', createdAt: new Date().toISOString() });
  });

  app.get('/api/dns/records', requireBearer, (req, res) => {
    const records = [...dnsRecords.values()];
    const zone = req.query.zone;
    res.json(zone ? records.filter(r => r.zone === zone) : records);
  });

  app.post('/api/dns/records', requireBearer, (req, res) => {
    const { name, type, value, ttl = 300, zone } = req.body;
    if (!name || !type || !value) return res.status(400).json({ error: 'name, type, value required' });
    const VALID_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'PTR'];
    if (!VALID_TYPES.includes(type.toUpperCase())) return res.status(400).json({ error: `Invalid type. Valid: ${VALID_TYPES.join(', ')}` });
    const id = `dns-${uuidv4().slice(0,8)}`;
    const record = { id, name: name.toLowerCase(), type: type.toUpperCase(), value, ttl, zone: zone || name.split('.').slice(-2).join('.'), createdAt: new Date().toISOString() };
    dnsRecords.set(name.toLowerCase(), record);
    res.status(201).json(record);
  });

  app.put('/api/dns/records/:name', requireBearer, (req, res) => {
    const record = dnsRecords.get(req.params.name.toLowerCase());
    if (!record) return res.status(404).json({ error: 'Record not found' });
    Object.assign(record, req.body, { updatedAt: new Date().toISOString() });
    dnsRecords.set(record.name, record);
    res.json(record);
  });

  app.delete('/api/dns/records/:name', requireBearer, (req, res) => {
    if (!dnsRecords.has(req.params.name.toLowerCase())) return res.status(404).json({ error: 'Not found' });
    dnsRecords.delete(req.params.name.toLowerCase());
    res.json({ success: true });
  });

  app.get('/api/dns/zones', requireBearer, (req, res) => {
    const zones = [...new Set([...dnsRecords.values()].map(r => r.zone))];
    res.json(zones.map(z => ({ zone: z, recordCount: [...dnsRecords.values()].filter(r => r.zone === z).length })));
  });

  // ─── PIM (Privileged Identity Management) ────────────────────────────────────
  // In-memory stores (PostgreSQL used when available via auditDb pool)

  const pimRoles = new Map();
  const pimRequests = new Map();

  // Seed demo PIM roles
  const pimRoleSeed = [
    {
      id: uuidv4(),
      name: 'Server-Administrator',
      description: 'Temporärer Root-Zugriff auf Server-Gruppe',
      target_group_id: 'grp-servers',
      target_group_name: 'Server-Admins',
      max_duration_hours: 4,
      requires_approval: true,
      approver_group_id: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
    {
      id: uuidv4(),
      name: 'Helpdesk-Elevated',
      description: 'Erweiterte Helpdesk-Rechte ohne Genehmigung',
      target_group_id: 'grp-helpdesk',
      target_group_name: 'Helpdesk-Team',
      max_duration_hours: 8,
      requires_approval: false,
      approver_group_id: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];
  pimRoleSeed.forEach(r => pimRoles.set(r.id, r));

  // Helper: load PIM roles (DB first, fallback to in-memory)
  async function getPimRolesFromDb() {
    if (!auditDb.isAvailable()) return null;
    try {
      const r = await auditDb.query('SELECT * FROM pim_roles ORDER BY created_at');
      return r.rows;
    } catch { return null; }
  }

  async function getPimRequestsFromDb(filters = {}) {
    if (!auditDb.isAvailable()) return null;
    try {
      const conditions = [];
      const vals = [];
      let idx = 1;
      if (filters.status) { conditions.push(`status=$${idx++}`); vals.push(filters.status); }
      if (filters.userId) { conditions.push(`user_id=$${idx++}`); vals.push(filters.userId); }
      const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
      const r = await auditDb.query(`SELECT * FROM pim_requests ${where} ORDER BY requested_at DESC`, vals);
      return r.rows;
    } catch { return null; }
  }

  // ── PIM Roles (admin) ───────────────────────────────────────────────────────

  app.get('/api/pim/roles', requireBearer, async (req, res) => {
    const dbRows = await getPimRolesFromDb();
    if (dbRows) return res.json(dbRows);
    res.json([...pimRoles.values()]);
  });

  app.post('/api/pim/roles', requireBearer, async (req, res) => {
    const { name, description, target_group_id, target_group_name, max_duration_hours, requires_approval, approver_group_id } = req.body;
    if (!name || !target_group_id) return res.status(400).json({ error: 'name and target_group_id required' });
    const now = new Date().toISOString();
    const id = uuidv4();
    const role = {
      id,
      name,
      description: description ?? null,
      target_group_id,
      target_group_name: target_group_name ?? null,
      max_duration_hours: max_duration_hours ?? 8,
      requires_approval: requires_approval !== false,
      approver_group_id: approver_group_id ?? null,
      created_at: now,
      updated_at: now,
    };
    if (auditDb.isAvailable()) {
      try {
        await auditDb.query(
          `INSERT INTO pim_roles(id,name,description,target_group_id,target_group_name,max_duration_hours,requires_approval,approver_group_id)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
          [id, name, role.description, target_group_id, role.target_group_name, role.max_duration_hours, role.requires_approval, role.approver_group_id]
        );
      } catch (err) { return res.status(500).json({ error: err.message }); }
    }
    pimRoles.set(id, role);
    res.status(201).json(role);
  });

  app.put('/api/pim/roles/:id', requireBearer, async (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    const now = new Date().toISOString();
    if (auditDb.isAvailable()) {
      try {
        const fields = [];
        const vals = [];
        let idx = 1;
        const allowed = ['name','description','target_group_id','target_group_name','max_duration_hours','requires_approval','approver_group_id'];
        for (const key of allowed) {
          if (updates[key] !== undefined) { fields.push(`${key}=$${idx++}`); vals.push(updates[key]); }
        }
        fields.push(`updated_at=$${idx++}`); vals.push(now);
        vals.push(id);
        if (fields.length > 1) {
          const r = await auditDb.query(`UPDATE pim_roles SET ${fields.join(',')} WHERE id=$${idx} RETURNING *`, vals);
          if (r.rows.length === 0) return res.status(404).json({ error: 'Role not found' });
          return res.json(r.rows[0]);
        }
      } catch (err) { return res.status(500).json({ error: err.message }); }
    }
    const role = pimRoles.get(id);
    if (!role) return res.status(404).json({ error: 'Role not found' });
    Object.assign(role, updates, { updated_at: now });
    res.json(role);
  });

  app.delete('/api/pim/roles/:id', requireBearer, async (req, res) => {
    const { id } = req.params;
    if (auditDb.isAvailable()) {
      try {
        await auditDb.query('DELETE FROM pim_roles WHERE id=$1', [id]);
      } catch (err) { return res.status(500).json({ error: err.message }); }
    }
    pimRoles.delete(id);
    res.status(204).send();
  });

  // ── PIM Requests (user + admin) ─────────────────────────────────────────────

  app.get('/api/pim/requests', requireBearer, async (req, res) => {
    const { status, userId } = req.query;
    const dbRows = await getPimRequestsFromDb({ status, userId });
    if (dbRows) return res.json(dbRows);
    let list = [...pimRequests.values()];
    if (status) list = list.filter(r => r.status === status);
    if (userId) list = list.filter(r => r.user_id === userId);
    list.sort((a, b) => new Date(b.requested_at) - new Date(a.requested_at));
    res.json(list);
  });

  app.post('/api/pim/requests', requireBearer, async (req, res) => {
    const { role_id, justification, requested_duration_hours, user_id, user_name, user_email } = req.body;
    if (!role_id) return res.status(400).json({ error: 'role_id required' });

    // Resolve role
    let role = null;
    if (auditDb.isAvailable()) {
      try {
        const r = await auditDb.query('SELECT * FROM pim_roles WHERE id=$1', [role_id]);
        if (r.rows.length > 0) role = r.rows[0];
      } catch {}
    }
    if (!role) role = pimRoles.get(role_id);
    if (!role) return res.status(404).json({ error: 'PIM role not found' });

    const now = new Date();
    const duration = Math.min(requested_duration_hours ?? 4, role.max_duration_hours);
    const autoApprove = !role.requires_approval;
    const id = uuidv4();

    const request = {
      id,
      user_id: user_id ?? 'unknown',
      user_name: user_name ?? null,
      user_email: user_email ?? null,
      role_id,
      role_name: role.name,
      justification: justification ?? null,
      requested_duration_hours: duration,
      status: autoApprove ? 'active' : 'pending',
      requested_at: now.toISOString(),
      decided_at: autoApprove ? now.toISOString() : null,
      decided_by: autoApprove ? 'system' : null,
      activated_at: autoApprove ? now.toISOString() : null,
      expires_at: autoApprove ? new Date(now.getTime() + duration * 3600_000).toISOString() : null,
      revoked_at: null,
      revoked_by: null,
    };

    if (auditDb.isAvailable()) {
      try {
        await auditDb.query(
          `INSERT INTO pim_requests(id,user_id,user_name,user_email,role_id,role_name,justification,requested_duration_hours,status,decided_at,decided_by,activated_at,expires_at)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
          [id, request.user_id, request.user_name, request.user_email, role_id, role.name, request.justification, duration, request.status, request.decided_at, request.decided_by, request.activated_at, request.expires_at]
        );
      } catch (err) { return res.status(500).json({ error: err.message }); }
    }
    pimRequests.set(id, request);
    res.status(201).json(request);
  });

  app.post('/api/pim/requests/:id/approve', requireBearer, async (req, res) => {
    const { id } = req.params;
    const { decided_by } = req.body;
    const now = new Date();

    let request = null;
    if (auditDb.isAvailable()) {
      try {
        const r = await auditDb.query('SELECT * FROM pim_requests WHERE id=$1', [id]);
        if (r.rows.length > 0) request = r.rows[0];
      } catch {}
    }
    if (!request) request = pimRequests.get(id);
    if (!request) return res.status(404).json({ error: 'Request not found' });
    if (request.status !== 'pending') return res.status(400).json({ error: `Cannot approve request with status '${request.status}'` });

    const duration = request.requested_duration_hours;
    const expiresAt = new Date(now.getTime() + duration * 3600_000).toISOString();
    const decider = decided_by ?? 'admin';

    if (auditDb.isAvailable()) {
      try {
        const r = await auditDb.query(
          `UPDATE pim_requests SET status='active', decided_at=$1, decided_by=$2, activated_at=$1, expires_at=$3 WHERE id=$4 RETURNING *`,
          [now.toISOString(), decider, expiresAt, id]
        );
        if (r.rows.length > 0) {
          const updated = r.rows[0];
          pimRequests.set(id, { ...pimRequests.get(id), ...updated });
          try { publish('security.pim.granted', { userId: request.user_id, roleId: request.role_id, duration: request.requested_duration_hours, approvedBy: decider }); } catch (e) {}
          return res.json(updated);
        }
      } catch (err) { return res.status(500).json({ error: err.message }); }
    }
    Object.assign(request, { status: 'active', decided_at: now.toISOString(), decided_by: decider, activated_at: now.toISOString(), expires_at: expiresAt });
    try { publish('security.pim.granted', { userId: request.user_id, roleId: request.role_id, duration: request.requested_duration_hours, approvedBy: decider }); } catch (e) {}
    res.json(request);
  });

  app.post('/api/pim/requests/:id/deny', requireBearer, async (req, res) => {
    const { id } = req.params;
    const { decided_by } = req.body;
    const now = new Date().toISOString();

    let request = null;
    if (auditDb.isAvailable()) {
      try {
        const r = await auditDb.query('SELECT * FROM pim_requests WHERE id=$1', [id]);
        if (r.rows.length > 0) request = r.rows[0];
      } catch {}
    }
    if (!request) request = pimRequests.get(id);
    if (!request) return res.status(404).json({ error: 'Request not found' });
    if (request.status !== 'pending') return res.status(400).json({ error: `Cannot deny request with status '${request.status}'` });

    const decider = decided_by ?? 'admin';
    if (auditDb.isAvailable()) {
      try {
        const r = await auditDb.query(
          `UPDATE pim_requests SET status='denied', decided_at=$1, decided_by=$2 WHERE id=$3 RETURNING *`,
          [now, decider, id]
        );
        if (r.rows.length > 0) {
          const updated = r.rows[0];
          pimRequests.set(id, { ...pimRequests.get(id), ...updated });
          return res.json(updated);
        }
      } catch (err) { return res.status(500).json({ error: err.message }); }
    }
    Object.assign(request, { status: 'denied', decided_at: now, decided_by: decider });
    res.json(request);
  });

  app.post('/api/pim/requests/:id/revoke', requireBearer, async (req, res) => {
    const { id } = req.params;
    const { revoked_by } = req.body;
    const now = new Date().toISOString();

    let request = null;
    if (auditDb.isAvailable()) {
      try {
        const r = await auditDb.query('SELECT * FROM pim_requests WHERE id=$1', [id]);
        if (r.rows.length > 0) request = r.rows[0];
      } catch {}
    }
    if (!request) request = pimRequests.get(id);
    if (!request) return res.status(404).json({ error: 'Request not found' });
    if (request.status !== 'active') return res.status(400).json({ error: `Cannot revoke request with status '${request.status}'` });

    const revoker = revoked_by ?? 'admin';
    if (auditDb.isAvailable()) {
      try {
        const r = await auditDb.query(
          `UPDATE pim_requests SET status='revoked', revoked_at=$1, revoked_by=$2 WHERE id=$3 RETURNING *`,
          [now, revoker, id]
        );
        if (r.rows.length > 0) {
          const updated = r.rows[0];
          pimRequests.set(id, { ...pimRequests.get(id), ...updated });
          return res.json(updated);
        }
      } catch (err) { return res.status(500).json({ error: err.message }); }
    }
    Object.assign(request, { status: 'revoked', revoked_at: now, revoked_by: revoker });
    res.json(request);
  });

  app.get('/api/pim/activations', requireBearer, async (req, res) => {
    const now = new Date().toISOString();
    if (auditDb.isAvailable()) {
      try {
        const r = await auditDb.query(
          `SELECT * FROM pim_requests WHERE status='active' AND expires_at > $1 ORDER BY activated_at DESC`,
          [now]
        );
        return res.json(r.rows);
      } catch {}
    }
    const active = [...pimRequests.values()].filter(r => r.status === 'active' && r.expires_at && r.expires_at > now);
    active.sort((a, b) => new Date(b.activated_at) - new Date(a.activated_at));
    res.json(active);
  });

  app.post('/api/pim/expire', requireBearer, async (req, res) => {
    const now = new Date().toISOString();
    let expiredCount = 0;
    if (auditDb.isAvailable()) {
      try {
        const r = await auditDb.query(
          `UPDATE pim_requests SET status='expired' WHERE status='active' AND expires_at < $1`,
          [now]
        );
        expiredCount = r.rowCount ?? 0;
        // Sync expired ones to in-memory store
        const expired = await auditDb.query(`SELECT id FROM pim_requests WHERE status='expired' AND expires_at < $1`, [now]);
        expired.rows.forEach(row => {
          const req = pimRequests.get(row.id);
          if (req) req.status = 'expired';
        });
        return res.json({ expired: expiredCount });
      } catch (err) { return res.status(500).json({ error: err.message }); }
    }
    for (const request of pimRequests.values()) {
      if (request.status === 'active' && request.expires_at && request.expires_at < now) {
        request.status = 'expired';
        expiredCount++;
      }
    }
    res.json({ expired: expiredCount });
  });
})();
