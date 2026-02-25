const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const passport = require('passport');
const rateLimit = require('express-rate-limit');

const AuthenticationManager = require('./services/authenticationManager');
const TokenService = require('./services/tokenService');
const MFAService = require('./services/mfaService');
const ZeroTrustService = require('./services/zeroTrustService');
const SessionManager = require('./services/sessionManager');
const UserService = require('./services/userService');
const AuditService = require('./services/auditService');

const logger = require('./utils/logger');
const config = require('./utils/config');

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
    const authLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // 5 login attempts
      message: 'Too many authentication attempts, please try again later.',
      standardHeaders: true,
      legacyHeaders: false,
      skip: (req) => req.ip === '127.0.0.1', // Skip localhost
    });

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
        const user = await this.authManager.authenticateLocal(username, password);
        if (!user) {
          return done(null, false, { message: 'Invalid credentials' });
        }
        
        // Zero-Trust verification
        const trustScore = await this.zeroTrust.evaluateTrust(req, user);
        if (trustScore < config.zeroTrust.minTrustScore) {
          await this.auditService.logFailedAuth(username, req, 'Low trust score');
          return done(null, false, { message: 'Additional verification required' });
        }
        
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
    this.app.post('/api/auth/login', this.login.bind(this));
    this.app.post('/api/auth/logout', this.logout.bind(this));
    this.app.post('/api/auth/register', this.register.bind(this));
    this.app.post('/api/auth/refresh', this.refreshToken.bind(this));
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
    this.app.post('/api/auth/change-password', this.changePassword.bind(this));
    this.app.post('/api/auth/reset-password', this.resetPassword.bind(this));
    
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
          await this.auditService.logFailedAuth(username, req, info?.message);
          return res.status(401).json({
            error: 'Authentication failed',
            message: info?.message || 'Invalid credentials'
          });
        }
        
        // Check if MFA is required
        if (user.mfaEnabled && !mfaCode) {
          return res.status(200).json({
            requiresMFA: true,
            tempToken: await this.tokenService.generateTempToken(user.id)
          });
        }
        
        // Verify MFA if provided
        if (user.mfaEnabled && mfaCode) {
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
        await this.auditService.logSuccessfulAuth(user.id, req, provider);
        
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
      
      // Create in LDAP if configured
      if (config.ldap.syncNewUsers) {
        await this.authManager.createLdapUser(user);
      }
      
      // Log registration
      await this.auditService.logUserEvent('user_registered', user.id, req);
      
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
      
      await this.userService.changePassword(userId, newPassword);
      await this.sessionManager.revokeAllUserSessions(userId);
      await this.auditService.logSecurityEvent('password_changed', userId, req);
      
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
        const resetToken = await this.tokenService.generatePasswordResetToken(user.id);
        await this.userService.sendPasswordResetEmail(user.email, resetToken);
        await this.auditService.logUserEvent('password_reset_requested', user.id, req);
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
    this.app.listen(port, () => {
      logger.info(`🔐 Unified Authentication Service started on port ${port}`);
      logger.info(`📊 Health check: http://localhost:${port}/health`);
      logger.info(`🔑 Auth providers: Local, LDAP, JWT, SSO`);
      logger.info(`🛡️ Zero-Trust: ${config.zeroTrust.enabled ? 'Enabled' : 'Disabled'}`);
      logger.info(`📱 MFA: ${config.mfa.enabled ? 'Enabled' : 'Disabled'}`);
    });
  }
}

// Start the service
const authService = new UnifiedAuthenticationService();
authService.start();

module.exports = UnifiedAuthenticationService;