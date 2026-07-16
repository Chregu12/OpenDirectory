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

const { createProvider } = require('./oidc/provider');
const { buildInteractionsRouter } = require('./oidc/interactions');

// ─── DDD Infrastructure ────────────────────────────────────────────────────────
const PostgresUserRepository = require('./infrastructure/repositories/PostgresUserRepository');
const AuthApplicationService = require('./application/AuthApplicationService');
const PasswordApplicationService = require('./application/PasswordApplicationService');
const InMemoryTtlCache = require('./infrastructure/cache/InMemoryTtlCache');

const logger = require('./utils/logger');
const config = require('./utils/config');

// ─── Route modules ─────────────────────────────────────────────────────────────
const { createAuthRoutes }      = require('./routes/auth');
const { createUserRoutes }      = require('./routes/users');
const { createMfaRoutes }       = require('./routes/mfa');
const { createSessionRoutes }   = require('./routes/sessions');
const { createSsoRoutes }       = require('./routes/sso');
const { createAuditRoutes }     = require('./routes/audit');
const { createZeroTrustRoutes } = require('./routes/zeroTrust');


class UnifiedAuthenticationService {
  constructor() {
    this.app = express();

    // ─── DDD Repository ──────────────────────────────────────────────────────
    // Create a lazy DB adapter: PostgresUserRepository calls db.query() which
    // will require('../db') on first use.  This avoids a hard startup failure
    // when the database is not yet available.
    const dbAdapter = {
      query: async (sql, params) => {
        const db = require('./db');
        return db.query(sql, params);
      },
    };
    this.userRepository = new PostgresUserRepository(dbAdapter);

    // ─── DDD Application Service ─────────────────────────────────────────────
    this.authAppService = new AuthApplicationService({
      userRepository: this.userRepository,
      sessionRepository: null,
      messageBus: null,
      config: { jwtSecret: process.env.JWT_SECRET || config.jwt.secret },
      logger,
    });

    // Password-reset tokens: kept in-process (matches the legacy Map-based
    // behavior it replaces) — see InMemoryTtlCache. tokenGenerator preserves
    // the exact 32-byte-hex token format the HTTP layer used to mint itself.
    this.passwordResetCache = new InMemoryTtlCache();
    this.passwordAppService = new PasswordApplicationService({
      userRepository: this.userRepository,
      cache: this.passwordResetCache,
      messageBus: null,
      logger,
      tokenGenerator: () => require('crypto').randomBytes(32).toString('hex'),
    });

    // ─── Legacy Services (now repository-aware) ──────────────────────────────
    this.authManager = new AuthenticationManager({
      userRepository: this.userRepository,
      logger,
    });
    this.tokenService = new TokenService();
    this.mfaService = new MFAService();
    this.zeroTrust = new ZeroTrustService();
    this.sessionManager = new SessionManager();
    this.userService = new UserService({
      userRepository: this.userRepository,
      logger,
    });
    this.auditService = new AuditService();

    // OIDC provider is initialized asynchronously in start()
    this.oidcProvider = null;

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
        // Prefer DDD AuthApplicationService; fall back to legacy manager.
        let user;
        try {
          const result = await this.authAppService.login({
            username,
            password,
            ip: req.ip,
            userAgent: req.headers['user-agent'],
          });
          user = result ? result.user : null;
        } catch (appServiceErr) {
          // AuthApplicationService throws on invalid credentials (401/403) —
          // treat as authentication failure rather than a system error.
          if (appServiceErr.status === 401 || appServiceErr.status === 403) {
            user = null;
          } else {
            // DB unavailable or other infrastructure error — fall back to legacy
            logger.warn('AuthApplicationService.login failed, falling back to legacy:', appServiceErr.message);
            user = await this.authManager.authenticateLocal(username, password);
          }
        }

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

  /**
   * Mount OIDC-related middleware and endpoints.
   * Called after the provider has been instantiated in start().
   * @param {import('node-oidc-provider').Provider} oidcProvider
   */
  mountOidcRoutes(oidcProvider) {
    // Interactions router MUST be mounted before the provider callback
    // so that /interaction/* routes are handled by Express, not the provider.
    const interactionsRouter = buildInteractionsRouter(oidcProvider, {
      authManager: this.authManager,
      userService: this.userService,
      auditService: this.auditService,
    });
    this.app.use(interactionsRouter);

    // Mount the OIDC provider — this registers all standard endpoints:
    //   /authorize, /token, /userinfo, /jwks,
    //   /.well-known/openid-configuration, /end_session, /introspect, /revoke
    this.app.use(oidcProvider.callback());

    logger.info('OIDC provider mounted (issuer: ' + oidcProvider.issuer + ')');
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

    // Build services bag passed to every route factory.
    // Auth middleware factories are included so route modules can apply them.
    const services = {
      authManager:        this.authManager,
      tokenService:       this.tokenService,
      mfaService:         this.mfaService,
      zeroTrust:          this.zeroTrust,
      sessionManager:     this.sessionManager,
      userService:        this.userService,
      auditService:       this.auditService,
      passwordAppService: this.passwordAppService,
      requireAuth:        () => this.requireAuth(),
      requireAdmin:       () => this.requireAdmin(),
    };

    // NOTE: /api/auth/login is kept for backwards-compatible direct API access.
    //       New clients should use the OIDC /authorize flow instead.

    // Core auth routes (login, logout, refresh, validate)
    this.app.use(createAuthRoutes(services));

    // MFA routes (setup, verify, disable, recovery-codes)
    this.app.use(createMfaRoutes(services));

    // Zero-trust routes (verify-device, verify-location, trust-score, step-up)
    this.app.use(createZeroTrustRoutes(services));

    // Session management routes
    this.app.use(createSessionRoutes(services));

    // SSO / LDAP federation routes
    this.app.use(createSsoRoutes(services));

    // User management routes (profile, register, password, admin CRUD)
    this.app.use(createUserRoutes(services));

    // Audit log routes
    this.app.use(createAuditRoutes(services));

    // Error handling
    this.app.use(this.errorHandler.bind(this));
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

  async start(port = process.env.PORT || 3001) {
    // Initialize the OIDC provider before accepting connections
    const issuer = process.env.ISSUER_URL || `http://localhost:${port}`;
    try {
      this.oidcProvider = await createProvider(issuer);
      this.mountOidcRoutes(this.oidcProvider);
      logger.info(`OIDC issuer: ${issuer}`);
    } catch (err) {
      logger.error('Failed to initialize OIDC provider:', err);
      throw err;
    }

    this.server = this.app.listen(port, () => {
      logger.info(`Unified Authentication Service started on port ${port}`);
      logger.info(`Health check: http://localhost:${port}/health`);
      logger.info(`OIDC discovery: ${issuer}/.well-known/openid-configuration`);
      logger.info(`Auth providers: Local, LDAP, JWT, SSO, OIDC`);
      logger.info(`Zero-Trust: ${config.zeroTrust.enabled ? 'Enabled' : 'Disabled'}`);
      logger.info(`MFA: ${config.mfa.enabled ? 'Enabled' : 'Disabled'}`);
    });
  }

  stop() {
    if (this.server) this.server.close(() => logger.info('Authentication service stopped'));
  }
}

// Start the service
const authService = new UnifiedAuthenticationService();
authService.start().catch((err) => {
  // Use console.error as a fallback in case logger is not yet initialized
  (typeof logger !== 'undefined' ? logger.error : console.error)('Fatal startup error:', err);
  process.exit(1);
});

function shutdown(signal) {
  logger.info(`Received ${signal}, shutting down gracefully`);
  authService.stop();
  setTimeout(() => { logger.error('Forced shutdown after timeout'); process.exit(1); }, 10000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
