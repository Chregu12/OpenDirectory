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

const {localAuthentication}=require('./localAuthentication');

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
const { createPimRoutes }             = require('./routes/pim');
const { createServiceAccountRoutes }  = require('./routes/serviceAccounts');
const { createDirectoryRoutes }       = require('./routes/directory');


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
    const redisClient = require('./utils/redisClient').redisClient();
    this.redisClient=redisClient;

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
    }, localAuthentication(this)));

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
    this.app.use(require('./EmployeeInvitationRoutes').employeeInvitationRoutes(require('./db')));
    this.app.use(/^\/(?:\.well-known\/openid-configuration|authorize|auth|token|userinfo|me|jwks|end_session|session\/end|introspect|revoke|interaction)(?=\/|$)/,(_req,res)=>{
      res.set('Cache-Control','no-store').status(410).json({error:'legacy_oidc_retired',message:'Use the configured central oauth-provider issuer.'});
    });
    // Health check
    this.app.get('/health', async (req, res) => {
      const db=require('./db');let ready=db.isAvailable();
      try{if(ready)await db.query('SELECT record_revision,is_locked FROM users LIMIT 0');}catch{ready=false;}
      res.status(ready?200:503).json({
        status: ready?'healthy':'unavailable',
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
    //       New clients use the central oauth-provider /oauth/authorize flow.

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

    // PIM (Privileged Identity Management) routes — real requireBearerAuth
    // (JWT verification), DB-first with in-memory fallback (see
    // src/routes/pim.js for restoration notes).
    this.app.use(createPimRoutes(services));

    // Service account routes — real requireBearerAuth, in-memory persistence
    // (see src/routes/serviceAccounts.js for restoration notes).
    this.app.use(createServiceAccountRoutes(services));

    // Directory routes: domain configuration only — real requireBearerAuth
    // (see src/routes/directory.js for restoration notes). OUs used to live
    // here too; they moved to identity-service to resolve a namespace
    // collision — see the NOTE at the top of src/routes/directory.js.
    this.app.use(createDirectoryRoutes(services));

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

  async start(port = process.env.PORT || 3002) {
    const db = require('./db');
    await db.initDb();

    this.server = this.app.listen(port, () => {
      logger.info(`Unified Authentication Service started on port ${port}`);
      logger.info(`Health check: http://localhost:${port}/health`);
      logger.info('Credential providers: Local, LDAP; OIDC/SAML use the central oauth-provider');
      logger.info(`Zero-Trust: ${config.zeroTrust.enabled ? 'Enabled' : 'Disabled'}`);
      logger.info(`MFA: ${config.mfa.enabled ? 'Enabled' : 'Disabled'}`);
    });
  }

  async stop() {
    if(this.server)await new Promise((resolve,reject)=>this.server.close(error=>error?reject(error):resolve()));
    await Promise.allSettled([this.redisClient,this.tokenService._redisClient,this.sessionManager._redisClient].filter(Boolean).map(client=>client.quit()));
    await require('./db').close();
    logger.info('Authentication service stopped');
  }
}

// Start the service
const authService = new UnifiedAuthenticationService();
authService.start().catch((err) => {
  // Use console.error as a fallback in case logger is not yet initialized
  (typeof logger !== 'undefined' ? logger.error : console.error)('Fatal startup error:', err);
  process.exit(1);
});

async function shutdown(signal) {
  logger.info(`Received ${signal}, shutting down gracefully`);
  const timer=setTimeout(() => { logger.error('Forced shutdown after timeout'); process.exit(1); }, 10000);
  try{await authService.stop();clearTimeout(timer);}catch{logger.error('Authentication shutdown failed');process.exit(1);}
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

module.exports = UnifiedAuthenticationService;
// Expose the module-level singleton so tests (and any other in-process
// consumers) can reach the fully wired instance without triggering a second
// startup/listen cycle.
module.exports._instance = authService;
