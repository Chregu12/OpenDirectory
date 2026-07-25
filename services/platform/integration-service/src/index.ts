import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import pinoHttp from 'pino-http';
import { register, collectDefaultMetrics } from 'prom-client';

import logger from './lib/logger';
import routes from './routes';
import { API_CONFIG } from './config/services';
import { oidcAuth } from './middleware/oidcAuth';

// Initialize Prometheus metrics collection
collectDefaultMetrics({ register });

const app = express();

// Security middleware
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      frameSrc: ["'self'", "http://localhost:30300", "https:"], // Allow Grafana iframes
    },
  },
}));

// CORS configuration
app.use(cors({
  origin: API_CONFIG.corsOrigins,
  credentials: true,
  optionsSuccessStatus: 200,
}));

// Rate limiting
app.use(rateLimit(API_CONFIG.rateLimit));

// Request logging
app.use(pinoHttp({ logger }));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// OIDC bearer-token auth (see middleware/oidcAuth.ts for the full P0
// rationale). skipPaths is deliberately narrow — only the health-probe
// surface bypasses auth entirely. The service-status/config-discovery routes
// (/api/services, /api/config/*) were deliberately NOT added here even
// though they look like harmless "discovery" endpoints: they disclose which
// internal services exist, their live health, and which platform modules are
// enabled — reconnaissance-grade information an unauthenticated caller must
// not get for free (same reasoning as network-infrastructure's discovery
// routes). Per-route admin gating (requireAdmin) is layered on top inside
// the individual route files for Vault (all routes) and LLDAP (user/group
// CRUD).
app.use(oidcAuth({ skipPaths: ['/health'] }));

// Routes
app.use('/', routes);

// Global error handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  logger.error('Unhandled error:', err);
  
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message,
    timestamp: new Date().toISOString(),
    path: req.path,
    method: req.method,
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString(),
  });
});

// Graceful shutdown handling
const gracefulShutdown = (signal: string) => {
  logger.info(`Received ${signal}. Starting graceful shutdown...`);
  
  server.close(() => {
    logger.info('HTTP server closed.');
    process.exit(0);
  });

  // Force close after 30 seconds
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 30000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Unhandled promise rejection
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Uncaught exception
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

const port = API_CONFIG.port;
const server = app.listen(port, () => {
  logger.info(`OpenDirectory Integration Service started on port ${port}`);
  logger.info('Available services:', {
    lldap: '/api/lldap',
    grafana: '/api/grafana', 
    prometheus: '/api/prometheus',
    vault: '/api/vault',
    health: '/health',
    metrics: '/metrics',
  });
});

// Named export of the underlying http.Server alongside the default app
// export, purely for tests (src/__tests__/*.test.ts): supertest can drive
// `app` directly without needing this, but the test suite needs a handle to
// close the listener the block above opens, so it doesn't leak an open port
// across test files. Nothing else in the codebase imports this module (it's
// only ever run directly via `node dist/index.js`), so this is a safe,
// test-only addition.
export { server };
export default app;