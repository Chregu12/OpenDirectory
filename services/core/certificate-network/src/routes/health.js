/**
 * OpenDirectory Certificate & Network Service Health Check Routes
 */

const express = require('express');
const router = express.Router();
const { logger } = require('../utils/logger');

// Main health check endpoint
router.get('/', async (req, res) => {
  try {
    // Get the main service instance from app context
    const service = req.app.locals.service || req.app.service;
    
    let health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'certificate-network'
    };

    if (service && typeof service.healthCheck === 'function') {
      health = await service.healthCheck();
    }

    const statusCode = health.status === 'healthy' ? 200 : 
                      health.status === 'degraded' ? 200 : 503;

    res.status(statusCode).json(health);

  } catch (error) {
    logger.error('Health check error:', error);
    
    res.status(503).json({
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString(),
      service: 'certificate-network'
    });
  }
});

// Detailed health check with component status
router.get('/detailed', async (req, res) => {
  try {
    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'certificate-network',
      version: '1.0.0',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      components: {}
    };

    // Check core services
    if (req.services) {
      for (const [name, service] of Object.entries(req.services)) {
        try {
          if (typeof service.healthCheck === 'function') {
            health.components[name] = await service.healthCheck();
          } else if (typeof service.getStatus === 'function') {
            health.components[name] = service.getStatus();
          } else {
            health.components[name] = { status: 'unknown' };
          }
        } catch (error) {
          health.components[name] = { status: 'unhealthy', error: error.message };
          if (health.status === 'healthy') health.status = 'degraded';
        }
      }
    }

    // Check Enterprise Directory integration
    if (req.integrationManager) {
      try {
        health.integration = await req.integrationManager.healthCheck();
        if (health.integration.status === 'unhealthy' && health.status === 'healthy') {
          health.status = 'degraded';
        }
      } catch (error) {
        health.integration = { status: 'unhealthy', error: error.message };
        if (health.status === 'healthy') health.status = 'degraded';
      }
    } else {
      health.integration = { status: 'disabled' };
    }

    const statusCode = health.status === 'healthy' ? 200 : 
                      health.status === 'degraded' ? 200 : 503;

    res.status(statusCode).json(health);

  } catch (error) {
    logger.error('Detailed health check error:', error);
    
    res.status(503).json({
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString(),
      service: 'certificate-network'
    });
  }
});

// Integration status endpoint
router.get('/integration', async (req, res) => {
  try {
    if (!req.integrationManager) {
      return res.json({
        status: 'disabled',
        message: 'Enterprise Directory integration not configured'
      });
    }

    const integrationStatus = req.integrationManager.getStatus();
    const healthCheck = await req.integrationManager.healthCheck();

    res.json({
      ...integrationStatus,
      health: healthCheck,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Integration status check error:', error);
    
    res.status(500).json({
      status: 'error',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Liveness probe (simple check)
router.get('/live', (req, res) => {
  res.json({
    status: 'alive',
    timestamp: new Date().toISOString(),
    service: 'certificate-network'
  });
});

// Readiness probe (check if service is ready to accept requests)
router.get('/ready', async (req, res) => {
  try {
    // Check if main service is initialized
    const service = req.app.locals.service || req.app.service;
    
    if (!service || !service.isInitialized()) {
      return res.status(503).json({
        status: 'not-ready',
        message: 'Service not fully initialized',
        timestamp: new Date().toISOString()
      });
    }

    res.json({
      status: 'ready',
      timestamp: new Date().toISOString(),
      service: 'certificate-network'
    });

  } catch (error) {
    res.status(503).json({
      status: 'not-ready',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

module.exports = router;