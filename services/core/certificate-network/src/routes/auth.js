/**
 * OpenDirectory Certificate & Network Service Authentication Routes
 * Provides authentication endpoints that integrate with Enterprise Directory
 */

const express = require('express');
const router = express.Router();
const { logger } = require('../utils/logger');

// Authenticate user through Enterprise Directory
router.post('/authenticate', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'Username and password are required'
      });
    }

    const clientInfo = {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString()
    };

    // Use Enterprise Directory integration if available
    if (req.integrationManager) {
      const result = await req.integrationManager.authenticateUser(username, password, clientInfo);
      
      if (result.success) {
        logger.info(`User authenticated successfully: ${username}`);
        res.json(result);
      } else {
        logger.warn(`Authentication failed for user: ${username}`);
        res.status(401).json(result);
      }
    } else {
      // Fallback authentication (local only)
      logger.warn('Enterprise Directory integration not available - authentication declined');
      res.status(503).json({
        success: false,
        error: 'Authentication service unavailable'
      });
    }

  } catch (error) {
    logger.error('Authentication error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal authentication error'
    });
  }
});

// Get user information
router.get('/user/:identifier', async (req, res) => {
  try {
    const { identifier } = req.params;
    const { type = 'auto' } = req.query;

    if (!req.integrationManager) {
      return res.status(503).json({
        success: false,
        error: 'Directory service unavailable'
      });
    }

    const result = await req.integrationManager.getUserByIdentifier(identifier, type);
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(404).json(result);
    }

  } catch (error) {
    logger.error('User lookup error:', error);
    res.status(500).json({
      success: false,
      error: 'User lookup failed'
    });
  }
});

// Get user groups
router.get('/user/:userGUID/groups', async (req, res) => {
  try {
    const { userGUID } = req.params;

    if (!req.integrationManager) {
      return res.status(503).json({
        success: false,
        error: 'Directory service unavailable'
      });
    }

    const result = await req.integrationManager.getUserGroups(userGUID);
    res.json(result);

  } catch (error) {
    logger.error('User groups lookup error:', error);
    res.status(500).json({
      success: false,
      error: 'Groups lookup failed'
    });
  }
});

// Get user policies
router.get('/user/:userGUID/policies', async (req, res) => {
  try {
    const { userGUID } = req.params;

    if (!req.integrationManager) {
      return res.status(503).json({
        success: false,
        error: 'Directory service unavailable'
      });
    }

    const result = await req.integrationManager.getUserPolicies(userGUID);
    res.json(result);

  } catch (error) {
    logger.error('User policies lookup error:', error);
    res.status(500).json({
      success: false,
      error: 'Policies lookup failed'
    });
  }
});

// Get computer information
router.get('/computer/:identifier', async (req, res) => {
  try {
    const { identifier } = req.params;
    const { type = 'auto' } = req.query;

    if (!req.integrationManager) {
      return res.status(503).json({
        success: false,
        error: 'Directory service unavailable'
      });
    }

    const result = await req.integrationManager.getComputerByIdentifier(identifier, type);
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(404).json(result);
    }

  } catch (error) {
    logger.error('Computer lookup error:', error);
    res.status(500).json({
      success: false,
      error: 'Computer lookup failed'
    });
  }
});

// Join computer to domain
router.post('/computer/join', async (req, res) => {
  try {
    const computerInfo = req.body;

    if (!req.integrationManager) {
      return res.status(503).json({
        success: false,
        error: 'Directory service unavailable'
      });
    }

    const result = await req.integrationManager.joinComputer(computerInfo);
    
    if (result.success) {
      logger.info(`Computer joined successfully: ${computerInfo.computerName}`);
      res.json(result);
    } else {
      res.status(400).json(result);
    }

  } catch (error) {
    logger.error('Computer join error:', error);
    res.status(500).json({
      success: false,
      error: 'Computer join failed'
    });
  }
});

// Get computer policies
router.get('/computer/:computerGUID/policies', async (req, res) => {
  try {
    const { computerGUID } = req.params;

    if (!req.integrationManager) {
      return res.status(503).json({
        success: false,
        error: 'Directory service unavailable'
      });
    }

    const result = await req.integrationManager.getComputerPolicies(computerGUID);
    res.json(result);

  } catch (error) {
    logger.error('Computer policies lookup error:', error);
    res.status(500).json({
      success: false,
      error: 'Policies lookup failed'
    });
  }
});

module.exports = router;