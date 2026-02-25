/**
 * OpenDirectory Certificate & Network Service Profile Routes
 */

const express = require('express');
const router = express.Router();
const { logger } = require('../utils/logger');

// WiFi Profile Routes
router.post('/wifi/generate', async (req, res) => {
  try {
    const { platform, config } = req.body;

    if (!req.services.wifiProfile) {
      return res.status(503).json({
        success: false,
        error: 'WiFi profile service unavailable'
      });
    }

    const result = await req.services.wifiProfile.generateProfile(platform, config);
    res.json(result);

  } catch (error) {
    logger.error('WiFi profile generation error:', error);
    res.status(500).json({
      success: false,
      error: 'WiFi profile generation failed'
    });
  }
});

router.post('/wifi/deploy', async (req, res) => {
  try {
    const { targetType, targetId, profileConfig } = req.body;

    if (!req.services.wifiProfile) {
      return res.status(503).json({
        success: false,
        error: 'WiFi profile service unavailable'
      });
    }

    let result;
    if (targetType === 'user') {
      result = await req.services.wifiProfile.deployUserProfile(targetId, profileConfig);
    } else if (targetType === 'computer') {
      result = await req.services.wifiProfile.deployComputerProfile(targetId, profileConfig);
    } else {
      return res.status(400).json({
        success: false,
        error: 'Invalid target type. Must be "user" or "computer"'
      });
    }

    res.json(result);

  } catch (error) {
    logger.error('WiFi profile deployment error:', error);
    res.status(500).json({
      success: false,
      error: 'WiFi profile deployment failed'
    });
  }
});

// VPN Profile Routes
router.post('/vpn/generate', async (req, res) => {
  try {
    const { platform, config } = req.body;

    if (!req.services.vpnProfile) {
      return res.status(503).json({
        success: false,
        error: 'VPN profile service unavailable'
      });
    }

    const result = await req.services.vpnProfile.generateProfile(platform, config);
    res.json(result);

  } catch (error) {
    logger.error('VPN profile generation error:', error);
    res.status(500).json({
      success: false,
      error: 'VPN profile generation failed'
    });
  }
});

router.post('/vpn/deploy', async (req, res) => {
  try {
    const { targetType, targetId, profileConfig } = req.body;

    if (!req.services.vpnProfile) {
      return res.status(503).json({
        success: false,
        error: 'VPN profile service unavailable'
      });
    }

    let result;
    if (targetType === 'user') {
      result = await req.services.vpnProfile.deployUserProfile(targetId, profileConfig);
    } else if (targetType === 'computer') {
      result = await req.services.vpnProfile.deployComputerProfile(targetId, profileConfig);
    } else {
      return res.status(400).json({
        success: false,
        error: 'Invalid target type. Must be "user" or "computer"'
      });
    }

    res.json(result);

  } catch (error) {
    logger.error('VPN profile deployment error:', error);
    res.status(500).json({
      success: false,
      error: 'VPN profile deployment failed'
    });
  }
});

// Email Profile Routes
router.post('/email/generate', async (req, res) => {
  try {
    const { platform, config } = req.body;

    if (!req.services.emailProfile) {
      return res.status(503).json({
        success: false,
        error: 'Email profile service unavailable'
      });
    }

    const result = await req.services.emailProfile.generateProfile(platform, config);
    res.json(result);

  } catch (error) {
    logger.error('Email profile generation error:', error);
    res.status(500).json({
      success: false,
      error: 'Email profile generation failed'
    });
  }
});

router.post('/email/deploy', async (req, res) => {
  try {
    const { targetId, profileConfig } = req.body;

    if (!req.services.emailProfile) {
      return res.status(503).json({
        success: false,
        error: 'Email profile service unavailable'
      });
    }

    const result = await req.services.emailProfile.deployUserProfile(targetId, profileConfig);
    res.json(result);

  } catch (error) {
    logger.error('Email profile deployment error:', error);
    res.status(500).json({
      success: false,
      error: 'Email profile deployment failed'
    });
  }
});

// Certificate Distribution Routes
router.post('/certificates/distribute', async (req, res) => {
  try {
    const { certificateId, targets, method } = req.body;

    if (!req.services.certificateDistribution) {
      return res.status(503).json({
        success: false,
        error: 'Certificate distribution service unavailable'
      });
    }

    const result = await req.services.certificateDistribution.distributeCertificate(
      certificateId,
      targets,
      method
    );

    res.json(result);

  } catch (error) {
    logger.error('Certificate distribution error:', error);
    res.status(500).json({
      success: false,
      error: 'Certificate distribution failed'
    });
  }
});

// Get profile deployment status
router.get('/deployments/:deploymentId', async (req, res) => {
  try {
    const { deploymentId } = req.params;

    // This would typically check with the appropriate service
    // For now, return a placeholder response
    res.json({
      success: true,
      deployment: {
        id: deploymentId,
        status: 'deployed',
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    logger.error('Deployment status error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get deployment status'
    });
  }
});

// Get profile templates
router.get('/templates/:profileType', async (req, res) => {
  try {
    const { profileType } = req.params;

    let service;
    switch (profileType.toLowerCase()) {
      case 'wifi':
        service = req.services.wifiProfile;
        break;
      case 'vpn':
        service = req.services.vpnProfile;
        break;
      case 'email':
        service = req.services.emailProfile;
        break;
      default:
        return res.status(400).json({
          success: false,
          error: 'Invalid profile type'
        });
    }

    if (!service) {
      return res.status(503).json({
        success: false,
        error: `${profileType} profile service unavailable`
      });
    }

    const templates = await service.getAvailableTemplates();
    res.json({ success: true, templates });

  } catch (error) {
    logger.error('Template retrieval error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get profile templates'
    });
  }
});

module.exports = router;