/**
 * OpenDirectory Certificate & Network Service Certificate Routes
 */

const express = require('express');
const router = express.Router();
const { logger } = require('../utils/logger');

// Get certificate status
router.get('/status', async (req, res) => {
  try {
    if (!req.services.certificateLifecycle) {
      return res.status(503).json({
        success: false,
        error: 'Certificate service unavailable'
      });
    }

    const status = await req.services.certificateLifecycle.getStatus();
    res.json({ success: true, status });

  } catch (error) {
    logger.error('Certificate status error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get certificate status'
    });
  }
});

// Enroll for a new certificate
router.post('/enroll', async (req, res) => {
  try {
    const enrollmentRequest = req.body;

    if (!req.services.certificateLifecycle) {
      return res.status(503).json({
        success: false,
        error: 'Certificate service unavailable'
      });
    }

    const result = await req.services.certificateLifecycle.enrollCertificate(enrollmentRequest);
    
    if (result.success) {
      // Notify Enterprise Directory if integration is available
      if (req.integrationManager) {
        await req.integrationManager.notifyCertificateIssued(result.certificate);
      }
    }

    res.json(result);

  } catch (error) {
    logger.error('Certificate enrollment error:', error);
    res.status(500).json({
      success: false,
      error: 'Certificate enrollment failed'
    });
  }
});

// Get certificate by serial number
router.get('/:serialNumber', async (req, res) => {
  try {
    const { serialNumber } = req.params;

    if (!req.services.certificateLifecycle) {
      return res.status(503).json({
        success: false,
        error: 'Certificate service unavailable'
      });
    }

    const certificate = await req.services.certificateLifecycle.getCertificateBySerial(serialNumber);
    
    if (certificate) {
      res.json({ success: true, certificate });
    } else {
      res.status(404).json({ success: false, error: 'Certificate not found' });
    }

  } catch (error) {
    logger.error('Certificate lookup error:', error);
    res.status(500).json({
      success: false,
      error: 'Certificate lookup failed'
    });
  }
});

// Revoke certificate
router.post('/:serialNumber/revoke', async (req, res) => {
  try {
    const { serialNumber } = req.params;
    const { reason, revokedBy } = req.body;

    if (!req.services.certificateLifecycle) {
      return res.status(503).json({
        success: false,
        error: 'Certificate service unavailable'
      });
    }

    const result = await req.services.certificateLifecycle.revokeCertificate(
      serialNumber, 
      reason || 'unspecified', 
      revokedBy || 'API'
    );
    
    if (result.success) {
      // Notify Enterprise Directory if integration is available
      if (req.integrationManager) {
        await req.integrationManager.notifyCertificateRevoked({
          serialNumber,
          revocationDate: new Date(),
          revocationReason: reason || 'unspecified',
          revokedBy: revokedBy || 'API'
        });
      }
    }

    res.json(result);

  } catch (error) {
    logger.error('Certificate revocation error:', error);
    res.status(500).json({
      success: false,
      error: 'Certificate revocation failed'
    });
  }
});

// Get CA certificate
router.get('/ca/certificate', async (req, res) => {
  try {
    if (!req.services.enterpriseCA) {
      return res.status(503).json({
        success: false,
        error: 'CA service unavailable'
      });
    }

    const caCertificate = await req.services.enterpriseCA.getRootCACertificate();
    
    res.set('Content-Type', 'application/x-pem-file');
    res.set('Content-Disposition', 'attachment; filename="ca-certificate.pem"');
    res.send(caCertificate);

  } catch (error) {
    logger.error('CA certificate retrieval error:', error);
    res.status(500).json({
      success: false,
      error: 'CA certificate retrieval failed'
    });
  }
});

// Get CRL (Certificate Revocation List)
router.get('/ca/crl', async (req, res) => {
  try {
    if (!req.services.enterpriseCA) {
      return res.status(503).json({
        success: false,
        error: 'CA service unavailable'
      });
    }

    const crl = await req.services.enterpriseCA.getCurrentCRL();
    
    res.set('Content-Type', 'application/x-pem-file');
    res.set('Content-Disposition', 'attachment; filename="ca.crl"');
    res.send(crl);

  } catch (error) {
    logger.error('CRL retrieval error:', error);
    res.status(500).json({
      success: false,
      error: 'CRL retrieval failed'
    });
  }
});

module.exports = router;