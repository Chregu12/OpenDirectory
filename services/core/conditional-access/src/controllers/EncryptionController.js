/**
 * Encryption Controller
 * REST API endpoints for encryption management
 */

const express = require('express');
const crypto = require('crypto');

class EncryptionController {
    constructor(encryptionManager, auditLogger) {
        this.encryptionManager = encryptionManager;
        this.auditLogger = auditLogger;
        this.router = express.Router();
        this.setupRoutes();
    }

    setupRoutes() {
        // Check encryption status
        this.router.post('/status', this.checkStatus.bind(this));
        
        // Enable encryption
        this.router.post('/enable', this.enableEncryption.bind(this));
        
        // Get encryption job status
        this.router.get('/jobs/:jobId', this.getJobStatus.bind(this));
        
        // Retrieve recovery key
        this.router.post('/recovery-key', this.retrieveRecoveryKey.bind(this));
        
        // Rotate recovery key
        this.router.post('/devices/:deviceId/rotate-key', this.rotateRecoveryKey.bind(this));
        
        // Get policy compliance
        this.router.get('/devices/:deviceId/compliance', this.getPolicyCompliance.bind(this));
    }

    async checkStatus(req, res) {
        try {
            const { deviceInfo } = req.body;
            
            const status = await this.encryptionManager.checkEncryptionStatus(deviceInfo);
            
            await this.auditLogger.logEvent(
                'encryption',
                'ENCRYPTION_STATUS_CHECKED',
                {
                    deviceId: deviceInfo.deviceId,
                    encrypted: status.encrypted,
                    algorithm: status.algorithm
                }
            );
            
            res.json({
                success: true,
                data: status
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async enableEncryption(req, res) {
        try {
            const { deviceId, options } = req.body;
            
            await this.auditLogger.logEvent(
                'encryption',
                'ENCRYPTION_ENABLE_REQUESTED',
                {
                    deviceId,
                    requestedBy: req.user.id,
                    options
                }
            );
            
            const result = await this.encryptionManager.enableEncryption(deviceId, options);
            
            res.json({
                success: true,
                data: result
            });

        } catch (error) {
            await this.auditLogger.logEvent(
                'encryption',
                'ENCRYPTION_ENABLE_FAILED',
                {
                    deviceId: req.body.deviceId,
                    error: error.message
                }
            );
            
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async getJobStatus(req, res) {
        try {
            const { jobId } = req.params;
            const job = this.encryptionManager.getEncryptionJobStatus(jobId);
            
            if (!job) {
                return res.status(404).json({
                    success: false,
                    error: 'Job not found'
                });
            }
            
            res.json({
                success: true,
                data: job
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async retrieveRecoveryKey(req, res) {
        try {
            const { deviceId, justification } = req.body;
            const requesterId = req.user.id;
            
            const result = await this.encryptionManager.retrieveRecoveryKey(
                deviceId,
                requesterId,
                justification
            );
            
            // Don't log the actual recovery key
            await this.auditLogger.logEvent(
                'encryption',
                'RECOVERY_KEY_RETRIEVED',
                {
                    deviceId,
                    requesterId,
                    justification,
                    retrievedAt: result.retrievedAt
                }
            );
            
            res.json({
                success: true,
                data: result
            });

        } catch (error) {
            await this.auditLogger.logEvent(
                'encryption',
                'RECOVERY_KEY_RETRIEVAL_FAILED',
                {
                    deviceId: req.body.deviceId,
                    requesterId: req.user.id,
                    error: error.message
                }
            );
            
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async rotateRecoveryKey(req, res) {
        try {
            const { deviceId } = req.params;
            
            const result = await this.encryptionManager.rotateRecoveryKey(deviceId);
            
            await this.auditLogger.logEvent(
                'encryption',
                'RECOVERY_KEY_ROTATED',
                {
                    deviceId,
                    rotatedBy: req.user.id
                }
            );
            
            res.json({
                success: true,
                data: result
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async getPolicyCompliance(req, res) {
        try {
            const { deviceId } = req.params;
            
            const compliance = await this.encryptionManager.checkPolicyCompliance(deviceId);
            
            res.json({
                success: true,
                data: compliance
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    getRouter() {
        return this.router;
    }
}

module.exports = EncryptionController;