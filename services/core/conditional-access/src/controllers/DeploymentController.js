/**
 * Deployment Controller
 * REST API endpoints for autopilot / zero-touch device deployment
 */

const express = require('express');

class DeploymentController {
    constructor(autopilotDeployment, auditLogger) {
        this.autopilotDeployment = autopilotDeployment;
        this.auditLogger = auditLogger;
        this.router = express.Router();
        this.setupRoutes();
    }

    setupRoutes() {
        // Deployment profiles
        this.router.get('/profiles', this.getProfiles.bind(this));
        this.router.post('/profiles', this.createProfile.bind(this));

        // Device registration
        this.router.post('/register', this.registerDevice.bind(this));
        this.router.get('/devices/:deviceIdentifier', this.getDeviceRegistration.bind(this));

        // Deployment execution
        this.router.post('/start', this.startDeployment.bind(this));
        this.router.get('/jobs/:jobId', this.getDeploymentStatus.bind(this));
    }

    async getProfiles(req, res) {
        try {
            const { platform } = req.query;
            const profiles = this.autopilotDeployment.getDeploymentProfiles(platform || null);

            res.json({
                success: true,
                data: profiles
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async createProfile(req, res) {
        try {
            const profileData = req.body;

            if (!profileData.name || !Array.isArray(profileData.platforms) || profileData.platforms.length === 0) {
                return res.status(400).json({
                    success: false,
                    error: 'name and platforms[] are required'
                });
            }

            const result = await this.autopilotDeployment.createDeploymentProfile(profileData);

            await this.auditLogger.logEvent(
                'deployment',
                'DEPLOYMENT_PROFILE_CREATED',
                {
                    profileId: result.profileId,
                    name: profileData.name,
                    createdBy: req.user?.id
                }
            );

            res.status(201).json({
                success: true,
                data: result
            });

        } catch (error) {
            res.status(400).json({
                success: false,
                error: error.message
            });
        }
    }

    async registerDevice(req, res) {
        try {
            const { deviceInfo, profileId } = req.body;

            if (!deviceInfo || !profileId) {
                return res.status(400).json({
                    success: false,
                    error: 'deviceInfo and profileId are required'
                });
            }

            const result = await this.autopilotDeployment.registerDevice(deviceInfo, profileId);

            await this.auditLogger.logEvent(
                'deployment',
                'DEVICE_REGISTERED_FOR_DEPLOYMENT',
                {
                    deviceId: deviceInfo.deviceId,
                    profileId,
                    registeredBy: req.user?.id
                }
            );

            res.status(201).json({
                success: true,
                data: result
            });

        } catch (error) {
            await this.auditLogger.logEvent(
                'deployment',
                'DEVICE_REGISTRATION_FAILED',
                {
                    deviceId: req.body?.deviceInfo?.deviceId,
                    error: error.message
                }
            );

            res.status(400).json({
                success: false,
                error: error.message
            });
        }
    }

    async getDeviceRegistration(req, res) {
        try {
            const { deviceIdentifier } = req.params;
            const registration = this.autopilotDeployment.getDeviceRegistration(deviceIdentifier);

            if (!registration) {
                return res.status(404).json({
                    success: false,
                    error: 'Device registration not found'
                });
            }

            res.json({
                success: true,
                data: registration
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async startDeployment(req, res) {
        try {
            const { deviceIdentifier, deploymentToken } = req.body;

            if (!deviceIdentifier || !deploymentToken) {
                return res.status(400).json({
                    success: false,
                    error: 'deviceIdentifier and deploymentToken are required'
                });
            }

            await this.auditLogger.logEvent(
                'deployment',
                'DEPLOYMENT_START_REQUESTED',
                {
                    deviceIdentifier,
                    requestedBy: req.user?.id
                }
            );

            const result = await this.autopilotDeployment.startDeployment(deviceIdentifier, deploymentToken);

            res.json({
                success: true,
                data: result
            });

        } catch (error) {
            await this.auditLogger.logEvent(
                'deployment',
                'DEPLOYMENT_START_FAILED',
                {
                    deviceIdentifier: req.body?.deviceIdentifier,
                    error: error.message
                }
            );

            res.status(400).json({
                success: false,
                error: error.message
            });
        }
    }

    async getDeploymentStatus(req, res) {
        try {
            const { jobId } = req.params;
            const job = this.autopilotDeployment.getDeploymentStatus(jobId);

            if (!job) {
                return res.status(404).json({
                    success: false,
                    error: 'Deployment job not found'
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

    getRouter() {
        return this.router;
    }
}

module.exports = DeploymentController;
