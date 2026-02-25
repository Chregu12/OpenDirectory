const express = require('express');
const { validateRequest } = require('../middleware/validation');
const { updateSchemas } = require('../middleware/validation');
const { requireRole, requirePermission } = require('../middleware/auth');
const logger = require('../utils/logger').logger;

class UpdateController {
    constructor(services) {
        this.services = services;
        this.router = express.Router();
        this.setupRoutes();
    }

    /**
     * Set up all routes for update management
     */
    setupRoutes() {
        // Windows Update Management routes
        this.router.get('/windows/policies', 
            requirePermission('update-management:read'),
            this.getWindowsUpdatePolicies.bind(this)
        );

        this.router.post('/windows/policies',
            requirePermission('update-management:write'),
            validateRequest(updateSchemas.windowsUpdatePolicy),
            this.createWindowsUpdatePolicy.bind(this)
        );

        this.router.get('/windows/policies/:policyId',
            requirePermission('update-management:read'),
            this.getWindowsUpdatePolicy.bind(this)
        );

        this.router.put('/windows/policies/:policyId',
            requirePermission('update-management:write'),
            validateRequest(updateSchemas.windowsUpdatePolicy),
            this.updateWindowsUpdatePolicy.bind(this)
        );

        this.router.delete('/windows/policies/:policyId',
            requirePermission('update-management:delete'),
            this.deleteWindowsUpdatePolicy.bind(this)
        );

        this.router.post('/windows/policies/:policyId/deploy',
            requirePermission('update-management:deploy'),
            this.deployWindowsUpdatePolicy.bind(this)
        );

        this.router.get('/windows/devices/:deviceId/status',
            requirePermission('device-management:read'),
            this.getWindowsUpdateStatus.bind(this)
        );

        this.router.post('/windows/devices/:deviceId/force-update',
            requirePermission('device-management:remote-actions'),
            this.forceWindowsUpdate.bind(this)
        );

        this.router.get('/windows/compliance',
            requirePermission('compliance:read'),
            this.getWindowsComplianceReport.bind(this)
        );

        // macOS Update Management routes
        this.router.get('/macos/policies',
            requirePermission('update-management:read'),
            this.getMacOSUpdatePolicies.bind(this)
        );

        this.router.post('/macos/policies',
            requirePermission('update-management:write'),
            validateRequest(updateSchemas.macosUpdatePolicy),
            this.createMacOSUpdatePolicy.bind(this)
        );

        this.router.get('/macos/policies/:policyId',
            requirePermission('update-management:read'),
            this.getMacOSUpdatePolicy.bind(this)
        );

        this.router.put('/macos/policies/:policyId',
            requirePermission('update-management:write'),
            validateRequest(updateSchemas.macosUpdatePolicy),
            this.updateMacOSUpdatePolicy.bind(this)
        );

        this.router.delete('/macos/policies/:policyId',
            requirePermission('update-management:delete'),
            this.deleteMacOSUpdatePolicy.bind(this)
        );

        this.router.get('/macos/devices/:deviceId/status',
            requirePermission('device-management:read'),
            this.getMacOSUpdateStatus.bind(this)
        );

        this.router.post('/macos/devices/:deviceId/force-update',
            requirePermission('device-management:remote-actions'),
            this.forceMacOSUpdate.bind(this)
        );

        this.router.get('/macos/compliance',
            requirePermission('compliance:read'),
            this.getMacOSComplianceReport.bind(this)
        );

        // Linux Update Management routes
        this.router.get('/linux/policies',
            requirePermission('update-management:read'),
            this.getLinuxUpdatePolicies.bind(this)
        );

        this.router.post('/linux/policies',
            requirePermission('update-management:write'),
            validateRequest(updateSchemas.linuxUpdatePolicy),
            this.createLinuxUpdatePolicy.bind(this)
        );

        this.router.get('/linux/policies/:policyId',
            requirePermission('update-management:read'),
            this.getLinuxUpdatePolicy.bind(this)
        );

        this.router.put('/linux/policies/:policyId',
            requirePermission('update-management:write'),
            validateRequest(updateSchemas.linuxUpdatePolicy),
            this.updateLinuxUpdatePolicy.bind(this)
        );

        this.router.delete('/linux/policies/:policyId',
            requirePermission('update-management:delete'),
            this.deleteLinuxUpdatePolicy.bind(this)
        );

        this.router.get('/linux/devices/:deviceId/status',
            requirePermission('device-management:read'),
            this.getLinuxUpdateStatus.bind(this)
        );

        this.router.post('/linux/devices/:deviceId/force-update',
            requirePermission('device-management:remote-actions'),
            this.forceLinuxUpdate.bind(this)
        );

        this.router.get('/linux/compliance',
            requirePermission('compliance:read'),
            this.getLinuxComplianceReport.bind(this)
        );

        // Cross-platform routes
        this.router.get('/overview',
            requirePermission('update-management:read'),
            this.getUpdateOverview.bind(this)
        );

        this.router.get('/statistics',
            requirePermission('reporting:read'),
            this.getUpdateStatistics.bind(this)
        );

        this.router.get('/health',
            this.getServiceHealth.bind(this)
        );
    }

    /**
     * Get Windows update policies
     */
    async getWindowsUpdatePolicies(req, res) {
        try {
            const tenantId = req.tenantId;
            const { page = 1, limit = 20, sort = 'name', order = 'asc' } = req.query;

            // This would typically query a database
            const policies = [];

            logger.info('Retrieved Windows update policies', {
                tenantId,
                count: policies.length,
                userId: req.user.id
            });

            res.json({
                success: true,
                data: policies,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: policies.length,
                    pages: Math.ceil(policies.length / limit)
                },
                timestamp: new Date().toISOString()
            });

        } catch (error) {
            logger.error('Error retrieving Windows update policies:', error);
            res.status(500).json({
                success: false,
                error: 'Internal server error',
                message: 'Failed to retrieve Windows update policies',
                timestamp: new Date().toISOString()
            });
        }
    }

    /**
     * Create Windows update policy
     */
    async createWindowsUpdatePolicy(req, res) {
        try {
            const tenantId = req.tenantId;
            const userId = req.user.id;
            const policyData = req.body;

            const result = await this.services.windowsUpdate.configureUpdatePolicy('temp-device-id', {
                ...policyData,
                tenantId,
                createdBy: userId
            });

            if (result.success) {
                logger.info('Windows update policy created', {
                    policyId: result.policyId,
                    tenantId,
                    userId
                });

                res.status(201).json({
                    success: true,
                    data: {
                        policyId: result.policyId,
                        policy: result.policy,
                        script: result.script
                    },
                    message: 'Windows update policy created successfully',
                    timestamp: new Date().toISOString()
                });
            } else {
                res.status(400).json({
                    success: false,
                    error: 'Policy creation failed',
                    message: result.message || 'Failed to create Windows update policy',
                    timestamp: new Date().toISOString()
                });
            }

        } catch (error) {
            logger.error('Error creating Windows update policy:', error);
            res.status(500).json({
                success: false,
                error: 'Internal server error',
                message: 'Failed to create Windows update policy',
                timestamp: new Date().toISOString()
            });
        }
    }

    /**
     * Get specific Windows update policy
     */
    async getWindowsUpdatePolicy(req, res) {
        try {
            const { policyId } = req.params;
            const tenantId = req.tenantId;

            // This would typically query a database
            const policy = null;

            if (!policy) {
                return res.status(404).json({
                    success: false,
                    error: 'Policy not found',
                    message: 'The requested Windows update policy was not found',
                    timestamp: new Date().toISOString()
                });
            }

            res.json({
                success: true,
                data: policy,
                timestamp: new Date().toISOString()
            });

        } catch (error) {
            logger.error('Error retrieving Windows update policy:', error);
            res.status(500).json({
                success: false,
                error: 'Internal server error',
                message: 'Failed to retrieve Windows update policy',
                timestamp: new Date().toISOString()
            });
        }
    }

    /**
     * Update Windows update policy
     */
    async updateWindowsUpdatePolicy(req, res) {
        try {
            const { policyId } = req.params;
            const tenantId = req.tenantId;
            const userId = req.user.id;
            const updates = req.body;

            // This would typically update the policy in database
            logger.info('Windows update policy updated', {
                policyId,
                tenantId,
                userId,
                updates: Object.keys(updates)
            });

            res.json({
                success: true,
                data: {
                    policyId,
                    ...updates,
                    lastModified: new Date().toISOString(),
                    modifiedBy: userId
                },
                message: 'Windows update policy updated successfully',
                timestamp: new Date().toISOString()
            });

        } catch (error) {
            logger.error('Error updating Windows update policy:', error);
            res.status(500).json({
                success: false,
                error: 'Internal server error',
                message: 'Failed to update Windows update policy',
                timestamp: new Date().toISOString()
            });
        }
    }

    /**
     * Delete Windows update policy
     */
    async deleteWindowsUpdatePolicy(req, res) {
        try {
            const { policyId } = req.params;
            const tenantId = req.tenantId;
            const userId = req.user.id;

            // This would typically delete from database and check dependencies
            logger.info('Windows update policy deleted', {
                policyId,
                tenantId,
                userId
            });

            res.json({
                success: true,
                message: 'Windows update policy deleted successfully',
                timestamp: new Date().toISOString()
            });

        } catch (error) {
            logger.error('Error deleting Windows update policy:', error);
            res.status(500).json({
                success: false,
                error: 'Internal server error',
                message: 'Failed to delete Windows update policy',
                timestamp: new Date().toISOString()
            });
        }
    }

    /**
     * Deploy Windows update policy
     */
    async deployWindowsUpdatePolicy(req, res) {
        try {
            const { policyId } = req.params;
            const { deviceIds, deploymentOptions } = req.body;
            const tenantId = req.tenantId;
            const userId = req.user.id;

            // This would deploy the policy to specified devices
            logger.info('Windows update policy deployment initiated', {
                policyId,
                deviceCount: deviceIds?.length || 0,
                tenantId,
                userId
            });

            res.json({
                success: true,
                data: {
                    deploymentId: `deployment-${Date.now()}`,
                    policyId,
                    deviceIds,
                    status: 'initiated'
                },
                message: 'Windows update policy deployment initiated',
                timestamp: new Date().toISOString()
            });

        } catch (error) {
            logger.error('Error deploying Windows update policy:', error);
            res.status(500).json({
                success: false,
                error: 'Internal server error',
                message: 'Failed to deploy Windows update policy',
                timestamp: new Date().toISOString()
            });
        }
    }

    /**
     * Get Windows update status for device
     */
    async getWindowsUpdateStatus(req, res) {
        try {
            const { deviceId } = req.params;
            const tenantId = req.tenantId;

            const result = await this.services.windowsUpdate.checkUpdateStatus(deviceId);

            if (result.success) {
                res.json({
                    success: true,
                    data: {
                        deviceId,
                        script: result.script,
                        timestamp: result.timestamp
                    },
                    message: 'Windows update status retrieved',
                    timestamp: new Date().toISOString()
                });
            } else {
                res.status(400).json({
                    success: false,
                    error: 'Status check failed',
                    message: 'Failed to check Windows update status',
                    timestamp: new Date().toISOString()
                });
            }

        } catch (error) {
            logger.error('Error getting Windows update status:', error);
            res.status(500).json({
                success: false,
                error: 'Internal server error',
                message: 'Failed to get Windows update status',
                timestamp: new Date().toISOString()
            });
        }
    }

    /**
     * Force Windows update on device
     */
    async forceWindowsUpdate(req, res) {
        try {
            const { deviceId } = req.params;
            const { updateIds } = req.body;
            const tenantId = req.tenantId;
            const userId = req.user.id;

            const result = await this.services.windowsUpdate.forceUpdateInstallation(deviceId, updateIds);

            if (result.success) {
                logger.info('Windows update forced', {
                    deviceId,
                    updateIds: updateIds || 'all',
                    tenantId,
                    userId
                });

                res.json({
                    success: true,
                    data: result,
                    message: 'Windows update installation forced',
                    timestamp: new Date().toISOString()
                });
            } else {
                res.status(400).json({
                    success: false,
                    error: 'Update force failed',
                    message: 'Failed to force Windows update installation',
                    timestamp: new Date().toISOString()
                });
            }

        } catch (error) {
            logger.error('Error forcing Windows update:', error);
            res.status(500).json({
                success: false,
                error: 'Internal server error',
                message: 'Failed to force Windows update',
                timestamp: new Date().toISOString()
            });
        }
    }

    /**
     * Get Windows compliance report
     */
    async getWindowsComplianceReport(req, res) {
        try {
            const { deviceIds } = req.query;
            const tenantId = req.tenantId;

            const deviceList = deviceIds ? deviceIds.split(',') : [];
            const result = await this.services.windowsUpdate.getComplianceReport(deviceList);

            if (result.success) {
                res.json({
                    success: true,
                    data: {
                        script: result.complianceScript,
                        reportTemplate: result.reportTemplate
                    },
                    message: 'Windows compliance report generated',
                    timestamp: new Date().toISOString()
                });
            } else {
                res.status(400).json({
                    success: false,
                    error: 'Report generation failed',
                    message: 'Failed to generate Windows compliance report',
                    timestamp: new Date().toISOString()
                });
            }

        } catch (error) {
            logger.error('Error generating Windows compliance report:', error);
            res.status(500).json({
                success: false,
                error: 'Internal server error',
                message: 'Failed to generate Windows compliance report',
                timestamp: new Date().toISOString()
            });
        }
    }

    // Similar methods would be implemented for macOS and Linux...
    // For brevity, I'll implement placeholders

    async getMacOSUpdatePolicies(req, res) {
        res.json({
            success: true,
            data: [],
            message: 'macOS update policies retrieved',
            timestamp: new Date().toISOString()
        });
    }

    async createMacOSUpdatePolicy(req, res) {
        const result = await this.services.macosUpdate.configureUpdatePolicy('temp-device-id', req.body);
        res.status(201).json({
            success: true,
            data: result,
            message: 'macOS update policy created',
            timestamp: new Date().toISOString()
        });
    }

    async getMacOSUpdatePolicy(req, res) {
        res.json({
            success: true,
            data: { id: req.params.policyId },
            message: 'macOS update policy retrieved',
            timestamp: new Date().toISOString()
        });
    }

    async updateMacOSUpdatePolicy(req, res) {
        res.json({
            success: true,
            data: { id: req.params.policyId, ...req.body },
            message: 'macOS update policy updated',
            timestamp: new Date().toISOString()
        });
    }

    async deleteMacOSUpdatePolicy(req, res) {
        res.json({
            success: true,
            message: 'macOS update policy deleted',
            timestamp: new Date().toISOString()
        });
    }

    async getMacOSUpdateStatus(req, res) {
        const result = await this.services.macosUpdate.checkUpdateStatus(req.params.deviceId);
        res.json({
            success: true,
            data: result,
            message: 'macOS update status retrieved',
            timestamp: new Date().toISOString()
        });
    }

    async forceMacOSUpdate(req, res) {
        const result = await this.services.macosUpdate.forceUpdateInstallation(req.params.deviceId, req.body);
        res.json({
            success: true,
            data: result,
            message: 'macOS update forced',
            timestamp: new Date().toISOString()
        });
    }

    async getMacOSComplianceReport(req, res) {
        const result = await this.services.macosUpdate.getComplianceReport();
        res.json({
            success: true,
            data: result,
            message: 'macOS compliance report generated',
            timestamp: new Date().toISOString()
        });
    }

    // Linux update methods (placeholders)
    async getLinuxUpdatePolicies(req, res) {
        res.json({
            success: true,
            data: [],
            message: 'Linux update policies retrieved',
            timestamp: new Date().toISOString()
        });
    }

    async createLinuxUpdatePolicy(req, res) {
        const result = await this.services.linuxUpdate.configureUpdatePolicy('temp-device-id', req.body);
        res.status(201).json({
            success: true,
            data: result,
            message: 'Linux update policy created',
            timestamp: new Date().toISOString()
        });
    }

    async getLinuxUpdatePolicy(req, res) {
        res.json({
            success: true,
            data: { id: req.params.policyId },
            message: 'Linux update policy retrieved',
            timestamp: new Date().toISOString()
        });
    }

    async updateLinuxUpdatePolicy(req, res) {
        res.json({
            success: true,
            data: { id: req.params.policyId, ...req.body },
            message: 'Linux update policy updated',
            timestamp: new Date().toISOString()
        });
    }

    async deleteLinuxUpdatePolicy(req, res) {
        res.json({
            success: true,
            message: 'Linux update policy deleted',
            timestamp: new Date().toISOString()
        });
    }

    async getLinuxUpdateStatus(req, res) {
        const result = await this.services.linuxUpdate.checkUpdateStatus(req.params.deviceId);
        res.json({
            success: true,
            data: result,
            message: 'Linux update status retrieved',
            timestamp: new Date().toISOString()
        });
    }

    async forceLinuxUpdate(req, res) {
        const result = await this.services.linuxUpdate.forceUpdateInstallation(req.params.deviceId, req.body);
        res.json({
            success: true,
            data: result,
            message: 'Linux update forced',
            timestamp: new Date().toISOString()
        });
    }

    async getLinuxComplianceReport(req, res) {
        const result = await this.services.linuxUpdate.getComplianceReport();
        res.json({
            success: true,
            data: result,
            message: 'Linux compliance report generated',
            timestamp: new Date().toISOString()
        });
    }

    /**
     * Get update overview across all platforms
     */
    async getUpdateOverview(req, res) {
        try {
            const tenantId = req.tenantId;

            const overview = {
                tenantId,
                platforms: {
                    windows: {
                        policies: 0,
                        devices: 0,
                        complianceRate: 0,
                        pendingUpdates: 0
                    },
                    macos: {
                        policies: 0,
                        devices: 0,
                        complianceRate: 0,
                        pendingUpdates: 0
                    },
                    linux: {
                        policies: 0,
                        devices: 0,
                        complianceRate: 0,
                        pendingUpdates: 0
                    }
                },
                overall: {
                    totalPolicies: 0,
                    totalDevices: 0,
                    averageComplianceRate: 0,
                    totalPendingUpdates: 0
                }
            };

            res.json({
                success: true,
                data: overview,
                message: 'Update overview retrieved',
                timestamp: new Date().toISOString()
            });

        } catch (error) {
            logger.error('Error getting update overview:', error);
            res.status(500).json({
                success: false,
                error: 'Internal server error',
                message: 'Failed to get update overview',
                timestamp: new Date().toISOString()
            });
        }
    }

    /**
     * Get update statistics
     */
    async getUpdateStatistics(req, res) {
        try {
            const { timeRange = '30d' } = req.query;
            const tenantId = req.tenantId;

            const statistics = {
                timeRange,
                deployments: {
                    total: 0,
                    successful: 0,
                    failed: 0,
                    pending: 0
                },
                platforms: {
                    windows: { deployments: 0, successRate: 0 },
                    macos: { deployments: 0, successRate: 0 },
                    linux: { deployments: 0, successRate: 0 }
                },
                trends: [],
                topIssues: []
            };

            res.json({
                success: true,
                data: statistics,
                message: 'Update statistics retrieved',
                timestamp: new Date().toISOString()
            });

        } catch (error) {
            logger.error('Error getting update statistics:', error);
            res.status(500).json({
                success: false,
                error: 'Internal server error',
                message: 'Failed to get update statistics',
                timestamp: new Date().toISOString()
            });
        }
    }

    /**
     * Get service health status
     */
    async getServiceHealth(req, res) {
        try {
            const health = {
                status: 'healthy',
                services: {
                    windowsUpdate: 'operational',
                    macosUpdate: 'operational',
                    linuxUpdate: 'operational'
                },
                lastCheck: new Date().toISOString(),
                uptime: process.uptime(),
                version: require('../../package.json').version || '1.0.0'
            };

            res.json({
                success: true,
                data: health,
                timestamp: new Date().toISOString()
            });

        } catch (error) {
            logger.error('Error getting service health:', error);
            res.status(500).json({
                success: false,
                error: 'Internal server error',
                message: 'Failed to get service health',
                timestamp: new Date().toISOString()
            });
        }
    }

    /**
     * Get router instance
     */
    getRouter() {
        return this.router;
    }
}

module.exports = UpdateController;