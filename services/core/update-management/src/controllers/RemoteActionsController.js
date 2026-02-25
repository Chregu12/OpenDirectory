const express = require('express');
const { validateRequest } = require('../middleware/validation');
const { remoteActionSchemas } = require('../middleware/validation');
const { requirePermission } = require('../middleware/auth');
const logger = require('../utils/logger').logger;

class RemoteActionsController {
    constructor(remoteActionsService) {
        this.remoteActionsService = remoteActionsService;
        this.router = express.Router();
        this.setupRoutes();
    }

    setupRoutes() {
        // Device lock actions
        this.router.post('/lock',
            requirePermission('device-management:remote-actions'),
            validateRequest(remoteActionSchemas.deviceLock),
            this.lockDevice.bind(this)
        );

        // Device wipe actions
        this.router.post('/wipe',
            requirePermission('device-management:wipe'),
            validateRequest(remoteActionSchemas.deviceWipe),
            this.wipeDevice.bind(this)
        );

        // Device restart actions
        this.router.post('/restart',
            requirePermission('device-management:remote-actions'),
            validateRequest(remoteActionSchemas.deviceRestart),
            this.restartDevice.bind(this)
        );

        // Device locate actions
        this.router.post('/locate',
            requirePermission('device-management:locate'),
            validateRequest(remoteActionSchemas.deviceLocate),
            this.locateDevice.bind(this)
        );

        // Action status and management
        this.router.get('/actions/:actionId',
            requirePermission('device-management:read'),
            this.getActionStatus.bind(this)
        );

        this.router.delete('/actions/:actionId',
            requirePermission('device-management:cancel-actions'),
            this.cancelAction.bind(this)
        );
    }

    async lockDevice(req, res) {
        try {
            const result = await this.remoteActionsService.lockDevice(req.body.deviceId, {
                ...req.body,
                executor: req.user.username
            });

            res.json({
                success: true,
                data: result,
                message: 'Device lock action initiated',
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            logger.error('Error locking device:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to lock device',
                timestamp: new Date().toISOString()
            });
        }
    }

    async wipeDevice(req, res) {
        try {
            const result = await this.remoteActionsService.wipeDevice(req.body.deviceId, {
                ...req.body,
                executor: req.user.username
            });

            res.json({
                success: true,
                data: result,
                message: 'Device wipe action initiated',
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            logger.error('Error wiping device:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to wipe device',
                timestamp: new Date().toISOString()
            });
        }
    }

    async restartDevice(req, res) {
        try {
            const result = await this.remoteActionsService.restartDevice(req.body.deviceId, {
                ...req.body,
                executor: req.user.username
            });

            res.json({
                success: true,
                data: result,
                message: 'Device restart action initiated',
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            logger.error('Error restarting device:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to restart device',
                timestamp: new Date().toISOString()
            });
        }
    }

    async locateDevice(req, res) {
        try {
            const result = await this.remoteActionsService.locateDevice(req.body.deviceId, {
                ...req.body,
                executor: req.user.username
            });

            res.json({
                success: true,
                data: result,
                message: 'Device locate action initiated',
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            logger.error('Error locating device:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to locate device',
                timestamp: new Date().toISOString()
            });
        }
    }

    async getActionStatus(req, res) {
        try {
            const result = await this.remoteActionsService.getActionStatus(req.params.actionId);

            res.json({
                success: true,
                data: result,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            logger.error('Error getting action status:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to get action status',
                timestamp: new Date().toISOString()
            });
        }
    }

    async cancelAction(req, res) {
        try {
            const result = await this.remoteActionsService.cancelAction(req.params.actionId);

            res.json({
                success: true,
                data: result,
                message: 'Action cancelled',
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            logger.error('Error cancelling action:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to cancel action',
                timestamp: new Date().toISOString()
            });
        }
    }

    getRouter() {
        return this.router;
    }
}

module.exports = RemoteActionsController;