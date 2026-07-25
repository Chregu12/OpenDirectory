/**
 * PIM (Privileged Identity Management) Controller
 * REST API endpoints for just-in-time privileged role elevation.
 *
 * Note: session-recording (`/pim/sessions*`) and break-glass
 * (`/pim/breakglass*`) endpoints are wired directly in index.js rather than
 * through this controller, so this router intentionally does not define
 * routes under those paths.
 */

const express = require('express');

class PIMController {
    constructor(pimService, auditLogger) {
        this.pimService = pimService;
        this.auditLogger = auditLogger;
        this.router = express.Router();
        this.setupRoutes();
    }

    setupRoutes() {
        // Privileged roles
        this.router.get('/roles', this.getRoles.bind(this));
        // Shorthand role-assignment endpoint (userId, role, justification, duration)
        this.router.post('/roles', this.assignRole.bind(this));

        // Elevation lifecycle
        this.router.post('/elevation/request', this.requestElevation.bind(this));
        this.router.post('/elevation/:requestId/approve', this.approveElevation.bind(this));
        this.router.post('/elevation/:requestId/deny', this.denyElevation.bind(this));
        this.router.post('/elevation/:elevationId/deactivate', this.deactivateElevation.bind(this));
        this.router.post('/elevation/:elevationId/activity', this.recordActivity.bind(this));

        // Reads — literal paths before the `:requestId` catch-all
        this.router.get('/elevation/active/:elevationId', this.getActiveElevation.bind(this));
        this.router.get('/elevation/:requestId', this.getElevationRequest.bind(this));

        // User-scoped views
        this.router.get('/users/:userId/elevations', this.getUserActiveElevations.bind(this));
        this.router.get('/users/:userId/history', this.getUserElevationHistory.bind(this));
    }

    async getRoles(req, res) {
        try {
            const roles = this.pimService.getPrivilegedRoles();

            res.json({
                success: true,
                data: roles
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async assignRole(req, res) {
        try {
            const { userId, role, justification, duration } = req.body;

            if (!userId || !role || !justification) {
                return res.status(400).json({
                    success: false,
                    error: 'userId, role, and justification are required'
                });
            }

            await this.auditLogger.logEvent(
                'privileged_identity',
                'ELEVATION_REQUESTED',
                { userId, role, requestedBy: req.user?.id }
            );

            const result = await this.pimService.requestElevation(userId, role, justification, duration || 8);

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

    async requestElevation(req, res) {
        try {
            const { requesterId, roleId, justification, duration } = req.body;

            if (!requesterId || !roleId || !justification) {
                return res.status(400).json({
                    success: false,
                    error: 'requesterId, roleId, and justification are required'
                });
            }

            await this.auditLogger.logEvent(
                'privileged_identity',
                'ELEVATION_REQUESTED',
                { requesterId, roleId, requestedBy: req.user?.id }
            );

            const result = await this.pimService.requestElevation(requesterId, roleId, justification, duration || 8);

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

    async approveElevation(req, res) {
        try {
            const { requestId } = req.params;
            const { approverId, justification } = req.body;

            if (!approverId) {
                return res.status(400).json({
                    success: false,
                    error: 'approverId is required'
                });
            }

            const result = await this.pimService.approveElevation(requestId, approverId, justification);

            await this.auditLogger.logEvent(
                'privileged_identity',
                'ELEVATION_APPROVED',
                { requestId, approverId, status: result.status }
            );

            res.json({
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

    async denyElevation(req, res) {
        try {
            const { requestId } = req.params;
            const { deniedBy, reason } = req.body;

            if (!deniedBy) {
                return res.status(400).json({
                    success: false,
                    error: 'deniedBy is required'
                });
            }

            const result = await this.pimService.denyElevation(requestId, deniedBy, reason);

            await this.auditLogger.logEvent(
                'privileged_identity',
                'ELEVATION_DENIED',
                { requestId, deniedBy, reason }
            );

            res.json({
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

    async deactivateElevation(req, res) {
        try {
            const { elevationId } = req.params;
            const reason = req.body.reason || 'USER_REQUEST';

            const result = await this.pimService.deactivateElevation(elevationId, reason);

            await this.auditLogger.logEvent(
                'privileged_identity',
                'ELEVATION_DEACTIVATED',
                { elevationId, reason, deactivatedBy: req.user?.id }
            );

            res.json({
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

    async recordActivity(req, res) {
        try {
            const { elevationId } = req.params;
            const activity = req.body;

            await this.pimService.recordPrivilegedActivity(elevationId, activity);

            res.status(201).json({
                success: true,
                message: 'Activity recorded'
            });

        } catch (error) {
            res.status(400).json({
                success: false,
                error: error.message
            });
        }
    }

    async getElevationRequest(req, res) {
        try {
            const { requestId } = req.params;
            const request = this.pimService.getElevationRequest(requestId);

            if (!request) {
                return res.status(404).json({
                    success: false,
                    error: 'Elevation request not found'
                });
            }

            res.json({
                success: true,
                data: request
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async getActiveElevation(req, res) {
        try {
            const { elevationId } = req.params;
            const elevation = this.pimService.getActiveElevation(elevationId);

            if (!elevation) {
                return res.status(404).json({
                    success: false,
                    error: 'Active elevation not found'
                });
            }

            res.json({
                success: true,
                data: elevation
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async getUserActiveElevations(req, res) {
        try {
            const { userId } = req.params;
            const elevations = this.pimService.getUserActiveElevations(userId);

            res.json({
                success: true,
                data: elevations
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async getUserElevationHistory(req, res) {
        try {
            const { userId } = req.params;
            const { days } = req.query;
            const history = this.pimService.getUserElevationHistory(userId, days ? parseInt(days, 10) : 30);

            res.json({
                success: true,
                data: history
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

module.exports = PIMController;
