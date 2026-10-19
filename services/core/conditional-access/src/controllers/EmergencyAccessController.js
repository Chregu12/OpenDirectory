/**
 * Emergency Access (Break Glass) Controller
 * REST API endpoints for emergency access requests, approvals, and monitoring
 */

const express = require('express');

class EmergencyAccessController {
    constructor(emergencyAccessService, auditLogger) {
        this.emergencyAccessService = emergencyAccessService;
        this.auditLogger = auditLogger;
        this.router = express.Router();
        this.setupRoutes();
    }

    setupRoutes() {
        this.router.get('/accounts', this.getEmergencyAccounts.bind(this));

        this.router.post('/request', this.requestAccess.bind(this));
        this.router.post('/:requestId/approve', this.approveAccess.bind(this));
        this.router.post('/:requestId/deny', this.denyAccess.bind(this));

        this.router.post('/sessions/:accessId/terminate', this.terminateAccess.bind(this));
        this.router.post('/sessions/:accessId/activity', this.recordActivity.bind(this));
        this.router.get('/sessions/:accessId', this.getActiveAccess.bind(this));

        this.router.get('/requests/:requestId', this.getRequest.bind(this));
        this.router.get('/users/:userId/history', this.getUserHistory.bind(this));
    }

    async getEmergencyAccounts(req, res) {
        try {
            const accounts = this.emergencyAccessService.getEmergencyAccounts();

            res.json({
                success: true,
                data: accounts
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async requestAccess(req, res) {
        try {
            const { requesterInfo, emergencyDetails } = req.body;

            if (!requesterInfo || !requesterInfo.userId) {
                return res.status(400).json({
                    success: false,
                    error: 'requesterInfo.userId is required'
                });
            }
            if (!emergencyDetails || !emergencyDetails.type || !emergencyDetails.justification) {
                return res.status(400).json({
                    success: false,
                    error: 'emergencyDetails.type and emergencyDetails.justification are required'
                });
            }

            const result = await this.emergencyAccessService.requestEmergencyAccess(requesterInfo, emergencyDetails);

            await this.auditLogger.logEvent(
                'emergency_access',
                'EMERGENCY_ACCESS_REQUESTED',
                {
                    requestId: result.requestId,
                    requester: requesterInfo.userId,
                    emergencyType: emergencyDetails.type
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

    async approveAccess(req, res) {
        try {
            const { requestId } = req.params;
            const { approverInfo, approvalDetails } = req.body;

            if (!approverInfo || !approverInfo.userId) {
                return res.status(400).json({
                    success: false,
                    error: 'approverInfo.userId is required'
                });
            }

            const result = await this.emergencyAccessService.approveEmergencyAccess(
                requestId,
                approverInfo,
                approvalDetails || {}
            );

            await this.auditLogger.logEvent(
                'emergency_access',
                'EMERGENCY_ACCESS_APPROVAL_RECORDED',
                { requestId, approver: approverInfo.userId, status: result.status }
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

    async denyAccess(req, res) {
        try {
            const { requestId } = req.params;
            const { denierInfo, denialDetails } = req.body;

            if (!denierInfo || !denierInfo.userId) {
                return res.status(400).json({
                    success: false,
                    error: 'denierInfo.userId is required'
                });
            }

            const result = await this.emergencyAccessService.denyEmergencyAccess(
                requestId,
                denierInfo,
                denialDetails || {}
            );

            await this.auditLogger.logEvent(
                'emergency_access',
                'EMERGENCY_ACCESS_DENIED',
                { requestId, denier: denierInfo.userId }
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

    async terminateAccess(req, res) {
        try {
            const { accessId } = req.params;
            const reason = req.body.reason || 'MANUAL_TERMINATION';

            const result = await this.emergencyAccessService.terminateEmergencyAccess(accessId, reason);

            await this.auditLogger.logEvent(
                'emergency_access',
                'EMERGENCY_ACCESS_TERMINATED',
                { accessId, reason, terminatedBy: req.user?.id }
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
            const { accessId } = req.params;
            const activity = req.body;

            await this.emergencyAccessService.recordEmergencyActivity(accessId, activity);

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

    async getActiveAccess(req, res) {
        try {
            const { accessId } = req.params;
            const access = this.emergencyAccessService.getActiveEmergencyAccess(accessId);

            if (!access) {
                return res.status(404).json({
                    success: false,
                    error: 'Emergency access session not found'
                });
            }

            res.json({
                success: true,
                data: access
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async getRequest(req, res) {
        try {
            const { requestId } = req.params;
            const request = this.emergencyAccessService.getEmergencyAccessRequest(requestId);

            if (!request) {
                return res.status(404).json({
                    success: false,
                    error: 'Emergency access request not found'
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

    async getUserHistory(req, res) {
        try {
            const { userId } = req.params;
            const { days } = req.query;

            const history = this.emergencyAccessService.getUserEmergencyAccessHistory(
                userId,
                days ? parseInt(days, 10) : 90
            );

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

module.exports = EmergencyAccessController;
