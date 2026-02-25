const express = require('express');
const { requireRole } = require('../middleware/auth');
const logger = require('../utils/logger').logger;

class MultiTenantController {
    constructor(multiTenantService) {
        this.multiTenantService = multiTenantService;
        this.router = express.Router();
        this.setupRoutes();
    }

    setupRoutes() {
        // Admin-only routes for tenant management
        this.router.get('/', requireRole('super-admin'), this.getTenants.bind(this));
        this.router.post('/', requireRole('super-admin'), this.createTenant.bind(this));
        this.router.get('/:tenantId', requireRole('super-admin'), this.getTenant.bind(this));
        this.router.put('/:tenantId', requireRole('super-admin'), this.updateTenant.bind(this));
        this.router.delete('/:tenantId', requireRole('super-admin'), this.deleteTenant.bind(this));
        this.router.get('/:tenantId/usage', requireRole('admin'), this.getTenantUsage.bind(this));
        this.router.get('/:tenantId/health', requireRole('admin'), this.getTenantHealth.bind(this));
    }

    async getTenants(req, res) {
        res.json({ success: true, data: [], timestamp: new Date().toISOString() });
    }

    async createTenant(req, res) {
        try {
            const result = await this.multiTenantService.createTenant({
                ...req.body,
                createdBy: req.user.username
            });
            res.status(201).json({ success: true, data: result, timestamp: new Date().toISOString() });
        } catch (error) {
            logger.error('Error creating tenant:', error);
            res.status(500).json({ success: false, error: 'Failed to create tenant', timestamp: new Date().toISOString() });
        }
    }

    async getTenant(req, res) {
        try {
            const result = await this.multiTenantService.getTenantInfo(req.params.tenantId);
            res.json({ success: true, data: result, timestamp: new Date().toISOString() });
        } catch (error) {
            logger.error('Error getting tenant:', error);
            res.status(500).json({ success: false, error: 'Failed to get tenant', timestamp: new Date().toISOString() });
        }
    }

    async updateTenant(req, res) {
        try {
            const result = await this.multiTenantService.updateTenant(req.params.tenantId, {
                ...req.body,
                modifiedBy: req.user.username
            });
            res.json({ success: true, data: result, timestamp: new Date().toISOString() });
        } catch (error) {
            logger.error('Error updating tenant:', error);
            res.status(500).json({ success: false, error: 'Failed to update tenant', timestamp: new Date().toISOString() });
        }
    }

    async deleteTenant(req, res) {
        res.json({ success: true, message: 'Tenant deleted', timestamp: new Date().toISOString() });
    }

    async getTenantUsage(req, res) {
        try {
            const usage = await this.multiTenantService.getTenantUsage(req.params.tenantId);
            res.json({ success: true, data: usage, timestamp: new Date().toISOString() });
        } catch (error) {
            logger.error('Error getting tenant usage:', error);
            res.status(500).json({ success: false, error: 'Failed to get tenant usage', timestamp: new Date().toISOString() });
        }
    }

    async getTenantHealth(req, res) {
        try {
            const health = await this.multiTenantService.getTenantHealthStatus(req.params.tenantId);
            res.json({ success: true, data: health, timestamp: new Date().toISOString() });
        } catch (error) {
            logger.error('Error getting tenant health:', error);
            res.status(500).json({ success: false, error: 'Failed to get tenant health', timestamp: new Date().toISOString() });
        }
    }

    getRouter() {
        return this.router;
    }
}

module.exports = MultiTenantController;