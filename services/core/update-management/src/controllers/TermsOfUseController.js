const express = require('express');
const { requirePermission } = require('../middleware/auth');
const logger = require('../utils/logger').logger;

class TermsOfUseController {
    constructor(termsOfUseService) {
        this.termsOfUseService = termsOfUseService;
        this.router = express.Router();
        this.setupRoutes();
    }

    setupRoutes() {
        this.router.get('/', requirePermission('terms:read'), this.getTerms.bind(this));
        this.router.post('/', requirePermission('terms:write'), this.createTerms.bind(this));
        this.router.get('/:termsId', requirePermission('terms:read'), this.getTerm.bind(this));
        this.router.put('/:termsId', requirePermission('terms:write'), this.updateTerms.bind(this));
        this.router.delete('/:termsId', requirePermission('terms:delete'), this.deleteTerms.bind(this));
        this.router.post('/:termsId/publish', requirePermission('terms:publish'), this.publishTerms.bind(this));
        this.router.post('/accept', this.recordAcceptance.bind(this));
        this.router.get('/users/:userId/compliance', requirePermission('compliance:read'), this.checkCompliance.bind(this));
    }

    async getTerms(req, res) {
        res.json({ success: true, data: [], timestamp: new Date().toISOString() });
    }

    async createTerms(req, res) {
        try {
            const result = await this.termsOfUseService.createTermsOfUse(req.body);
            res.status(201).json({ success: true, data: result, timestamp: new Date().toISOString() });
        } catch (error) {
            logger.error('Error creating terms:', error);
            res.status(500).json({ success: false, error: 'Failed to create terms', timestamp: new Date().toISOString() });
        }
    }

    async getTerm(req, res) {
        res.json({ success: true, data: { id: req.params.termsId }, timestamp: new Date().toISOString() });
    }

    async updateTerms(req, res) {
        res.json({ success: true, data: { id: req.params.termsId }, timestamp: new Date().toISOString() });
    }

    async deleteTerms(req, res) {
        res.json({ success: true, message: 'Terms deleted', timestamp: new Date().toISOString() });
    }

    async publishTerms(req, res) {
        try {
            const result = await this.termsOfUseService.publishTermsOfUse(req.params.termsId, req.body);
            res.json({ success: true, data: result, message: 'Terms published', timestamp: new Date().toISOString() });
        } catch (error) {
            logger.error('Error publishing terms:', error);
            res.status(500).json({ success: false, error: 'Failed to publish terms', timestamp: new Date().toISOString() });
        }
    }

    async recordAcceptance(req, res) {
        try {
            const result = await this.termsOfUseService.recordAcceptance(req.body);
            res.json({ success: true, data: result, message: 'Acceptance recorded', timestamp: new Date().toISOString() });
        } catch (error) {
            logger.error('Error recording acceptance:', error);
            res.status(500).json({ success: false, error: 'Failed to record acceptance', timestamp: new Date().toISOString() });
        }
    }

    async checkCompliance(req, res) {
        try {
            const result = await this.termsOfUseService.checkUserCompliance(req.params.userId);
            res.json({ success: true, data: result, timestamp: new Date().toISOString() });
        } catch (error) {
            logger.error('Error checking compliance:', error);
            res.status(500).json({ success: false, error: 'Failed to check compliance', timestamp: new Date().toISOString() });
        }
    }

    getRouter() {
        return this.router;
    }
}

module.exports = TermsOfUseController;