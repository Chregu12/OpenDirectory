'use strict';

const { Router } = require('express');
const multer = require('multer');

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB
});

/**
 * Admin API routes for the App Store.
 */
function createAdminRoutes(catalogManager, versionManager, assignmentEngine, licenseManager, installTracker, logger) {
  const router = Router();

  // -------------------------------------------------------------------------
  // Catalog CRUD
  // -------------------------------------------------------------------------

  /**
   * GET /api/store/catalog - List all apps (admin view)
   */
  router.get('/catalog', async (req, res, next) => {
    try {
      const {
        limit = 50,
        offset = 0,
        category,
        platform,
        mandatory,
        featured,
        sortBy = 'name',
        sortOrder = 'ASC',
      } = req.query;

      const result = await catalogManager.listApps({
        limit: parseInt(limit, 10),
        offset: parseInt(offset, 10),
        category,
        platform,
        mandatory: mandatory !== undefined ? mandatory === 'true' : undefined,
        featured: featured !== undefined ? featured === 'true' : undefined,
        sortBy,
        sortOrder,
      });

      res.json(result);
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/store/catalog - Add a new app
   */
  router.post('/catalog', async (req, res, next) => {
    try {
      const app = await catalogManager.createApp(req.body);
      res.status(201).json(app);
    } catch (err) {
      if (err.message.includes('required') || err.message.includes('Invalid')) {
        return res.status(400).json({ error: err.message });
      }
      next(err);
    }
  });

  /**
   * GET /api/store/catalog/:id - Get app details
   */
  router.get('/catalog/:id', async (req, res, next) => {
    try {
      const app = await catalogManager.getApp(req.params.id);
      if (!app) return res.status(404).json({ error: 'App not found' });
      res.json(app);
    } catch (err) {
      next(err);
    }
  });

  /**
   * PUT /api/store/catalog/:id - Update an app
   */
  router.put('/catalog/:id', async (req, res, next) => {
    try {
      const app = await catalogManager.updateApp(req.params.id, req.body);
      res.json(app);
    } catch (err) {
      if (err.message === 'App not found') {
        return res.status(404).json({ error: err.message });
      }
      if (err.message.includes('Invalid') || err.message.includes('No fields')) {
        return res.status(400).json({ error: err.message });
      }
      next(err);
    }
  });

  /**
   * DELETE /api/store/catalog/:id - Delete an app
   */
  router.delete('/catalog/:id', async (req, res, next) => {
    try {
      const result = await catalogManager.deleteApp(req.params.id);
      res.json(result);
    } catch (err) {
      if (err.message === 'App not found') {
        return res.status(404).json({ error: err.message });
      }
      next(err);
    }
  });

  // -------------------------------------------------------------------------
  // Versions
  // -------------------------------------------------------------------------

  /**
   * POST /api/store/catalog/:id/versions - Add a version
   */
  router.post('/catalog/:id/versions', async (req, res, next) => {
    try {
      const version = await versionManager.addVersion(req.params.id, req.body);
      res.status(201).json(version);
    } catch (err) {
      if (err.message === 'App not found' || err.message === 'Version string is required') {
        return res.status(400).json({ error: err.message });
      }
      next(err);
    }
  });

  /**
   * GET /api/store/catalog/:id/versions - List versions
   */
  router.get('/catalog/:id/versions', async (req, res, next) => {
    try {
      const versions = await versionManager.getVersions(req.params.id);
      res.json({ appId: req.params.id, versions });
    } catch (err) {
      next(err);
    }
  });

  // -------------------------------------------------------------------------
  // Assignments
  // -------------------------------------------------------------------------

  /**
   * POST /api/store/assignments - Create assignment
   */
  router.post('/assignments', async (req, res, next) => {
    try {
      const { appId, targetType, targetId, assignmentType } = req.body;
      if (!appId || !targetType || !targetId) {
        return res.status(400).json({ error: 'appId, targetType, and targetId are required' });
      }
      const assignment = await assignmentEngine.assignApp(appId, targetType, targetId, assignmentType);
      res.status(201).json(assignment);
    } catch (err) {
      if (err.message.includes('Invalid') || err.message === 'App not found') {
        return res.status(400).json({ error: err.message });
      }
      next(err);
    }
  });

  /**
   * DELETE /api/store/assignments/:id - Remove assignment
   */
  router.delete('/assignments/:id', async (req, res, next) => {
    try {
      const result = await assignmentEngine.unassignApp(req.params.id);
      res.json(result);
    } catch (err) {
      if (err.message === 'Assignment not found') {
        return res.status(404).json({ error: err.message });
      }
      next(err);
    }
  });

  /**
   * GET /api/store/assignments - List all assignments
   */
  router.get('/assignments', async (req, res, next) => {
    try {
      const { appId, targetType, targetId, assignmentType, limit = 100, offset = 0 } = req.query;
      const result = await assignmentEngine.listAssignments({
        appId,
        targetType,
        targetId,
        assignmentType,
        limit: parseInt(limit, 10),
        offset: parseInt(offset, 10),
      });
      res.json(result);
    } catch (err) {
      next(err);
    }
  });

  // -------------------------------------------------------------------------
  // Licenses
  // -------------------------------------------------------------------------

  /**
   * GET /api/store/licenses - License overview
   */
  router.get('/licenses', async (req, res, next) => {
    try {
      const overview = await licenseManager.getLicenseOverview();
      res.json({ licenses: overview });
    } catch (err) {
      next(err);
    }
  });

  /**
   * PUT /api/store/licenses/:appId - Update license count/type
   */
  router.put('/licenses/:appId', async (req, res, next) => {
    try {
      const { licenseType, totalCount } = req.body;
      const license = await licenseManager.setLicense(req.params.appId, {
        licenseType,
        totalCount: parseInt(totalCount, 10) || 0,
      });
      res.json(license);
    } catch (err) {
      if (err.message.includes('Invalid')) {
        return res.status(400).json({ error: err.message });
      }
      next(err);
    }
  });

  // -------------------------------------------------------------------------
  // Analytics
  // -------------------------------------------------------------------------

  /**
   * GET /api/store/analytics - Install analytics
   */
  router.get('/analytics', async (req, res, next) => {
    try {
      const analytics = await installTracker.getAnalytics();
      res.json(analytics);
    } catch (err) {
      next(err);
    }
  });

  // -------------------------------------------------------------------------
  // Categories
  // -------------------------------------------------------------------------

  /**
   * GET /api/store/categories - List categories
   */
  router.get('/categories', (_req, res) => {
    res.json({ categories: catalogManager.getCategories() });
  });

  return router;
}

module.exports = { createAdminRoutes };
