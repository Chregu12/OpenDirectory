'use strict';

const { Router } = require('express');

/**
 * Client-facing self-service App Store routes.
 * These endpoints are used by devices/users to browse, install, and manage apps.
 */
function createStoreRoutes(
  catalogManager,
  versionManager,
  assignmentEngine,
  licenseManager,
  distributionEngine,
  installTracker,
  clientDetector,
  domainResolver,
  logger
) {
  const router = Router();

  // -------------------------------------------------------------------------
  // Middleware: detect client context for store routes
  // -------------------------------------------------------------------------
  async function detectContext(req, res, next) {
    try {
      req.clientContext = await clientDetector.detectClient(req);
      next();
    } catch (err) {
      logger.error('Client detection failed', { error: err.message });
      req.clientContext = { deviceId: null, platform: null, domain: null, groups: [], ou: null, userId: null };
      next();
    }
  }

  // -------------------------------------------------------------------------
  // Browse & Search
  // -------------------------------------------------------------------------

  /**
   * GET /api/store/browse - Browse available apps (auto-filtered by client context)
   */
  router.get('/browse', detectContext, async (req, res, next) => {
    try {
      const apps = await domainResolver.getAppsForContext(req.clientContext);

      // Apply optional category filter from query
      let filtered = apps;
      if (req.query.category) {
        filtered = filtered.filter((a) => a.category === req.query.category);
      }

      // Pagination
      const limit = parseInt(req.query.limit, 10) || 50;
      const offset = parseInt(req.query.offset, 10) || 0;
      const paginated = filtered.slice(offset, offset + limit);

      res.json({
        apps: paginated,
        total: filtered.length,
        limit,
        offset,
        context: {
          deviceId: req.clientContext.deviceId,
          platform: req.clientContext.platform,
          domain: req.clientContext.domain,
        },
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/store/browse/:id - App detail page
   */
  router.get('/browse/:id', detectContext, async (req, res, next) => {
    try {
      const app = await catalogManager.getApp(req.params.id);
      if (!app) return res.status(404).json({ error: 'App not found' });

      // Get latest version info
      const latestVersion = await versionManager.getLatestVersion(req.params.id);
      const changelog = await versionManager.getChangelog(req.params.id);

      // Check license availability
      const licenseInfo = await licenseManager.checkAvailability(req.params.id);

      // Check if installed on requesting device
      let installed = false;
      if (req.clientContext.deviceId) {
        const installedApps = await installTracker.getInstalledApps(req.clientContext.deviceId);
        installed = installedApps.some((a) => a.app_id === req.params.id);
      }

      // Get platform-specific info
      let platformPackage = null;
      if (req.clientContext.platform && app.platforms) {
        const platforms = typeof app.platforms === 'string' ? JSON.parse(app.platforms) : app.platforms;
        platformPackage = platforms[req.clientContext.platform] || null;
      }

      res.json({
        ...app,
        latestVersion: latestVersion || null,
        changelog,
        licenseAvailable: licenseInfo.available,
        installed,
        platformPackage,
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/store/search - Search apps
   */
  router.get('/search', detectContext, async (req, res, next) => {
    try {
      const { q, category, limit = 50, offset = 0 } = req.query;

      if (!q) return res.status(400).json({ error: 'Search query "q" is required' });

      const result = await catalogManager.searchApps(q, {
        limit: parseInt(limit, 10),
        offset: parseInt(offset, 10),
        category,
        platform: req.clientContext.platform,
      });

      res.json(result);
    } catch (err) {
      next(err);
    }
  });

  // -------------------------------------------------------------------------
  // My Apps & Installed
  // -------------------------------------------------------------------------

  /**
   * GET /api/store/my-apps - Installed apps on requesting device
   */
  router.get('/my-apps', detectContext, async (req, res, next) => {
    try {
      const deviceId = req.clientContext.deviceId || req.query.deviceId;
      if (!deviceId) {
        return res.status(400).json({ error: 'Device ID is required (via header or query)' });
      }

      const installedApps = await installTracker.getInstalledApps(deviceId);

      // Enrich with update availability
      const enriched = await Promise.all(
        installedApps.map(async (app) => {
          const latestVersion = await versionManager.getLatestVersion(app.app_id);
          return {
            ...app,
            latestVersion: latestVersion?.version || null,
            updateAvailable: latestVersion && app.version
              ? latestVersion.version !== app.version
              : false,
          };
        })
      );

      res.json({ apps: enriched, deviceId });
    } catch (err) {
      next(err);
    }
  });

  // -------------------------------------------------------------------------
  // Install / Uninstall
  // -------------------------------------------------------------------------

  /**
   * POST /api/store/install - Request app installation
   */
  router.post('/install', detectContext, async (req, res, next) => {
    try {
      const appId = req.body.appId;
      const deviceId = req.body.deviceId || req.clientContext.deviceId;

      if (!appId) return res.status(400).json({ error: 'appId is required' });
      if (!deviceId) return res.status(400).json({ error: 'deviceId is required' });

      const job = await distributionEngine.requestInstall(appId, deviceId, req.body.version || null);
      res.status(202).json({
        message: 'Installation requested',
        job,
      });
    } catch (err) {
      if (err.message === 'App not found') {
        return res.status(404).json({ error: err.message });
      }
      if (err.message.includes('license')) {
        return res.status(409).json({ error: err.message });
      }
      next(err);
    }
  });

  /**
   * POST /api/store/uninstall - Request app uninstall
   */
  router.post('/uninstall', detectContext, async (req, res, next) => {
    try {
      const appId = req.body.appId;
      const deviceId = req.body.deviceId || req.clientContext.deviceId;

      if (!appId) return res.status(400).json({ error: 'appId is required' });
      if (!deviceId) return res.status(400).json({ error: 'deviceId is required' });

      const job = await distributionEngine.requestUninstall(appId, deviceId);
      res.status(202).json({
        message: 'Uninstallation requested',
        job,
      });
    } catch (err) {
      if (err.message === 'App not found') {
        return res.status(404).json({ error: err.message });
      }
      next(err);
    }
  });

  // -------------------------------------------------------------------------
  // Installation progress
  // -------------------------------------------------------------------------

  /**
   * GET /api/store/install/:jobId/status - Installation progress
   */
  router.get('/install/:jobId/status', async (req, res, next) => {
    try {
      const job = await installTracker.getInstallStatus(req.params.jobId);
      if (!job) return res.status(404).json({ error: 'Job not found' });
      res.json(job);
    } catch (err) {
      next(err);
    }
  });

  // -------------------------------------------------------------------------
  // Updates
  // -------------------------------------------------------------------------

  /**
   * GET /api/store/updates - Available updates for device
   */
  router.get('/updates', detectContext, async (req, res, next) => {
    try {
      const deviceId = req.clientContext.deviceId || req.query.deviceId;
      if (!deviceId) {
        return res.status(400).json({ error: 'Device ID is required' });
      }

      const installedApps = await installTracker.getInstalledApps(deviceId);
      const updates = [];

      for (const app of installedApps) {
        if (app.version) {
          const update = await versionManager.checkForUpdate(app.app_id, app.version);
          if (update) {
            updates.push({
              appId: app.app_id,
              appName: app.app_name,
              currentVersion: app.version,
              availableVersion: update.version,
              changelog: update.changelog,
              channel: update.channel,
            });
          }
        }
      }

      res.json({ updates, deviceId, count: updates.length });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/store/update-all - Update all apps on device
   */
  router.post('/update-all', detectContext, async (req, res, next) => {
    try {
      const deviceId = req.body.deviceId || req.clientContext.deviceId;
      if (!deviceId) {
        return res.status(400).json({ error: 'Device ID is required' });
      }

      const installedApps = await installTracker.getInstalledApps(deviceId);
      const results = [];

      for (const app of installedApps) {
        if (app.version) {
          const update = await versionManager.checkForUpdate(app.app_id, app.version);
          if (update) {
            try {
              const job = await distributionEngine.requestUpdate(app.app_id, deviceId, update.version);
              results.push({
                appId: app.app_id,
                appName: app.app_name,
                targetVersion: update.version,
                jobId: job.id,
                status: 'queued',
              });
            } catch (err) {
              results.push({
                appId: app.app_id,
                appName: app.app_name,
                error: err.message,
                status: 'failed',
              });
            }
          }
        }
      }

      res.status(202).json({
        message: 'Update requests submitted',
        updates: results,
        deviceId,
      });
    } catch (err) {
      next(err);
    }
  });

  // -------------------------------------------------------------------------
  // Mandatory apps
  // -------------------------------------------------------------------------

  /**
   * GET /api/store/mandatory - List mandatory apps for device
   */
  router.get('/mandatory', detectContext, async (req, res, next) => {
    try {
      const deviceId = req.clientContext.deviceId || req.query.deviceId;

      // Get globally mandatory apps
      const mandatoryResult = await catalogManager.listApps({
        mandatory: true,
        platform: req.clientContext.platform,
        limit: 1000,
      });

      // Get assignment-based mandatory apps
      let assignmentMandatory = [];
      if (deviceId) {
        assignmentMandatory = await assignmentEngine.getMandatoryAppsForDevice(
          deviceId,
          req.clientContext
        );
      }

      // Merge and deduplicate
      const appMap = new Map();
      for (const app of mandatoryResult.apps) {
        appMap.set(app.id, { ...app, source: 'global' });
      }
      for (const assignment of assignmentMandatory) {
        if (!appMap.has(assignment.app_id)) {
          appMap.set(assignment.app_id, {
            id: assignment.app_id,
            name: assignment.app_name,
            source: `assignment:${assignment.target_type}:${assignment.target_id}`,
          });
        }
      }

      res.json({
        apps: Array.from(appMap.values()),
        count: appMap.size,
        deviceId: deviceId || null,
      });
    } catch (err) {
      next(err);
    }
  });

  // -------------------------------------------------------------------------
  // Categories (client-facing)
  // -------------------------------------------------------------------------

  /**
   * GET /api/store/categories - Browse by category (client view)
   */
  router.get('/client-categories', detectContext, async (req, res, next) => {
    try {
      const categories = catalogManager.getCategories();

      // Get counts per category for the current platform
      const categoryCounts = await Promise.all(
        categories.map(async (cat) => {
          const result = await catalogManager.listApps({
            category: cat,
            platform: req.clientContext.platform,
            limit: 1,
          });
          return { category: cat, count: result.total };
        })
      );

      res.json({
        categories: categoryCounts.filter((c) => c.count > 0),
      });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

module.exports = { createStoreRoutes };
