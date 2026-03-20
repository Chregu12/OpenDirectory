'use strict';

class DomainResolver {
  constructor(assignmentEngine, catalogManager, redis, logger) {
    this.assignmentEngine = assignmentEngine;
    this.catalogManager = catalogManager;
    this.redis = redis;
    this.logger = logger;
  }

  /**
   * Get all apps available for a given client context.
   * Merges: mandatory global apps + domain-specific + OU-specific + group-specific + device-specific.
   * Filters by platform and removes duplicates.
   */
  async getAppsForContext(clientContext) {
    const { deviceId, platform, domain, groups = [], ou, userId } = clientContext;

    // Step 1: Get all mandatory global apps
    const mandatoryApps = await this._getMandatoryGlobalApps(platform);

    // Step 2: Get assignments for this device context
    const assignments = await this.assignmentEngine.getAssignmentsForDevice(
      deviceId || '__none__',
      { groups, ou, domain, userId }
    );

    // Step 3: Collect all assigned app IDs
    const assignedAppIds = assignments.map((a) => a.app_id);

    // Step 4: Get full app details for assigned apps
    const assignedApps = assignedAppIds.length > 0
      ? await this.catalogManager.getAppsByIds(assignedAppIds)
      : [];

    // Step 5: Merge mandatory global + assigned apps
    const appMap = new Map();

    // Add mandatory global apps
    for (const app of mandatoryApps) {
      appMap.set(app.id, {
        ...app,
        assignmentType: 'required',
        assignmentSource: 'global_mandatory',
      });
    }

    // Add assigned apps (with assignment metadata)
    for (const app of assignedApps) {
      const assignment = assignments.find((a) => a.app_id === app.id);
      const existing = appMap.get(app.id);

      // Determine effective assignment type: required wins over available
      const assignmentType = assignment?.assignment_type || 'available';
      const effectiveType = (existing?.assignmentType === 'required' || assignmentType === 'required')
        ? 'required'
        : 'available';

      const assignmentSource = this._determineSource(assignment);

      appMap.set(app.id, {
        ...app,
        assignmentType: effectiveType,
        assignmentSource: existing ? `${existing.assignmentSource}, ${assignmentSource}` : assignmentSource,
      });
    }

    // Step 6: Filter by platform
    let result = Array.from(appMap.values());
    if (platform) {
      result = result.filter((app) => {
        if (!app.platforms) return true; // no platform restriction
        const platformData = typeof app.platforms === 'string'
          ? JSON.parse(app.platforms)
          : app.platforms;
        return platformData[platform] !== undefined;
      });
    }

    // Step 7: Sort by relevance
    result.sort((a, b) => {
      // Required apps first
      if (a.assignmentType === 'required' && b.assignmentType !== 'required') return -1;
      if (b.assignmentType === 'required' && a.assignmentType !== 'required') return 1;
      // Featured apps next
      if (a.featured && !b.featured) return -1;
      if (b.featured && !a.featured) return 1;
      // Then alphabetical
      return (a.name || '').localeCompare(b.name || '');
    });

    this.logger.debug('Apps resolved for context', {
      deviceId,
      platform,
      domain,
      totalApps: result.length,
      requiredCount: result.filter((a) => a.assignmentType === 'required').length,
    });

    return result;
  }

  /**
   * Get apps filtered by a specific domain.
   */
  async getAppsForDomain(domain, platform = null) {
    const appIds = await this.assignmentEngine.getAppIdsForTarget('domain', domain);
    if (appIds.length === 0) return [];

    const apps = await this.catalogManager.getAppsByIds(appIds.map((a) => a.app_id));

    let result = apps.map((app) => {
      const assignment = appIds.find((a) => a.app_id === app.id);
      return {
        ...app,
        assignmentType: assignment?.assignment_type || 'available',
        assignmentSource: `domain:${domain}`,
      };
    });

    if (platform) {
      result = result.filter((app) => {
        const platformData = typeof app.platforms === 'string'
          ? JSON.parse(app.platforms)
          : app.platforms;
        return platformData && platformData[platform] !== undefined;
      });
    }

    return result;
  }

  /**
   * Get apps filtered by a specific OU.
   */
  async getAppsForOU(ou, platform = null) {
    const appIds = await this.assignmentEngine.getAppIdsForTarget('ou', ou);
    if (appIds.length === 0) return [];

    const apps = await this.catalogManager.getAppsByIds(appIds.map((a) => a.app_id));

    let result = apps.map((app) => {
      const assignment = appIds.find((a) => a.app_id === app.id);
      return {
        ...app,
        assignmentType: assignment?.assignment_type || 'available',
        assignmentSource: `ou:${ou}`,
      };
    });

    if (platform) {
      result = result.filter((app) => {
        const platformData = typeof app.platforms === 'string'
          ? JSON.parse(app.platforms)
          : app.platforms;
        return platformData && platformData[platform] !== undefined;
      });
    }

    return result;
  }

  /**
   * Get all globally mandatory apps, optionally filtered by platform.
   */
  async _getMandatoryGlobalApps(platform = null) {
    const result = await this.catalogManager.listApps({
      mandatory: true,
      platform,
      limit: 1000,
    });
    return result.apps;
  }

  /**
   * Determine the assignment source label.
   */
  _determineSource(assignment) {
    if (!assignment) return 'unknown';
    const typeLabel = assignment.target_type;
    const id = assignment.target_id;
    return `${typeLabel}:${id}`;
  }
}

module.exports = { DomainResolver };
