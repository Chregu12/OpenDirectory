'use strict';

const axios = require('axios');
const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'app-store-detection' },
  transports: [new winston.transports.Console()],
});

const DEVICE_SERVICE_URL = process.env.DEVICE_SERVICE_URL || 'http://device-service:3903';
const IDENTITY_SERVICE_URL = process.env.IDENTITY_SERVICE_URL || 'http://authentication-service:3001';
const DIRECTORY_SERVICE_URL = process.env.DIRECTORY_SERVICE_URL || 'http://enterprise-directory:3002';

class ClientDetector {
  constructor(pool) {
    this.pool = pool;
  }

  /**
   * Detect client context from device ID and request
   * @param {string} deviceId - The device identifier
   * @param {object} requestContext - Additional request context (headers, user info)
   * @returns {object} Client information including platform, domain, groups, OU, userId
   */
  async detectClient(deviceId, requestContext = {}) {
    const clientInfo = {
      deviceId,
      platform: null,
      domain: null,
      groups: [],
      ou: null,
      userId: requestContext.userId || null,
      hostname: null,
    };

    // 1. Look up device in device-service
    try {
      const deviceResponse = await axios.get(`${DEVICE_SERVICE_URL}/api/devices/${deviceId}`, {
        timeout: 5000,
        headers: { 'X-Internal-Service': 'app-store' },
      });

      const device = deviceResponse.data;
      clientInfo.platform = this._normalizePlatform(device.os_type || device.platform);
      clientInfo.hostname = device.hostname || device.name;
      clientInfo.domain = device.domain || device.ad_domain || null;
      clientInfo.ou = device.ou || device.organizational_unit || null;
    } catch (error) {
      logger.warn('Failed to fetch device info from device-service, using request context', {
        deviceId,
        error: error.message,
      });
      // Fall back to request context if device-service is unavailable
      clientInfo.platform = requestContext.platform || null;
      clientInfo.hostname = requestContext.hostname || null;
    }

    // 2. Get user's group memberships from identity-service
    if (clientInfo.userId) {
      try {
        const groupsResponse = await axios.get(
          `${IDENTITY_SERVICE_URL}/api/users/${clientInfo.userId}/groups`,
          {
            timeout: 5000,
            headers: { 'X-Internal-Service': 'app-store' },
          }
        );

        clientInfo.groups = (groupsResponse.data || []).map(
          (g) => g.name || g.cn || g.id
        );
      } catch (error) {
        logger.warn('Failed to fetch user groups from identity-service', {
          userId: clientInfo.userId,
          error: error.message,
        });
      }
    }

    // 3. Get additional domain/OU info from directory service if not already present
    if (!clientInfo.domain || !clientInfo.ou) {
      try {
        const dirResponse = await axios.get(
          `${DIRECTORY_SERVICE_URL}/api/directory/devices/${deviceId}`,
          {
            timeout: 5000,
            headers: { 'X-Internal-Service': 'app-store' },
          }
        );

        const dirInfo = dirResponse.data;
        if (!clientInfo.domain) {
          clientInfo.domain = dirInfo.domain || null;
        }
        if (!clientInfo.ou) {
          clientInfo.ou = dirInfo.ou || dirInfo.organizational_unit || null;
        }
      } catch (error) {
        logger.debug('Failed to fetch directory info', {
          deviceId,
          error: error.message,
        });
      }
    }

    logger.info('Client detected', {
      deviceId,
      platform: clientInfo.platform,
      domain: clientInfo.domain,
      groupCount: clientInfo.groups.length,
      ou: clientInfo.ou,
    });

    return clientInfo;
  }

  /**
   * Get the personalized list of available apps for a client
   * @param {object} clientInfo - Client information from detectClient()
   * @returns {object} { required: [], available: [] }
   */
  async getAvailableApps(clientInfo) {
    const { platform, domain, groups, ou, userId, deviceId } = clientInfo;

    // 1. Get all enabled apps for the client's platform
    let platformCondition = '';
    const params = [];
    let paramIndex = 1;

    if (platform) {
      platformCondition = `AND platforms @> $${paramIndex}::jsonb`;
      params.push(JSON.stringify([platform]));
      paramIndex++;
    }

    const appsResult = await this.pool.query(
      `SELECT * FROM store_apps WHERE enabled = true ${platformCondition} ORDER BY display_name ASC`,
      params
    );

    const allApps = appsResult.rows;

    // 2. Get all assignments that match this client
    const assignmentConditions = [];
    const assignmentParams = [];
    let aParamIndex = 1;

    // Domain assignments
    if (domain) {
      assignmentConditions.push(`(target_type = 'domain' AND target_id = $${aParamIndex})`);
      assignmentParams.push(domain);
      aParamIndex++;
    }

    // OU assignments
    if (ou) {
      assignmentConditions.push(`(target_type = 'ou' AND target_id = $${aParamIndex})`);
      assignmentParams.push(ou);
      aParamIndex++;
    }

    // Group assignments
    for (const group of groups) {
      assignmentConditions.push(`(target_type = 'group' AND target_id = $${aParamIndex})`);
      assignmentParams.push(group);
      aParamIndex++;
    }

    // Device-specific assignments
    if (deviceId) {
      assignmentConditions.push(`(target_type = 'device' AND target_id = $${aParamIndex})`);
      assignmentParams.push(deviceId);
      aParamIndex++;
    }

    // User-specific assignments
    if (userId) {
      assignmentConditions.push(`(target_type = 'user' AND target_id = $${aParamIndex})`);
      assignmentParams.push(userId);
      aParamIndex++;
    }

    let assignments = [];
    if (assignmentConditions.length > 0) {
      const assignmentResult = await this.pool.query(
        `SELECT * FROM store_assignments WHERE ${assignmentConditions.join(' OR ')}`,
        assignmentParams
      );
      assignments = assignmentResult.rows;
    }

    // 3. Build assignment map: appId -> install_type
    const assignmentMap = new Map();
    for (const assignment of assignments) {
      const existing = assignmentMap.get(assignment.app_id);
      // "required" takes precedence over "available", "uninstall" overrides both
      if (!existing || assignment.install_type === 'required' || assignment.install_type === 'uninstall') {
        assignmentMap.set(assignment.app_id, assignment.install_type);
      }
    }

    // 4. Split apps into required, available, and uninstall
    const required = [];
    const available = [];
    const uninstall = [];

    for (const app of allApps) {
      const installType = assignmentMap.get(app.id);

      if (installType === 'uninstall') {
        uninstall.push({ ...app, install_type: 'uninstall' });
      } else if (installType === 'required' || app.required) {
        required.push({ ...app, install_type: 'required' });
      } else {
        // Available if there is an assignment for it, or if there are no assignments at all (open catalog)
        available.push({ ...app, install_type: 'available' });
      }
    }

    return { required, available, uninstall };
  }

  /**
   * Get installed apps for a device
   */
  async getInstalledApps(deviceId) {
    const result = await this.pool.query(
      `SELECT si.*, sa.name as app_name, sa.display_name, sa.category, sa.icon_url, sa.packages, sa.platforms
       FROM store_installations si
       JOIN store_apps sa ON si.app_id = sa.id
       WHERE si.device_id = $1 AND si.status IN ('installed', 'installing', 'downloading', 'pending')
       ORDER BY si.installed_at DESC NULLS LAST`,
      [deviceId]
    );
    return result.rows;
  }

  /**
   * Normalize platform string to standard format
   */
  _normalizePlatform(platform) {
    if (!platform) return null;
    const p = platform.toLowerCase();
    if (p.includes('win')) return 'windows';
    if (p.includes('mac') || p.includes('darwin')) return 'macos';
    if (p.includes('linux') || p.includes('ubuntu') || p.includes('debian') || p.includes('centos') || p.includes('fedora')) return 'linux';
    return p;
  }
}

module.exports = ClientDetector;
