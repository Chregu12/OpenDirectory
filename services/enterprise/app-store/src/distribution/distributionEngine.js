'use strict';

const winston = require('winston');
const amqplib = require('amqplib');
const axios = require('axios');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'app-store-distribution' },
  transports: [new winston.transports.Console()],
});

const DEVICE_SERVICE_URL = process.env.DEVICE_SERVICE_URL || 'http://device-service:3903';
const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://guest:guest@rabbitmq:5672';
const EXCHANGE_NAME = 'opendirectory.events';

class DistributionEngine {
  constructor(pool, wss) {
    this.pool = pool;
    this.wss = wss;
    this.amqpConnection = null;
    this.amqpChannel = null;
  }

  /**
   * Initialize RabbitMQ connection for event publishing
   */
  async initializeMessaging() {
    try {
      this.amqpConnection = await amqplib.connect(RABBITMQ_URL);
      this.amqpChannel = await this.amqpConnection.createChannel();
      await this.amqpChannel.assertExchange(EXCHANGE_NAME, 'topic', { durable: true });
      logger.info('RabbitMQ connection established for distribution engine');
    } catch (error) {
      logger.warn('Failed to connect to RabbitMQ, events will not be published', {
        error: error.message,
      });
    }
  }

  /**
   * Request installation of an app on a device
   * @param {string} appId - The app to install
   * @param {string} deviceId - Target device
   * @param {string} userId - Requesting user
   * @returns {object} Installation record with installId
   */
  async requestInstall(appId, deviceId, userId) {
    // 1. Verify app exists and get package info
    const appResult = await this.pool.query(
      'SELECT * FROM store_apps WHERE id = $1 AND enabled = true',
      [appId]
    );

    if (appResult.rows.length === 0) {
      throw new Error('App not found or disabled');
    }

    const app = appResult.rows[0];

    // Determine platform for this device
    const platform = await this._getDevicePlatform(deviceId);
    const packageInfo = app.packages[platform];

    if (!packageInfo) {
      throw new Error(`App "${app.display_name}" is not available for platform "${platform}"`);
    }

    // 2. Check license availability
    if (app.license_type !== 'free' && app.max_licenses) {
      if (app.used_licenses >= app.max_licenses) {
        throw new Error(`No licenses available for "${app.display_name}" (${app.used_licenses}/${app.max_licenses} used)`);
      }
    }

    // 3. Check if already installed or pending
    const existingInstall = await this.pool.query(
      `SELECT id, status FROM store_installations
       WHERE app_id = $1 AND device_id = $2 AND status IN ('pending', 'downloading', 'installing', 'installed')`,
      [appId, deviceId]
    );

    if (existingInstall.rows.length > 0) {
      const existing = existingInstall.rows[0];
      if (existing.status === 'installed') {
        throw new Error(`App "${app.display_name}" is already installed on this device`);
      }
      // Return existing pending/in-progress installation
      return { installId: existing.id, status: existing.status, alreadyInProgress: true };
    }

    // 4. Create installation record
    const installResult = await this.pool.query(
      `INSERT INTO store_installations (app_id, device_id, user_id, version, status, progress)
       VALUES ($1, $2, $3, $4, 'pending', 0) RETURNING *`,
      [appId, deviceId, userId, app.version]
    );

    const installation = installResult.rows[0];

    // 5. Send install command to device via device-service
    try {
      await axios.post(`${DEVICE_SERVICE_URL}/api/devices/${deviceId}/commands`, {
        type: 'store_install',
        data: {
          installId: installation.id,
          appId: app.id,
          appName: app.display_name,
          version: app.version,
          package: packageInfo,
        },
      }, {
        timeout: 10000,
        headers: { 'X-Internal-Service': 'app-store' },
      });

      logger.info('Install command sent to device', {
        installId: installation.id,
        deviceId,
        appName: app.display_name,
      });
    } catch (error) {
      logger.warn('Failed to send install command to device-service, device will pick up on next sync', {
        installId: installation.id,
        deviceId,
        error: error.message,
      });
    }

    // 6. Emit event to RabbitMQ
    await this._publishEvent('app.install.requested', {
      installId: installation.id,
      appId: app.id,
      appName: app.display_name,
      deviceId,
      userId,
      version: app.version,
      package: packageInfo,
    });

    return {
      installId: installation.id,
      status: 'pending',
      appName: app.display_name,
      version: app.version,
    };
  }

  /**
   * Update the status of an installation
   */
  async updateInstallStatus(installId, status, progress = null, error = null) {
    const updates = ['status = $2', 'updated_at = NOW()'];
    const params = [installId, status];
    let paramIndex = 3;

    if (progress !== null) {
      updates.push(`progress = $${paramIndex}`);
      params.push(progress);
      paramIndex++;
    }

    if (error) {
      updates.push(`error_message = $${paramIndex}`);
      params.push(error);
      paramIndex++;
    }

    if (status === 'installed') {
      updates.push('installed_at = NOW()');
      updates.push('progress = 100');
    }

    const result = await this.pool.query(
      `UPDATE store_installations SET ${updates.join(', ')} WHERE id = $1 RETURNING *`,
      params
    );

    if (result.rows.length === 0) {
      throw new Error('Installation not found');
    }

    const installation = result.rows[0];

    // If installed, increment license count
    if (status === 'installed') {
      await this.pool.query(
        'UPDATE store_apps SET used_licenses = used_licenses + 1 WHERE id = $1',
        [installation.app_id]
      );
    }

    // If failed, emit failure event
    if (status === 'failed') {
      await this._publishEvent('app.install.failed', {
        installId,
        appId: installation.app_id,
        deviceId: installation.device_id,
        error,
      });
    }

    // Broadcast status to WebSocket clients (admin dashboard)
    this._broadcastWs({
      type: 'install_status',
      data: {
        installId,
        appId: installation.app_id,
        deviceId: installation.device_id,
        status,
        progress: progress !== null ? progress : installation.progress,
        error,
      },
    });

    logger.info('Installation status updated', { installId, status, progress });
    return installation;
  }

  /**
   * Request uninstallation of an app from a device
   */
  async requestUninstall(appId, deviceId) {
    // Get app info
    const appResult = await this.pool.query('SELECT * FROM store_apps WHERE id = $1', [appId]);
    if (appResult.rows.length === 0) {
      throw new Error('App not found');
    }

    const app = appResult.rows[0];
    const platform = await this._getDevicePlatform(deviceId);
    const packageInfo = app.packages[platform];

    // Update existing installation record or create uninstall record
    const existingInstall = await this.pool.query(
      `SELECT id FROM store_installations WHERE app_id = $1 AND device_id = $2 AND status = 'installed'`,
      [appId, deviceId]
    );

    let installId;
    if (existingInstall.rows.length > 0) {
      installId = existingInstall.rows[0].id;
      await this.pool.query(
        `UPDATE store_installations SET status = 'uninstalling', updated_at = NOW() WHERE id = $1`,
        [installId]
      );
    } else {
      const result = await this.pool.query(
        `INSERT INTO store_installations (app_id, device_id, version, status)
         VALUES ($1, $2, $3, 'uninstalling') RETURNING id`,
        [appId, deviceId, app.version]
      );
      installId = result.rows[0].id;
    }

    // Send uninstall command
    try {
      await axios.post(`${DEVICE_SERVICE_URL}/api/devices/${deviceId}/commands`, {
        type: 'store_uninstall',
        data: {
          installId,
          appId: app.id,
          appName: app.display_name,
          package: packageInfo,
        },
      }, {
        timeout: 10000,
        headers: { 'X-Internal-Service': 'app-store' },
      });
    } catch (error) {
      logger.warn('Failed to send uninstall command to device-service', {
        installId,
        deviceId,
        error: error.message,
      });
    }

    // Decrement license count
    if (app.license_type !== 'free') {
      await this.pool.query(
        'UPDATE store_apps SET used_licenses = GREATEST(used_licenses - 1, 0) WHERE id = $1',
        [appId]
      );
    }

    await this._publishEvent('app.uninstall.requested', {
      installId,
      appId: app.id,
      appName: app.display_name,
      deviceId,
    });

    logger.info('Uninstall requested', { installId, appId, deviceId });
    return { installId, status: 'uninstalling' };
  }

  /**
   * Push all required apps to a device (called on enrollment or assignment change)
   */
  async pushRequiredApps(deviceId) {
    const platform = await this._getDevicePlatform(deviceId);

    // Get all required apps for this platform
    let platformCondition = '';
    const params = [];
    if (platform) {
      platformCondition = 'AND platforms @> $1::jsonb';
      params.push(JSON.stringify([platform]));
    }

    const requiredApps = await this.pool.query(
      `SELECT * FROM store_apps WHERE enabled = true AND required = true ${platformCondition}`,
      params
    );

    // Also get assigned required apps
    // For simplicity, push all globally required apps
    const results = [];
    for (const app of requiredApps.rows) {
      try {
        const result = await this.requestInstall(app.id, deviceId, 'system');
        results.push({ appId: app.id, appName: app.display_name, ...result });
      } catch (error) {
        // Skip if already installed or other non-fatal error
        logger.debug('Skipping required app push', {
          appId: app.id,
          deviceId,
          reason: error.message,
        });
        results.push({ appId: app.id, appName: app.display_name, skipped: true, reason: error.message });
      }
    }

    logger.info('Required apps pushed to device', { deviceId, total: results.length });
    return results;
  }

  /**
   * Get installation status
   */
  async getInstallStatus(installId) {
    const result = await this.pool.query(
      `SELECT si.*, sa.display_name as app_name, sa.icon_url
       FROM store_installations si
       JOIN store_apps sa ON si.app_id = sa.id
       WHERE si.id = $1`,
      [installId]
    );

    if (result.rows.length === 0) {
      return null;
    }
    return result.rows[0];
  }

  /**
   * Get installation history with optional filters
   */
  async getInstallHistory({ deviceId, appId, status, page = 1, limit = 50 } = {}) {
    const conditions = [];
    const params = [];
    let paramIndex = 1;

    if (deviceId) {
      conditions.push(`si.device_id = $${paramIndex}`);
      params.push(deviceId);
      paramIndex++;
    }

    if (appId) {
      conditions.push(`si.app_id = $${paramIndex}`);
      params.push(appId);
      paramIndex++;
    }

    if (status) {
      conditions.push(`si.status = $${paramIndex}`);
      params.push(status);
      paramIndex++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const offset = (page - 1) * limit;

    params.push(limit);
    params.push(offset);

    const result = await this.pool.query(
      `SELECT si.*, sa.display_name as app_name, sa.category, sa.icon_url
       FROM store_installations si
       JOIN store_apps sa ON si.app_id = sa.id
       ${whereClause}
       ORDER BY si.requested_at DESC
       LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`,
      params
    );

    const countResult = await this.pool.query(
      `SELECT COUNT(*) FROM store_installations si ${whereClause}`,
      params.slice(0, -2)
    );

    return {
      installations: result.rows,
      total: parseInt(countResult.rows[0].count, 10),
      page,
      limit,
    };
  }

  /**
   * Get license usage report
   */
  async getLicenseReport() {
    const result = await this.pool.query(
      `SELECT id, name, display_name, license_type, max_licenses, used_licenses
       FROM store_apps
       WHERE license_type IN ('commercial', 'enterprise') AND max_licenses IS NOT NULL
       ORDER BY display_name ASC`
    );

    return result.rows.map((app) => ({
      ...app,
      available: app.max_licenses - app.used_licenses,
      usage_percent: app.max_licenses > 0
        ? Math.round((app.used_licenses / app.max_licenses) * 100)
        : 0,
    }));
  }

  /**
   * Get the platform of a device
   */
  async _getDevicePlatform(deviceId) {
    try {
      const response = await axios.get(`${DEVICE_SERVICE_URL}/api/devices/${deviceId}`, {
        timeout: 5000,
        headers: { 'X-Internal-Service': 'app-store' },
      });
      const platform = response.data.os_type || response.data.platform || 'windows';
      return this._normalizePlatform(platform);
    } catch (error) {
      logger.warn('Could not determine device platform, defaulting to windows', {
        deviceId,
        error: error.message,
      });
      return 'windows';
    }
  }

  /**
   * Normalize platform string
   */
  _normalizePlatform(platform) {
    if (!platform) return 'windows';
    const p = platform.toLowerCase();
    if (p.includes('win')) return 'windows';
    if (p.includes('mac') || p.includes('darwin')) return 'macos';
    if (p.includes('linux')) return 'linux';
    return p;
  }

  /**
   * Publish event to RabbitMQ
   */
  async _publishEvent(routingKey, data) {
    if (!this.amqpChannel) return;
    try {
      this.amqpChannel.publish(
        EXCHANGE_NAME,
        routingKey,
        Buffer.from(JSON.stringify({ event: routingKey, data, timestamp: new Date().toISOString() })),
        { persistent: true }
      );
    } catch (error) {
      logger.warn('Failed to publish event', { routingKey, error: error.message });
    }
  }

  /**
   * Broadcast message to all WebSocket clients
   */
  _broadcastWs(message) {
    if (!this.wss) return;
    const payload = JSON.stringify(message);
    this.wss.clients.forEach((client) => {
      if (client.readyState === 1) {
        client.send(payload);
      }
    });
  }

  /**
   * Cleanup resources
   */
  async shutdown() {
    try {
      if (this.amqpChannel) await this.amqpChannel.close();
      if (this.amqpConnection) await this.amqpConnection.close();
    } catch (error) {
      logger.warn('Error during distribution engine shutdown', { error: error.message });
    }
  }
}

module.exports = DistributionEngine;
