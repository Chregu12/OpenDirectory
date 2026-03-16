'use strict';

const axios = require('axios');

class ClientDetector {
  constructor(config, redis, logger) {
    this.deviceServiceUrl = config.deviceServiceUrl;
    this.identityServiceUrl = config.identityServiceUrl;
    this.redis = redis;
    this.logger = logger;
    this.cacheTimeout = 300; // 5 minutes
  }

  /**
   * Detect client context from an HTTP request or WebSocket handshake.
   * Returns: { deviceId, platform, domain, groups, ou, userId }
   */
  async detectClient(req) {
    const context = {
      deviceId: null,
      platform: null,
      domain: null,
      groups: [],
      ou: null,
      userId: null,
    };

    // Extract device ID from header, query, or body
    context.deviceId =
      req.headers['x-device-id'] ||
      req.query?.deviceId ||
      req.body?.deviceId ||
      null;

    // Extract platform hint from header or user-agent
    context.platform =
      req.headers['x-device-platform'] ||
      req.query?.platform ||
      this._detectPlatformFromUA(req.headers['user-agent']) ||
      null;

    // Extract user ID from auth headers
    context.userId =
      req.headers['x-user-id'] ||
      req.query?.userId ||
      null;

    // Enrich from device service if we have a device ID
    if (context.deviceId) {
      const deviceInfo = await this._getDeviceInfo(context.deviceId);
      if (deviceInfo) {
        context.platform = context.platform || deviceInfo.platform || deviceInfo.os_type || null;
        context.domain = deviceInfo.domain || deviceInfo.ad_domain || null;
        context.ou = deviceInfo.ou || deviceInfo.organizational_unit || null;
        if (deviceInfo.groups) {
          context.groups = Array.isArray(deviceInfo.groups)
            ? deviceInfo.groups
            : [deviceInfo.groups];
        }
        if (!context.userId && deviceInfo.primary_user_id) {
          context.userId = deviceInfo.primary_user_id;
        }
      }
    }

    // Enrich from identity service if we have a user ID
    if (context.userId) {
      const userInfo = await this._getUserInfo(context.userId);
      if (userInfo) {
        if (userInfo.groups) {
          const userGroups = Array.isArray(userInfo.groups) ? userInfo.groups : [userInfo.groups];
          context.groups = [...new Set([...context.groups, ...userGroups])];
        }
        if (!context.domain && userInfo.domain) {
          context.domain = userInfo.domain;
        }
        if (!context.ou && userInfo.ou) {
          context.ou = userInfo.ou;
        }
      }
    }

    // Normalise platform
    context.platform = this._normalisePlatform(context.platform);

    this.logger.debug('Client detected', { context });
    return context;
  }

  /**
   * Fetch device info from device-service with caching.
   */
  async _getDeviceInfo(deviceId) {
    const cacheKey = `appstore:device:${deviceId}`;

    // Try cache first
    try {
      if (this.redis && this.redis.status === 'ready') {
        const cached = await this.redis.get(cacheKey);
        if (cached) return JSON.parse(cached);
      }
    } catch {
      // ignore cache errors
    }

    try {
      const response = await axios.get(`${this.deviceServiceUrl}/api/devices/${deviceId}`, {
        timeout: 5000,
        headers: { 'X-Internal-Service': 'app-store' },
      });

      const deviceInfo = response.data;

      // Cache the result
      try {
        if (this.redis && this.redis.status === 'ready') {
          await this.redis.setex(cacheKey, this.cacheTimeout, JSON.stringify(deviceInfo));
        }
      } catch {
        // ignore cache errors
      }

      return deviceInfo;
    } catch (err) {
      this.logger.warn('Failed to fetch device info', { deviceId, error: err.message });
      return null;
    }
  }

  /**
   * Fetch user info from identity-service with caching.
   */
  async _getUserInfo(userId) {
    const cacheKey = `appstore:user:${userId}`;

    try {
      if (this.redis && this.redis.status === 'ready') {
        const cached = await this.redis.get(cacheKey);
        if (cached) return JSON.parse(cached);
      }
    } catch {
      // ignore cache errors
    }

    try {
      const response = await axios.get(`${this.identityServiceUrl}/api/users/${userId}`, {
        timeout: 5000,
        headers: { 'X-Internal-Service': 'app-store' },
      });

      const userInfo = response.data;

      try {
        if (this.redis && this.redis.status === 'ready') {
          await this.redis.setex(cacheKey, this.cacheTimeout, JSON.stringify(userInfo));
        }
      } catch {
        // ignore cache errors
      }

      return userInfo;
    } catch (err) {
      this.logger.warn('Failed to fetch user info', { userId, error: err.message });
      return null;
    }
  }

  /**
   * Detect platform from User-Agent string.
   */
  _detectPlatformFromUA(ua) {
    if (!ua) return null;
    const lower = ua.toLowerCase();
    if (lower.includes('windows') || lower.includes('win32') || lower.includes('win64')) return 'windows';
    if (lower.includes('macintosh') || lower.includes('mac os') || lower.includes('darwin')) return 'macos';
    if (lower.includes('linux') || lower.includes('ubuntu') || lower.includes('debian') || lower.includes('centos') || lower.includes('fedora')) return 'linux';
    return null;
  }

  /**
   * Normalise platform string to canonical form.
   */
  _normalisePlatform(platform) {
    if (!platform) return null;
    const lower = platform.toLowerCase().trim();
    const mapping = {
      windows: 'windows',
      win: 'windows',
      win32: 'windows',
      win64: 'windows',
      macos: 'macos',
      mac: 'macos',
      darwin: 'macos',
      osx: 'macos',
      linux: 'linux',
      ubuntu: 'linux',
      debian: 'linux',
      centos: 'linux',
      rhel: 'linux',
      fedora: 'linux',
    };
    return mapping[lower] || lower;
  }
}

module.exports = { ClientDetector };
