'use strict';

const semver = require('semver');

const CHANNELS = ['stable', 'beta', 'latest'];

class VersionManager {
  constructor(pool, redis, logger) {
    this.pool = pool;
    this.redis = redis;
    this.logger = logger;
  }

  /**
   * Add a new version to an app.
   */
  async addVersion(appId, { version, changelog = '', channel = 'stable' }) {
    if (!version) throw new Error('Version string is required');

    const cleaned = semver.clean(version) || version;
    if (!semver.valid(cleaned) && !this._isLooseVersion(version)) {
      this.logger.warn('Version is not strict semver, storing as-is', { appId, version });
    }

    if (!CHANNELS.includes(channel)) {
      throw new Error(`Invalid channel. Must be one of: ${CHANNELS.join(', ')}`);
    }

    // Verify app exists
    const appCheck = await this.pool.query('SELECT id FROM apps WHERE id = $1', [appId]);
    if (appCheck.rows.length === 0) throw new Error('App not found');

    const result = await this.pool.query(
      `INSERT INTO app_versions (app_id, version, changelog, channel)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (app_id, version) DO UPDATE SET changelog = $3, channel = $4
       RETURNING *`,
      [appId, cleaned || version, changelog, channel]
    );

    this.logger.info('Version added', { appId, version: cleaned || version, channel });
    return result.rows[0];
  }

  /**
   * Get all versions for an app, sorted by semver descending.
   */
  async getVersions(appId) {
    const result = await this.pool.query(
      `SELECT * FROM app_versions WHERE app_id = $1 ORDER BY released_at DESC`,
      [appId]
    );

    const versions = result.rows;

    // Sort by semver if possible
    versions.sort((a, b) => {
      const va = semver.valid(semver.clean(a.version));
      const vb = semver.valid(semver.clean(b.version));
      if (va && vb) return semver.rcompare(va, vb);
      if (va) return -1;
      if (vb) return 1;
      return b.released_at - a.released_at;
    });

    return versions;
  }

  /**
   * Get the latest version of an app on a given channel.
   */
  async getLatestVersion(appId, channel = 'stable') {
    const versions = await this.pool.query(
      `SELECT * FROM app_versions WHERE app_id = $1 AND channel = $2 ORDER BY released_at DESC`,
      [appId, channel]
    );

    if (versions.rows.length === 0) return null;

    // Try to find the highest semver
    const semverVersions = versions.rows
      .map((v) => ({ ...v, parsed: semver.valid(semver.clean(v.version)) }))
      .filter((v) => v.parsed);

    if (semverVersions.length > 0) {
      semverVersions.sort((a, b) => semver.rcompare(a.parsed, b.parsed));
      return semverVersions[0];
    }

    // Fall back to most recently released
    return versions.rows[0];
  }

  /**
   * Get the full changelog for an app (all versions).
   */
  async getChangelog(appId) {
    const versions = await this.getVersions(appId);
    return versions.map((v) => ({
      version: v.version,
      channel: v.channel,
      changelog: v.changelog,
      released_at: v.released_at,
    }));
  }

  /**
   * Check if a newer version is available compared to the given installed version.
   */
  async checkForUpdate(appId, installedVersion, channel = 'stable') {
    const latest = await this.getLatestVersion(appId, channel);
    if (!latest) return null;

    const installedClean = semver.clean(installedVersion) || installedVersion;
    const latestClean = semver.clean(latest.version) || latest.version;

    if (semver.valid(installedClean) && semver.valid(latestClean)) {
      if (semver.gt(latestClean, installedClean)) {
        return latest;
      }
      return null;
    }

    // Fallback: string comparison
    if (latestClean !== installedClean) return latest;
    return null;
  }

  /**
   * Get a specific version.
   */
  async getVersion(appId, version) {
    const cleaned = semver.clean(version) || version;
    const result = await this.pool.query(
      `SELECT * FROM app_versions WHERE app_id = $1 AND version = $2`,
      [appId, cleaned]
    );
    return result.rows[0] || null;
  }

  /**
   * Delete a specific version (rollback support).
   */
  async deleteVersion(appId, version) {
    const cleaned = semver.clean(version) || version;
    const result = await this.pool.query(
      `DELETE FROM app_versions WHERE app_id = $1 AND version = $2 RETURNING *`,
      [appId, cleaned]
    );
    if (result.rows.length === 0) throw new Error('Version not found');
    this.logger.info('Version deleted', { appId, version: cleaned });
    return { deleted: true };
  }

  /**
   * Get the previous version for rollback.
   */
  async getPreviousVersion(appId, currentVersion, channel = 'stable') {
    const versions = await this.pool.query(
      `SELECT * FROM app_versions WHERE app_id = $1 AND channel = $2 ORDER BY released_at DESC`,
      [appId, channel]
    );

    const currentClean = semver.clean(currentVersion) || currentVersion;
    const list = versions.rows;

    for (let i = 0; i < list.length; i++) {
      const v = semver.clean(list[i].version) || list[i].version;
      if (semver.valid(v) && semver.valid(currentClean)) {
        if (semver.lt(v, currentClean)) return list[i];
      } else if (v !== currentClean && i > 0) {
        return list[i];
      }
    }

    return null;
  }

  /**
   * Loose version check for non-semver strings like "2024.1" etc.
   */
  _isLooseVersion(version) {
    return /^\d+(\.\d+)*/.test(version);
  }
}

module.exports = { VersionManager, CHANNELS };
