'use strict';

class InstallTracker {
  constructor(pool, redis, logger) {
    this.pool = pool;
    this.redis = redis;
    this.logger = logger;
  }

  /**
   * Create a new install/uninstall/update job.
   */
  async createJob({ appId, deviceId, action = 'install', version = null }) {
    const result = await this.pool.query(
      `INSERT INTO install_jobs (app_id, device_id, action, status, progress, version)
       VALUES ($1, $2, $3, 'queued', 0, $4)
       RETURNING *`,
      [appId, deviceId, action, version]
    );

    const job = result.rows[0];
    this.logger.info('Install job created', { jobId: job.id, appId, deviceId, action });
    return job;
  }

  /**
   * Update job status from agent reports.
   */
  async updateJobStatus(jobId, { status, progress = 0, error = null }) {
    const updates = ['status = $2', 'progress = $3', 'error = $4'];
    const values = [jobId, status, progress, error];
    let idx = 5;

    if (status === 'downloading' || status === 'installing') {
      updates.push(`started_at = COALESCE(started_at, NOW())`);
    }
    if (status === 'completed' || status === 'failed') {
      updates.push(`completed_at = NOW()`);
      if (status === 'completed') {
        updates.push(`progress = 100`);
      }
    }

    const result = await this.pool.query(
      `UPDATE install_jobs SET ${updates.join(', ')} WHERE id = $1 RETURNING *`,
      values
    );

    if (result.rows.length === 0) {
      this.logger.warn('Install job not found for update', { jobId });
      return null;
    }

    this.logger.debug('Job status updated', { jobId, status, progress });
    return result.rows[0];
  }

  /**
   * Get a specific job.
   */
  async getJob(jobId) {
    const result = await this.pool.query(
      `SELECT j.*, a.name AS app_name
       FROM install_jobs j
       JOIN apps a ON a.id = j.app_id
       WHERE j.id = $1`,
      [jobId]
    );
    return result.rows[0] || null;
  }

  /**
   * Get install status (alias for getJob).
   */
  async getInstallStatus(jobId) {
    return this.getJob(jobId);
  }

  /**
   * Get install history for a device.
   */
  async getDeviceInstallHistory(deviceId, { limit = 50, offset = 0 } = {}) {
    const countResult = await this.pool.query(
      'SELECT COUNT(*) FROM install_jobs WHERE device_id = $1',
      [deviceId]
    );

    const result = await this.pool.query(
      `SELECT j.*, a.name AS app_name
       FROM install_jobs j
       JOIN apps a ON a.id = j.app_id
       WHERE j.device_id = $1
       ORDER BY j.created_at DESC
       LIMIT $2 OFFSET $3`,
      [deviceId, limit, offset]
    );

    return {
      jobs: result.rows,
      total: parseInt(countResult.rows[0].count, 10),
      limit,
      offset,
    };
  }

  /**
   * Get installed apps on a device (latest completed install jobs, excluding uninstalled).
   */
  async getInstalledApps(deviceId) {
    const result = await this.pool.query(
      `SELECT DISTINCT ON (j.app_id) j.*, a.name AS app_name, a.description, a.category, a.icon_url, a.platforms
       FROM install_jobs j
       JOIN apps a ON a.id = j.app_id
       WHERE j.device_id = $1
         AND j.status = 'completed'
       ORDER BY j.app_id, j.completed_at DESC`,
      [deviceId]
    );

    // Filter out apps whose last completed action was 'uninstall'
    return result.rows.filter((row) => row.action !== 'uninstall');
  }

  /**
   * Get install statistics for an app.
   */
  async getAppInstallStats(appId) {
    const result = await this.pool.query(
      `SELECT
         COUNT(*) FILTER (WHERE status = 'completed' AND action = 'install') AS successful_installs,
         COUNT(*) FILTER (WHERE status = 'failed') AS failed_installs,
         COUNT(*) FILTER (WHERE status IN ('queued', 'downloading', 'installing')) AS pending_installs,
         COUNT(*) FILTER (WHERE status = 'completed' AND action = 'uninstall') AS uninstalls,
         AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) FILTER (WHERE status = 'completed' AND started_at IS NOT NULL) AS avg_install_seconds,
         COUNT(DISTINCT device_id) FILTER (WHERE status = 'completed' AND action = 'install') AS unique_devices
       FROM install_jobs
       WHERE app_id = $1`,
      [appId]
    );

    const stats = result.rows[0];
    const totalAttempts = parseInt(stats.successful_installs, 10) + parseInt(stats.failed_installs, 10);

    return {
      appId,
      successfulInstalls: parseInt(stats.successful_installs, 10),
      failedInstalls: parseInt(stats.failed_installs, 10),
      pendingInstalls: parseInt(stats.pending_installs, 10),
      uninstalls: parseInt(stats.uninstalls, 10),
      uniqueDevices: parseInt(stats.unique_devices, 10),
      successRate: totalAttempts > 0
        ? Math.round((parseInt(stats.successful_installs, 10) / totalAttempts) * 100)
        : 0,
      avgInstallTimeSeconds: stats.avg_install_seconds
        ? Math.round(parseFloat(stats.avg_install_seconds))
        : null,
    };
  }

  /**
   * Get overall analytics across all apps.
   */
  async getAnalytics() {
    const overallResult = await this.pool.query(`
      SELECT
        COUNT(*) AS total_jobs,
        COUNT(*) FILTER (WHERE status = 'completed') AS completed,
        COUNT(*) FILTER (WHERE status = 'failed') AS failed,
        COUNT(*) FILTER (WHERE status IN ('queued', 'downloading', 'installing')) AS in_progress,
        COUNT(DISTINCT device_id) AS unique_devices,
        COUNT(DISTINCT app_id) AS unique_apps
      FROM install_jobs
    `);

    const topAppsResult = await this.pool.query(`
      SELECT a.id, a.name, COUNT(*) AS install_count
      FROM install_jobs j
      JOIN apps a ON a.id = j.app_id
      WHERE j.status = 'completed' AND j.action = 'install'
      GROUP BY a.id, a.name
      ORDER BY install_count DESC
      LIMIT 10
    `);

    const recentResult = await this.pool.query(`
      SELECT j.*, a.name AS app_name
      FROM install_jobs j
      JOIN apps a ON a.id = j.app_id
      ORDER BY j.created_at DESC
      LIMIT 20
    `);

    const overall = overallResult.rows[0];
    return {
      summary: {
        totalJobs: parseInt(overall.total_jobs, 10),
        completed: parseInt(overall.completed, 10),
        failed: parseInt(overall.failed, 10),
        inProgress: parseInt(overall.in_progress, 10),
        uniqueDevices: parseInt(overall.unique_devices, 10),
        uniqueApps: parseInt(overall.unique_apps, 10),
      },
      topApps: topAppsResult.rows,
      recentJobs: recentResult.rows,
    };
  }

  /**
   * Get active (in-progress) jobs.
   */
  async getActiveJobs() {
    const result = await this.pool.query(
      `SELECT j.*, a.name AS app_name
       FROM install_jobs j
       JOIN apps a ON a.id = j.app_id
       WHERE j.status IN ('queued', 'downloading', 'installing')
       ORDER BY j.created_at ASC`
    );
    return result.rows;
  }
}

module.exports = { InstallTracker };
