'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * BaselineManager – loads, stores and manages compliance baselines.
 * Built-in baselines are loaded from JSON files on disk; custom baselines
 * are persisted to PostgreSQL.
 */
class BaselineManager {
  constructor({ pgPool, logger }) {
    this.pgPool = pgPool;
    this.logger = logger;
    /** @type {Map<string, object>} id → baseline */
    this.baselines = new Map();
  }

  // ---------------------------------------------------------------------------
  // Loading
  // ---------------------------------------------------------------------------

  /**
   * Load all baseline JSON files from a directory.
   */
  async loadFromDirectory(dir) {
    try {
      if (!fs.existsSync(dir)) {
        this.logger.warn('Baselines directory does not exist', { dir });
        return;
      }

      const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
      for (const file of files) {
        try {
          const raw = fs.readFileSync(path.join(dir, file), 'utf8');
          const baseline = JSON.parse(raw);
          if (!baseline.id) {
            baseline.id = path.basename(file, '.json');
          }
          this.baselines.set(baseline.id, baseline);
          this.logger.info('Loaded baseline', { id: baseline.id, name: baseline.name, checks: (baseline.checks || []).length });
        } catch (err) {
          this.logger.error('Failed to load baseline file', { file, error: err.message });
        }
      }
    } catch (err) {
      this.logger.error('Failed to read baselines directory', { dir, error: err.message });
    }

    // Also load custom baselines from database
    await this._loadCustomBaselines();
  }

  /**
   * Load custom baselines from PostgreSQL.
   */
  async _loadCustomBaselines() {
    try {
      const { rows } = await this.pgPool.query(
        `SELECT * FROM compliance_baselines WHERE enabled = true`
      );
      for (const row of rows) {
        const baseline = {
          id: row.id,
          name: row.name,
          description: row.description,
          framework: row.framework,
          platform: row.platform,
          version: row.version,
          checks: row.checks || [],
          custom: true,
        };
        this.baselines.set(baseline.id, baseline);
      }
      this.logger.info('Loaded custom baselines from database', { count: rows.length });
    } catch {
      this.logger.warn('Could not load custom baselines from database');
    }
  }

  // ---------------------------------------------------------------------------
  // Query
  // ---------------------------------------------------------------------------

  /**
   * Get the number of loaded baselines.
   */
  getLoadedCount() {
    return this.baselines.size;
  }

  /**
   * List all baselines, optionally filtered by platform.
   */
  listBaselines(platform) {
    const all = Array.from(this.baselines.values());
    if (!platform) return all.map(this._summarize);
    return all
      .filter((b) => b.platform === platform || b.platform === 'all' || b.platform === 'cross-platform')
      .map(this._summarize);
  }

  /**
   * Get a baseline by its ID.
   */
  getBaselineById(id) {
    return this.baselines.get(id) || null;
  }

  /**
   * Get all baselines applicable to a specific device/platform.
   */
  getBaselinesForDevice(deviceId, platform) {
    const applicable = [];
    for (const baseline of this.baselines.values()) {
      if (
        baseline.platform === platform ||
        baseline.platform === 'all' ||
        baseline.platform === 'cross-platform'
      ) {
        applicable.push(baseline);
      }
    }
    return applicable;
  }

  // ---------------------------------------------------------------------------
  // CRUD
  // ---------------------------------------------------------------------------

  /**
   * Create a custom baseline and persist it.
   */
  async createBaseline(data) {
    if (!data.name) throw new Error('Baseline name is required');
    if (!data.framework) throw new Error('Baseline framework is required');
    if (!data.platform) throw new Error('Baseline platform is required');
    if (!data.checks || !Array.isArray(data.checks) || data.checks.length === 0) {
      throw new Error('At least one check is required');
    }

    const id = data.id || crypto.randomUUID();
    const version = data.version || '1.0.0';

    const { rows } = await this.pgPool.query(
      `INSERT INTO compliance_baselines (id, name, description, framework, platform, version, checks)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [id, data.name, data.description || '', data.framework, data.platform, version, JSON.stringify(data.checks)]
    );

    const baseline = {
      id: rows[0].id,
      name: rows[0].name,
      description: rows[0].description,
      framework: rows[0].framework,
      platform: rows[0].platform,
      version: rows[0].version,
      checks: rows[0].checks,
      custom: true,
    };
    this.baselines.set(baseline.id, baseline);
    this.logger.info('Created custom baseline', { id: baseline.id, name: baseline.name });
    return baseline;
  }

  /**
   * Update an existing custom baseline.
   */
  async updateBaseline(id, data) {
    const existing = this.baselines.get(id);
    if (!existing) return null;

    const updates = {
      name: data.name || existing.name,
      description: data.description !== undefined ? data.description : existing.description,
      framework: data.framework || existing.framework,
      platform: data.platform || existing.platform,
      version: data.version || existing.version,
      checks: data.checks || existing.checks,
    };

    if (existing.custom) {
      await this.pgPool.query(
        `UPDATE compliance_baselines
         SET name = $2, description = $3, framework = $4, platform = $5, version = $6, checks = $7, updated_at = NOW()
         WHERE id = $1`,
        [id, updates.name, updates.description, updates.framework, updates.platform, updates.version, JSON.stringify(updates.checks)]
      );
    }

    const updated = { ...existing, ...updates };
    this.baselines.set(id, updated);
    this.logger.info('Updated baseline', { id });
    return updated;
  }

  /**
   * Return a summary (without full checks array) for listing purposes.
   */
  _summarize(baseline) {
    return {
      id: baseline.id,
      name: baseline.name,
      description: baseline.description,
      framework: baseline.framework,
      platform: baseline.platform,
      version: baseline.version,
      checksCount: (baseline.checks || []).length,
      custom: baseline.custom || false,
    };
  }
}

module.exports = BaselineManager;
