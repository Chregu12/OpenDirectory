'use strict';

const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

class BaselineManager {
  constructor(db) {
    this.db = db;
    this.baselinesDir = path.join(__dirname, '../../baselines');
  }

  /**
   * Load all built-in JSON baselines from the /baselines/ directory into the database.
   * Performs upsert based on the baseline's embedded id to avoid duplicates.
   */
  async loadBuiltInBaselines() {
    logger.info('Loading built-in compliance baselines...');

    if (!fs.existsSync(this.baselinesDir)) {
      logger.warn(`Baselines directory not found: ${this.baselinesDir}`);
      return [];
    }

    const files = fs.readdirSync(this.baselinesDir).filter(f => f.endsWith('.json'));
    const loaded = [];

    for (const file of files) {
      try {
        const filePath = path.join(this.baselinesDir, file);
        const raw = fs.readFileSync(filePath, 'utf8');
        const baseline = JSON.parse(raw);

        if (!baseline.name || !baseline.framework || !baseline.version) {
          logger.warn(`Skipping invalid baseline file: ${file} (missing required fields)`);
          continue;
        }

        // Upsert: insert or update if matching name + framework + version
        const { rows } = await this.db.query(
          `INSERT INTO compliance_baselines (name, description, framework, platform, version, checks, enabled)
           VALUES ($1, $2, $3, $4, $5, $6, true)
           ON CONFLICT ON CONSTRAINT compliance_baselines_pkey DO NOTHING
           RETURNING id`,
          [
            baseline.name,
            baseline.description || `${baseline.framework.toUpperCase()} baseline - ${baseline.name}`,
            baseline.framework,
            baseline.platform || 'all',
            baseline.version,
            JSON.stringify(baseline.checks || []),
          ]
        );

        // If ON CONFLICT did nothing, try to find existing and update
        if (rows.length === 0) {
          const existing = await this.db.query(
            `SELECT id FROM compliance_baselines WHERE name = $1 AND framework = $2`,
            [baseline.name, baseline.framework]
          );

          if (existing.rows.length > 0) {
            await this.db.query(
              `UPDATE compliance_baselines SET checks = $1, version = $2, platform = $3, updated_at = NOW()
               WHERE id = $4`,
              [JSON.stringify(baseline.checks || []), baseline.version, baseline.platform || 'all', existing.rows[0].id]
            );
            logger.info(`Updated existing baseline: ${baseline.name}`);
            loaded.push({ id: existing.rows[0].id, name: baseline.name, action: 'updated' });
          }
        } else {
          logger.info(`Loaded baseline: ${baseline.name} (${rows[0].id})`);
          loaded.push({ id: rows[0].id, name: baseline.name, action: 'created' });
        }
      } catch (error) {
        logger.error(`Failed to load baseline from ${file}: ${error.message}`);
      }
    }

    logger.info(`Loaded ${loaded.length} baselines from ${files.length} files`);
    return loaded;
  }

  /**
   * Create a custom compliance baseline.
   */
  async createBaseline(data) {
    const { name, description, framework, platform, version, checks, enabled } = data;

    if (!name || !framework || !version) {
      throw new Error('Missing required fields: name, framework, version');
    }

    const validFrameworks = ['cis', 'nist', 'bsi', 'iso27001', 'dsgvo', 'stig', 'custom'];
    if (!validFrameworks.includes(framework)) {
      throw new Error(`Invalid framework "${framework}". Must be one of: ${validFrameworks.join(', ')}`);
    }

    const validPlatforms = ['windows', 'macos', 'linux', 'all'];
    if (platform && !validPlatforms.includes(platform)) {
      throw new Error(`Invalid platform "${platform}". Must be one of: ${validPlatforms.join(', ')}`);
    }

    // Validate checks structure
    if (checks && Array.isArray(checks)) {
      for (const check of checks) {
        if (!check.id || !check.title) {
          throw new Error('Each check must have an id and title');
        }
      }
    }

    const { rows } = await this.db.query(
      `INSERT INTO compliance_baselines (name, description, framework, platform, version, checks, enabled)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [
        name,
        description || '',
        framework,
        platform || 'all',
        version,
        JSON.stringify(checks || []),
        enabled !== false,
      ]
    );

    logger.info(`Created custom baseline: ${name} (${rows[0].id})`);
    return rows[0];
  }

  /**
   * Update an existing baseline.
   */
  async updateBaseline(id, data) {
    const updates = [];
    const values = [];
    let paramIndex = 1;

    const allowedFields = ['name', 'description', 'framework', 'platform', 'version', 'checks', 'enabled'];

    for (const field of allowedFields) {
      if (data[field] !== undefined) {
        const value = field === 'checks' ? JSON.stringify(data[field]) : data[field];
        updates.push(`${field} = $${paramIndex}`);
        values.push(value);
        paramIndex++;
      }
    }

    if (updates.length === 0) {
      throw new Error('No valid fields to update');
    }

    updates.push(`updated_at = NOW()`);
    values.push(id);

    const { rows } = await this.db.query(
      `UPDATE compliance_baselines SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
      values
    );

    if (rows.length === 0) {
      throw new Error(`Baseline not found: ${id}`);
    }

    logger.info(`Updated baseline: ${rows[0].name} (${id})`);
    return rows[0];
  }

  /**
   * Get a single baseline by ID.
   */
  async getBaseline(id) {
    const { rows } = await this.db.query(
      'SELECT * FROM compliance_baselines WHERE id = $1',
      [id]
    );

    if (rows.length === 0) {
      return null;
    }

    return rows[0];
  }

  /**
   * List baselines with optional filters.
   */
  async listBaselines(filters = {}) {
    let query = 'SELECT * FROM compliance_baselines WHERE 1=1';
    const params = [];

    if (filters.framework) {
      params.push(filters.framework);
      query += ` AND framework = $${params.length}`;
    }

    if (filters.platform) {
      params.push(filters.platform);
      query += ` AND (platform = $${params.length} OR platform = 'all')`;
    }

    if (filters.enabled !== undefined) {
      params.push(filters.enabled);
      query += ` AND enabled = $${params.length}`;
    }

    if (filters.search) {
      params.push(`%${filters.search}%`);
      query += ` AND (name ILIKE $${params.length} OR description ILIKE $${params.length})`;
    }

    query += ' ORDER BY framework, name';

    if (filters.limit) {
      params.push(filters.limit);
      query += ` LIMIT $${params.length}`;
    }

    if (filters.offset) {
      params.push(filters.offset);
      query += ` OFFSET $${params.length}`;
    }

    const { rows } = await this.db.query(query, params);
    return rows;
  }

  /**
   * Get baselines applicable to a specific platform.
   */
  async getBaselineForPlatform(platform) {
    const { rows } = await this.db.query(
      `SELECT * FROM compliance_baselines
       WHERE enabled = true AND (platform = $1 OR platform = 'all')
       ORDER BY framework, name`,
      [platform]
    );
    return rows;
  }
}

module.exports = BaselineManager;
