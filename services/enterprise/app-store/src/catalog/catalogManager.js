'use strict';

const { Pool } = require('pg');
const winston = require('winston');
const semver = require('semver');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'app-store-catalog' },
  transports: [new winston.transports.Console()],
});

const defaultApps = [
  { name: 'firefox', display_name: 'Mozilla Firefox', description: 'Fast, privacy-focused web browser from Mozilla', category: 'browser', publisher: 'Mozilla', version: '121.0', platforms: ['windows', 'macos', 'linux'], packages: { windows: { type: 'winget', id: 'Mozilla.Firefox', args: '--silent' }, macos: { type: 'brew', id: 'firefox', cask: true }, linux: { type: 'apt', id: 'firefox' } }, license_type: 'free', tags: ['browser', 'privacy', 'open-source'] },
  { name: 'chrome', display_name: 'Google Chrome', description: 'Fast and secure web browser by Google', category: 'browser', publisher: 'Google', version: '120.0', platforms: ['windows', 'macos', 'linux'], packages: { windows: { type: 'winget', id: 'Google.Chrome', args: '--silent' }, macos: { type: 'brew', id: 'google-chrome', cask: true }, linux: { type: 'apt', id: 'google-chrome-stable' } }, license_type: 'free', tags: ['browser', 'google'] },
  { name: 'vscode', display_name: 'Visual Studio Code', description: 'Lightweight but powerful source code editor', category: 'development', publisher: 'Microsoft', version: '1.85.0', platforms: ['windows', 'macos', 'linux'], packages: { windows: { type: 'winget', id: 'Microsoft.VisualStudioCode', args: '--silent' }, macos: { type: 'brew', id: 'visual-studio-code', cask: true }, linux: { type: 'apt', id: 'code' } }, license_type: 'free', tags: ['editor', 'ide', 'development'] },
  { name: '7zip', display_name: '7-Zip', description: 'High compression ratio file archiver', category: 'utilities', publisher: 'Igor Pavlov', version: '23.01', platforms: ['windows', 'macos', 'linux'], packages: { windows: { type: 'winget', id: '7zip.7zip', args: '--silent' }, macos: { type: 'brew', id: 'p7zip' }, linux: { type: 'apt', id: 'p7zip-full' } }, license_type: 'free', tags: ['archiver', 'compression', 'utilities'] },
  { name: 'vlc', display_name: 'VLC Media Player', description: 'Free and open source cross-platform multimedia player', category: 'media', publisher: 'VideoLAN', version: '3.0.20', platforms: ['windows', 'macos', 'linux'], packages: { windows: { type: 'winget', id: 'VideoLAN.VLC', args: '--silent' }, macos: { type: 'brew', id: 'vlc', cask: true }, linux: { type: 'apt', id: 'vlc' } }, license_type: 'free', tags: ['media', 'video', 'audio', 'open-source'] },
  { name: 'libreoffice', display_name: 'LibreOffice', description: 'Powerful and free office suite, successor to OpenOffice', category: 'productivity', publisher: 'The Document Foundation', version: '7.6.4', platforms: ['windows', 'macos', 'linux'], packages: { windows: { type: 'winget', id: 'TheDocumentFoundation.LibreOffice', args: '--silent' }, macos: { type: 'brew', id: 'libreoffice', cask: true }, linux: { type: 'apt', id: 'libreoffice' } }, license_type: 'free', tags: ['office', 'productivity', 'documents', 'open-source'] },
  { name: 'slack', display_name: 'Slack', description: 'Business communication platform for team collaboration', category: 'communication', publisher: 'Slack Technologies', version: '4.35.0', platforms: ['windows', 'macos', 'linux'], packages: { windows: { type: 'winget', id: 'SlackTechnologies.Slack', args: '--silent' }, macos: { type: 'brew', id: 'slack', cask: true }, linux: { type: 'snap', id: 'slack' } }, license_type: 'commercial', tags: ['chat', 'collaboration', 'messaging'] },
  { name: 'zoom', display_name: 'Zoom', description: 'Video conferencing and online meetings', category: 'communication', publisher: 'Zoom Video Communications', version: '5.17.0', platforms: ['windows', 'macos', 'linux'], packages: { windows: { type: 'winget', id: 'Zoom.Zoom', args: '--silent' }, macos: { type: 'brew', id: 'zoom', cask: true }, linux: { type: 'apt', id: 'zoom' } }, license_type: 'commercial', tags: ['video', 'conferencing', 'meetings'] },
  { name: 'keepassxc', display_name: 'KeePassXC', description: 'Cross-platform community-driven password manager', category: 'security', publisher: 'KeePassXC Team', version: '2.7.6', platforms: ['windows', 'macos', 'linux'], packages: { windows: { type: 'winget', id: 'KeePassXCTeam.KeePassXC', args: '--silent' }, macos: { type: 'brew', id: 'keepassxc', cask: true }, linux: { type: 'apt', id: 'keepassxc' } }, license_type: 'free', tags: ['passwords', 'security', 'encryption', 'open-source'] },
  { name: 'git', display_name: 'Git', description: 'Distributed version control system', category: 'development', publisher: 'Software Freedom Conservancy', version: '2.43.0', platforms: ['windows', 'macos', 'linux'], packages: { windows: { type: 'winget', id: 'Git.Git', args: '--silent' }, macos: { type: 'brew', id: 'git' }, linux: { type: 'apt', id: 'git' } }, license_type: 'free', tags: ['vcs', 'development', 'open-source'] },
  { name: 'nodejs', display_name: 'Node.js LTS', description: 'JavaScript runtime built on Chrome\'s V8 JavaScript engine', category: 'development', publisher: 'OpenJS Foundation', version: '20.10.0', platforms: ['windows', 'macos', 'linux'], packages: { windows: { type: 'winget', id: 'OpenJS.NodeJS.LTS', args: '--silent' }, macos: { type: 'brew', id: 'node@20' }, linux: { type: 'apt', id: 'nodejs' } }, license_type: 'free', tags: ['javascript', 'runtime', 'development'] },
  { name: 'thunderbird', display_name: 'Mozilla Thunderbird', description: 'Free email application, easy to set up and customize', category: 'communication', publisher: 'Mozilla', version: '115.6.0', platforms: ['windows', 'macos', 'linux'], packages: { windows: { type: 'winget', id: 'Mozilla.Thunderbird', args: '--silent' }, macos: { type: 'brew', id: 'thunderbird', cask: true }, linux: { type: 'apt', id: 'thunderbird' } }, license_type: 'free', tags: ['email', 'communication', 'open-source'] },
];

class CatalogManager {
  constructor(pool) {
    this.pool = pool;
  }

  /**
   * Seed the catalog with default enterprise apps
   */
  async seedDefaultApps() {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      let seeded = 0;

      for (const app of defaultApps) {
        const existing = await client.query(
          'SELECT id FROM store_apps WHERE name = $1',
          [app.name]
        );

        if (existing.rows.length === 0) {
          await client.query(
            `INSERT INTO store_apps (name, display_name, description, category, publisher, version, platforms, packages, license_type, tags)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
            [
              app.name,
              app.display_name,
              app.description,
              app.category,
              app.publisher,
              app.version,
              JSON.stringify(app.platforms),
              JSON.stringify(app.packages),
              app.license_type,
              JSON.stringify(app.tags),
            ]
          );
          seeded++;
        }
      }

      await client.query('COMMIT');
      logger.info(`Seeded ${seeded} default apps into the catalog`);
      return { seeded, total: defaultApps.length };
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error('Failed to seed default apps', { error: error.message });
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * List all apps with optional filtering
   */
  async listApps({ search, category, platform, tags, enabled, page = 1, limit = 50 } = {}) {
    const conditions = [];
    const params = [];
    let paramIndex = 1;

    if (search) {
      conditions.push(`(name ILIKE $${paramIndex} OR display_name ILIKE $${paramIndex} OR description ILIKE $${paramIndex})`);
      params.push(`%${search}%`);
      paramIndex++;
    }

    if (category) {
      conditions.push(`category = $${paramIndex}`);
      params.push(category);
      paramIndex++;
    }

    if (platform) {
      conditions.push(`platforms @> $${paramIndex}::jsonb`);
      params.push(JSON.stringify([platform]));
      paramIndex++;
    }

    if (tags && tags.length > 0) {
      conditions.push(`tags ?| $${paramIndex}`);
      params.push(tags);
      paramIndex++;
    }

    if (typeof enabled === 'boolean') {
      conditions.push(`enabled = $${paramIndex}`);
      params.push(enabled);
      paramIndex++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const offset = (page - 1) * limit;

    const countResult = await this.pool.query(
      `SELECT COUNT(*) FROM store_apps ${whereClause}`,
      params
    );

    params.push(limit);
    params.push(offset);

    const result = await this.pool.query(
      `SELECT * FROM store_apps ${whereClause} ORDER BY display_name ASC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`,
      params
    );

    return {
      apps: result.rows,
      total: parseInt(countResult.rows[0].count, 10),
      page,
      limit,
      totalPages: Math.ceil(parseInt(countResult.rows[0].count, 10) / limit),
    };
  }

  /**
   * Get a single app by ID
   */
  async getApp(appId) {
    const result = await this.pool.query(
      'SELECT * FROM store_apps WHERE id = $1',
      [appId]
    );
    if (result.rows.length === 0) {
      return null;
    }
    return result.rows[0];
  }

  /**
   * Create a new app in the catalog
   */
  async createApp(appData) {
    const {
      name, display_name, description, category, publisher,
      icon_url, homepage_url, version, platforms, packages,
      size_bytes, license_type, max_licenses, required, tags, metadata,
    } = appData;

    const result = await this.pool.query(
      `INSERT INTO store_apps
        (name, display_name, description, category, publisher, icon_url, homepage_url, version, platforms, packages, size_bytes, license_type, max_licenses, required, tags, metadata)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
       RETURNING *`,
      [
        name, display_name, description || '', category, publisher || '',
        icon_url || null, homepage_url || null, version || '1.0.0',
        JSON.stringify(platforms || []),
        JSON.stringify(packages || {}),
        size_bytes || null,
        license_type || 'free',
        max_licenses || null,
        required || false,
        JSON.stringify(tags || []),
        JSON.stringify(metadata || {}),
      ]
    );

    logger.info('App created in catalog', { appId: result.rows[0].id, name });
    return result.rows[0];
  }

  /**
   * Update an existing app
   */
  async updateApp(appId, updates) {
    const fields = [];
    const params = [];
    let paramIndex = 1;

    const allowedFields = [
      'display_name', 'description', 'category', 'publisher',
      'icon_url', 'homepage_url', 'version', 'platforms', 'packages',
      'size_bytes', 'license_type', 'max_licenses', 'required',
      'tags', 'metadata', 'enabled',
    ];

    const jsonFields = ['platforms', 'packages', 'tags', 'metadata'];

    for (const field of allowedFields) {
      if (updates[field] !== undefined) {
        fields.push(`${field} = $${paramIndex}`);
        params.push(jsonFields.includes(field) ? JSON.stringify(updates[field]) : updates[field]);
        paramIndex++;
      }
    }

    if (fields.length === 0) {
      return this.getApp(appId);
    }

    fields.push(`updated_at = NOW()`);
    params.push(appId);

    const result = await this.pool.query(
      `UPDATE store_apps SET ${fields.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
      params
    );

    if (result.rows.length === 0) {
      return null;
    }

    logger.info('App updated in catalog', { appId });
    return result.rows[0];
  }

  /**
   * Delete an app from the catalog
   */
  async deleteApp(appId) {
    const result = await this.pool.query(
      'DELETE FROM store_apps WHERE id = $1 RETURNING id, name',
      [appId]
    );
    if (result.rows.length === 0) {
      return null;
    }
    logger.info('App deleted from catalog', { appId, name: result.rows[0].name });
    return result.rows[0];
  }

  /**
   * Add a new version record for an app
   */
  async addVersion(appId, versionData) {
    const { version, changelog, packages, min_os_version } = versionData;

    const app = await this.getApp(appId);
    if (!app) {
      throw new Error('App not found');
    }

    const result = await this.pool.query(
      `INSERT INTO store_app_versions (app_id, version, changelog, packages, min_os_version)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [appId, version, changelog || '', JSON.stringify(packages || {}), JSON.stringify(min_os_version || {})]
    );

    // Update the main app version if this is newer
    if (semver.valid(version) && semver.valid(app.version)) {
      if (semver.gt(version, app.version)) {
        await this.updateApp(appId, { version, packages: packages || app.packages });
      }
    } else {
      // If not semver, just update
      await this.updateApp(appId, { version, packages: packages || app.packages });
    }

    logger.info('App version added', { appId, version });
    return result.rows[0];
  }

  /**
   * Get version history for an app
   */
  async getVersions(appId) {
    const result = await this.pool.query(
      'SELECT * FROM store_app_versions WHERE app_id = $1 ORDER BY created_at DESC',
      [appId]
    );
    return result.rows;
  }

  /**
   * List all categories
   */
  async listCategories() {
    const result = await this.pool.query(
      'SELECT * FROM store_categories ORDER BY sort_order ASC'
    );
    return result.rows;
  }

  /**
   * Get store statistics
   */
  async getStats() {
    const [appsResult, installsResult, categoriesResult, licenseResult] = await Promise.all([
      this.pool.query('SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE enabled = true) as enabled FROM store_apps'),
      this.pool.query(`SELECT
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE status = 'installed') as installed,
        COUNT(*) FILTER (WHERE status = 'pending') as pending,
        COUNT(*) FILTER (WHERE status = 'failed') as failed
        FROM store_installations`),
      this.pool.query('SELECT category, COUNT(*) as count FROM store_apps GROUP BY category ORDER BY count DESC'),
      this.pool.query(`SELECT
        COUNT(*) FILTER (WHERE license_type = 'commercial' OR license_type = 'enterprise') as licensed_apps,
        SUM(used_licenses) as total_used_licenses
        FROM store_apps`),
    ]);

    return {
      apps: {
        total: parseInt(appsResult.rows[0].total, 10),
        enabled: parseInt(appsResult.rows[0].enabled, 10),
      },
      installations: {
        total: parseInt(installsResult.rows[0].total, 10),
        installed: parseInt(installsResult.rows[0].installed, 10),
        pending: parseInt(installsResult.rows[0].pending, 10),
        failed: parseInt(installsResult.rows[0].failed, 10),
      },
      categories: categoriesResult.rows,
      licenses: {
        licensedApps: parseInt(licenseResult.rows[0].licensed_apps, 10),
        totalUsedLicenses: parseInt(licenseResult.rows[0].total_used_licenses || '0', 10),
      },
    };
  }
}

module.exports = CatalogManager;
