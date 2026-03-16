'use strict';

const CATEGORIES = [
  'Productivity',
  'Security',
  'Development',
  'Communication',
  'Utilities',
  'Media',
  'Business',
];

const CACHE_TTL = 300; // 5 minutes

class CatalogManager {
  constructor(pool, redis, logger) {
    this.pool = pool;
    this.redis = redis;
    this.logger = logger;
  }

  // ---------------------------------------------------------------------------
  // CRUD
  // ---------------------------------------------------------------------------

  async createApp(data) {
    const {
      name,
      description = '',
      publisher = '',
      category = 'Utilities',
      icon_url = null,
      platforms = {},
      tags = [],
      featured = false,
      mandatory = false,
    } = data;

    if (!name) throw new Error('App name is required');
    if (!CATEGORIES.includes(category)) {
      throw new Error(`Invalid category. Must be one of: ${CATEGORIES.join(', ')}`);
    }

    const result = await this.pool.query(
      `INSERT INTO apps (name, description, publisher, category, icon_url, platforms, tags, featured, mandatory)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [name, description, publisher, category, icon_url, JSON.stringify(platforms), tags, featured, mandatory]
    );

    const app = result.rows[0];
    await this._invalidateCache();
    this.logger.info('App created', { appId: app.id, name });
    return app;
  }

  async updateApp(id, data) {
    const fields = [];
    const values = [];
    let idx = 1;

    const allowedFields = ['name', 'description', 'publisher', 'category', 'icon_url', 'platforms', 'tags', 'featured', 'mandatory'];

    for (const field of allowedFields) {
      if (data[field] !== undefined) {
        if (field === 'category' && !CATEGORIES.includes(data[field])) {
          throw new Error(`Invalid category. Must be one of: ${CATEGORIES.join(', ')}`);
        }
        const value = field === 'platforms' ? JSON.stringify(data[field]) : data[field];
        fields.push(`${field} = $${idx}`);
        values.push(value);
        idx++;
      }
    }

    if (fields.length === 0) throw new Error('No fields to update');

    fields.push(`updated_at = NOW()`);
    values.push(id);

    const result = await this.pool.query(
      `UPDATE apps SET ${fields.join(', ')} WHERE id = $${idx} RETURNING *`,
      values
    );

    if (result.rows.length === 0) throw new Error('App not found');

    await this._invalidateCache();
    this.logger.info('App updated', { appId: id });
    return result.rows[0];
  }

  async deleteApp(id) {
    const result = await this.pool.query('DELETE FROM apps WHERE id = $1 RETURNING id, name', [id]);
    if (result.rows.length === 0) throw new Error('App not found');

    await this._invalidateCache();
    this.logger.info('App deleted', { appId: id, name: result.rows[0].name });
    return { deleted: true, id };
  }

  async getApp(id) {
    const cacheKey = `app:${id}`;
    const cached = await this._getCache(cacheKey);
    if (cached) return cached;

    const result = await this.pool.query(
      `SELECT a.*,
              (SELECT json_agg(v ORDER BY v.released_at DESC)
               FROM app_versions v WHERE v.app_id = a.id) AS versions
       FROM apps a WHERE a.id = $1`,
      [id]
    );

    if (result.rows.length === 0) return null;

    const app = result.rows[0];
    await this._setCache(cacheKey, app);
    return app;
  }

  // ---------------------------------------------------------------------------
  // Listing & Search
  // ---------------------------------------------------------------------------

  async listApps({ limit = 50, offset = 0, category, platform, mandatory, featured, sortBy = 'name', sortOrder = 'ASC' } = {}) {
    const conditions = [];
    const values = [];
    let idx = 1;

    if (category) {
      conditions.push(`category = $${idx++}`);
      values.push(category);
    }
    if (platform) {
      conditions.push(`platforms ? $${idx++}`);
      values.push(platform);
    }
    if (mandatory !== undefined) {
      conditions.push(`mandatory = $${idx++}`);
      values.push(mandatory);
    }
    if (featured !== undefined) {
      conditions.push(`featured = $${idx++}`);
      values.push(featured);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const allowedSorts = ['name', 'category', 'publisher', 'created_at', 'updated_at'];
    const sort = allowedSorts.includes(sortBy) ? sortBy : 'name';
    const order = sortOrder.toUpperCase() === 'DESC' ? 'DESC' : 'ASC';

    const countResult = await this.pool.query(`SELECT COUNT(*) FROM apps ${where}`, values);
    const total = parseInt(countResult.rows[0].count, 10);

    values.push(limit, offset);
    const result = await this.pool.query(
      `SELECT * FROM apps ${where} ORDER BY ${sort} ${order} LIMIT $${idx++} OFFSET $${idx}`,
      values
    );

    return { apps: result.rows, total, limit, offset };
  }

  async searchApps(query, { limit = 50, offset = 0, category, platform } = {}) {
    if (!query || query.trim().length === 0) {
      return this.listApps({ limit, offset, category, platform });
    }

    const conditions = [
      `to_tsvector('english', coalesce(name,'') || ' ' || coalesce(description,'') || ' ' || array_to_string(tags, ' ')) @@ plainto_tsquery('english', $1)`,
    ];
    const values = [query];
    let idx = 2;

    if (category) {
      conditions.push(`category = $${idx++}`);
      values.push(category);
    }
    if (platform) {
      conditions.push(`platforms ? $${idx++}`);
      values.push(platform);
    }

    const where = `WHERE ${conditions.join(' AND ')}`;

    const countResult = await this.pool.query(`SELECT COUNT(*) FROM apps ${where}`, values);
    const total = parseInt(countResult.rows[0].count, 10);

    values.push(limit, offset);
    const result = await this.pool.query(
      `SELECT *, ts_rank(
          to_tsvector('english', coalesce(name,'') || ' ' || coalesce(description,'') || ' ' || array_to_string(tags, ' ')),
          plainto_tsquery('english', $1)
       ) AS relevance
       FROM apps ${where}
       ORDER BY relevance DESC, name ASC
       LIMIT $${idx++} OFFSET $${idx}`,
      values
    );

    return { apps: result.rows, total, limit, offset, query };
  }

  async getAppsByIds(ids) {
    if (!ids || ids.length === 0) return [];
    const result = await this.pool.query(
      `SELECT * FROM apps WHERE id = ANY($1)`,
      [ids]
    );
    return result.rows;
  }

  async getAppsByPlatform(platform) {
    const result = await this.pool.query(
      `SELECT * FROM apps WHERE platforms ? $1 ORDER BY name`,
      [platform]
    );
    return result.rows;
  }

  getCategories() {
    return CATEGORIES;
  }

  // ---------------------------------------------------------------------------
  // Cache helpers
  // ---------------------------------------------------------------------------

  async _getCache(key) {
    try {
      if (!this.redis || this.redis.status !== 'ready') return null;
      const data = await this.redis.get(`appstore:${key}`);
      return data ? JSON.parse(data) : null;
    } catch {
      return null;
    }
  }

  async _setCache(key, value) {
    try {
      if (!this.redis || this.redis.status !== 'ready') return;
      await this.redis.setex(`appstore:${key}`, CACHE_TTL, JSON.stringify(value));
    } catch {
      // ignore cache errors
    }
  }

  async _invalidateCache() {
    try {
      if (!this.redis || this.redis.status !== 'ready') return;
      const keys = await this.redis.keys('appstore:app:*');
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
    } catch {
      // ignore cache errors
    }
  }
}

module.exports = { CatalogManager, CATEGORIES };
