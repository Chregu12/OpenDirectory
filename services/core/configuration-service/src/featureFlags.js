const EventEmitter = require('eventemitter3');
const { Pool } = require('pg');
const logger = require('./utils/logger');

class FeatureFlags extends EventEmitter {
  constructor() {
    super();
    
    this.db = new Pool({
      connectionString: process.env.DATABASE_URL || 'postgres://opendirectory:changeme@postgres/configuration'
    });
    
    this.initialize();
  }

  async initialize() {
    await this.createTables();
  }

  async createTables() {
    const query = `
      CREATE TABLE IF NOT EXISTS feature_flags (
        id VARCHAR(255) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        enabled BOOLEAN DEFAULT false,
        rollout_percentage INTEGER DEFAULT 0,
        conditions JSONB DEFAULT '{}',
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    await this.db.query(query);
  }

  async getAllFlags() {
    const result = await this.db.query('SELECT * FROM feature_flags ORDER BY name');
    return result.rows;
  }

  async getFlag(flagId) {
    const result = await this.db.query('SELECT * FROM feature_flags WHERE id = $1', [flagId]);
    return result.rows[0];
  }

  async createFlag(flagId, data) {
    const query = `
      INSERT INTO feature_flags (id, name, description, enabled, rollout_percentage, conditions, metadata)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
    `;
    
    const values = [
      flagId,
      data.name || flagId,
      data.description || '',
      data.enabled || false,
      data.rollout_percentage || 0,
      JSON.stringify(data.conditions || {}),
      JSON.stringify(data.metadata || {})
    ];
    
    const result = await this.db.query(query, values);
    const flag = result.rows[0];
    
    this.emit('flag-changed', {
      flagId,
      action: 'created',
      flag
    });
    
    return flag;
  }

  async updateFlag(flagId, updates) {
    const current = await this.getFlag(flagId);
    if (!current) {
      return this.createFlag(flagId, updates);
    }
    
    const query = `
      UPDATE feature_flags
      SET enabled = $2,
          rollout_percentage = $3,
          conditions = $4,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING *
    `;
    
    const values = [
      flagId,
      updates.enabled !== undefined ? updates.enabled : current.enabled,
      updates.rollout_percentage !== undefined ? updates.rollout_percentage : current.rollout_percentage,
      JSON.stringify(updates.conditions || current.conditions)
    ];
    
    const result = await this.db.query(query, values);
    const flag = result.rows[0];
    
    this.emit('flag-changed', {
      flagId,
      action: 'updated',
      flag,
      changes: updates
    });
    
    logger.info(`Feature flag ${flagId} updated`);
    return flag;
  }

  async deleteFlag(flagId) {
    await this.db.query('DELETE FROM feature_flags WHERE id = $1', [flagId]);
    
    this.emit('flag-changed', {
      flagId,
      action: 'deleted'
    });
    
    logger.info(`Feature flag ${flagId} deleted`);
  }

  async isEnabled(flagId, context = {}) {
    const flag = await this.getFlag(flagId);
    
    if (!flag) {
      return false;
    }
    
    if (!flag.enabled) {
      return false;
    }
    
    // Check rollout percentage
    if (flag.rollout_percentage < 100) {
      const hash = this.hashContext(context.userId || context.sessionId || Math.random());
      const percentage = hash % 100;
      if (percentage >= flag.rollout_percentage) {
        return false;
      }
    }
    
    // Check conditions
    if (flag.conditions && Object.keys(flag.conditions).length > 0) {
      return this.evaluateConditions(flag.conditions, context);
    }
    
    return true;
  }

  evaluateConditions(conditions, context) {
    for (const [key, condition] of Object.entries(conditions)) {
      const contextValue = context[key];
      
      if (typeof condition === 'object') {
        // Handle complex conditions
        if (condition.$in && !condition.$in.includes(contextValue)) {
          return false;
        }
        if (condition.$eq !== undefined && condition.$eq !== contextValue) {
          return false;
        }
        if (condition.$ne !== undefined && condition.$ne === contextValue) {
          return false;
        }
        if (condition.$gt !== undefined && contextValue <= condition.$gt) {
          return false;
        }
        if (condition.$gte !== undefined && contextValue < condition.$gte) {
          return false;
        }
        if (condition.$lt !== undefined && contextValue >= condition.$lt) {
          return false;
        }
        if (condition.$lte !== undefined && contextValue > condition.$lte) {
          return false;
        }
      } else {
        // Simple equality check
        if (condition !== contextValue) {
          return false;
        }
      }
    }
    
    return true;
  }

  hashContext(value) {
    // Simple hash function for rollout percentage
    let hash = 0;
    const str = String(value);
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash);
  }

  // Bulk operations
  async bulkEvaluate(flagIds, context = {}) {
    const results = {};
    
    for (const flagId of flagIds) {
      results[flagId] = await this.isEnabled(flagId, context);
    }
    
    return results;
  }

  async getEnabledFlags(context = {}) {
    const allFlags = await this.getAllFlags();
    const enabled = [];
    
    for (const flag of allFlags) {
      if (await this.isEnabled(flag.id, context)) {
        enabled.push(flag.id);
      }
    }
    
    return enabled;
  }
}

module.exports = FeatureFlags;