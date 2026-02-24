const { Pool } = require('pg');
const winston = require('winston');
const Redis = require('redis');

class PermissionManager {
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.simple(),
      transports: [new winston.transports.Console()]
    });
    
    this.db = new Pool({
      connectionString: process.env.DATABASE_URL || 'postgres://opendirectory:changeme@localhost/printers'
    });
    
    // Redis for caching permissions
    this.redis = Redis.createClient({
      url: process.env.REDIS_URL || 'redis://localhost:6379'
    });
    
    this.redis.on('error', (err) => {
      this.logger.error('Redis error:', err);
    });
    
    this.redis.connect();
    
    this.initDatabase();
  }

  async initDatabase() {
    try {
      await this.db.query(`
        CREATE TABLE IF NOT EXISTS printer_permissions (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          printer_id UUID NOT NULL,
          permission_type VARCHAR(50) NOT NULL,
          entity_type VARCHAR(50) NOT NULL,
          entity_id VARCHAR(255) NOT NULL,
          allow BOOLEAN DEFAULT true,
          priority INTEGER DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          created_by VARCHAR(255),
          UNIQUE(printer_id, permission_type, entity_type, entity_id)
        );

        CREATE TABLE IF NOT EXISTS printer_access_rules (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          printer_id UUID,
          rule_name VARCHAR(255),
          rule_type VARCHAR(50),
          conditions JSONB,
          actions JSONB,
          priority INTEGER DEFAULT 0,
          enabled BOOLEAN DEFAULT true,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS department_printers (
          department_id VARCHAR(255),
          printer_id UUID,
          is_default BOOLEAN DEFAULT false,
          PRIMARY KEY (department_id, printer_id)
        );

        CREATE TABLE IF NOT EXISTS user_printer_defaults (
          user_id VARCHAR(255) PRIMARY KEY,
          printer_id UUID,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX idx_permissions_printer ON printer_permissions(printer_id);
        CREATE INDEX idx_permissions_entity ON printer_permissions(entity_type, entity_id);
        CREATE INDEX idx_dept_printers_dept ON department_printers(department_id);
      `);
      
      this.logger.info('Permissions database initialized');
    } catch (error) {
      this.logger.error('Database initialization error:', error);
    }
  }

  async setPrinterPermissions(printerId, permissions) {
    const client = await this.db.connect();
    
    try {
      await client.query('BEGIN');
      
      // Clear existing permissions
      await client.query(
        'DELETE FROM printer_permissions WHERE printer_id = $1',
        [printerId]
      );
      
      // Add user permissions
      if (permissions.users && permissions.users.length > 0) {
        for (const userId of permissions.users) {
          await client.query(`
            INSERT INTO printer_permissions 
            (printer_id, permission_type, entity_type, entity_id, allow)
            VALUES ($1, 'print', 'user', $2, true)
          `, [printerId, userId]);
        }
      }
      
      // Add group permissions
      if (permissions.groups && permissions.groups.length > 0) {
        for (const groupId of permissions.groups) {
          await client.query(`
            INSERT INTO printer_permissions
            (printer_id, permission_type, entity_type, entity_id, allow)
            VALUES ($1, 'print', 'group', $2, true)
          `, [printerId, groupId]);
        }
      }
      
      // Add department permissions
      if (permissions.departments && permissions.departments.length > 0) {
        for (const deptId of permissions.departments) {
          await client.query(`
            INSERT INTO printer_permissions
            (printer_id, permission_type, entity_type, entity_id, allow)
            VALUES ($1, 'print', 'department', $2, true)
          `, [printerId, deptId]);
          
          // Also add to department_printers table
          await client.query(`
            INSERT INTO department_printers (department_id, printer_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
          `, [deptId, printerId]);
        }
      }
      
      // Set allow all flag
      if (permissions.allowAll) {
        await client.query(`
          INSERT INTO printer_permissions
          (printer_id, permission_type, entity_type, entity_id, allow)
          VALUES ($1, 'print', 'all', '*', true)
        `, [printerId]);
      }
      
      await client.query('COMMIT');
      
      // Clear cache
      await this.clearPermissionCache(printerId);
      
      this.logger.info(`Set permissions for printer ${printerId}`);
      return true;
    } catch (error) {
      await client.query('ROLLBACK');
      this.logger.error('Set permissions error:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  async getPrinterPermissions(printerId) {
    const result = await this.db.query(`
      SELECT * FROM printer_permissions
      WHERE printer_id = $1
      ORDER BY priority DESC, entity_type, entity_id
    `, [printerId]);
    
    const permissions = {
      users: [],
      groups: [],
      departments: [],
      allowAll: false,
      rules: []
    };
    
    result.rows.forEach(row => {
      if (row.entity_type === 'user' && row.allow) {
        permissions.users.push(row.entity_id);
      } else if (row.entity_type === 'group' && row.allow) {
        permissions.groups.push(row.entity_id);
      } else if (row.entity_type === 'department' && row.allow) {
        permissions.departments.push(row.entity_id);
      } else if (row.entity_type === 'all' && row.entity_id === '*') {
        permissions.allowAll = row.allow;
      }
    });
    
    // Get access rules
    const rulesResult = await this.db.query(`
      SELECT * FROM printer_access_rules
      WHERE printer_id = $1 AND enabled = true
      ORDER BY priority DESC
    `, [printerId]);
    
    permissions.rules = rulesResult.rows;
    
    return permissions;
  }

  async checkAccess(printerId, userId, context = {}) {
    // Check cache first
    const cacheKey = `access:${printerId}:${userId}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached !== null) {
      return cached === 'true';
    }
    
    // Check allow all
    const allowAllResult = await this.db.query(`
      SELECT allow FROM printer_permissions
      WHERE printer_id = $1 AND entity_type = 'all' AND entity_id = '*'
    `, [printerId]);
    
    if (allowAllResult.rows.length > 0 && allowAllResult.rows[0].allow) {
      await this.cacheAccess(cacheKey, true);
      return true;
    }
    
    // Check user-specific permission
    const userResult = await this.db.query(`
      SELECT allow FROM printer_permissions
      WHERE printer_id = $1 AND entity_type = 'user' AND entity_id = $2
    `, [printerId, userId]);
    
    if (userResult.rows.length > 0) {
      const allowed = userResult.rows[0].allow;
      await this.cacheAccess(cacheKey, allowed);
      return allowed;
    }
    
    // Get user's groups and department
    const userInfo = await this.getUserInfo(userId);
    
    // Check group permissions
    if (userInfo.groups && userInfo.groups.length > 0) {
      const groupResult = await this.db.query(`
        SELECT allow FROM printer_permissions
        WHERE printer_id = $1 
          AND entity_type = 'group' 
          AND entity_id = ANY($2)
        ORDER BY priority DESC
        LIMIT 1
      `, [printerId, userInfo.groups]);
      
      if (groupResult.rows.length > 0) {
        const allowed = groupResult.rows[0].allow;
        await this.cacheAccess(cacheKey, allowed);
        return allowed;
      }
    }
    
    // Check department permission
    if (userInfo.department) {
      const deptResult = await this.db.query(`
        SELECT allow FROM printer_permissions
        WHERE printer_id = $1 
          AND entity_type = 'department' 
          AND entity_id = $2
      `, [printerId, userInfo.department]);
      
      if (deptResult.rows.length > 0) {
        const allowed = deptResult.rows[0].allow;
        await this.cacheAccess(cacheKey, allowed);
        return allowed;
      }
    }
    
    // Check custom access rules
    const allowed = await this.evaluateAccessRules(printerId, userId, context);
    await this.cacheAccess(cacheKey, allowed);
    
    return allowed;
  }

  async evaluateAccessRules(printerId, userId, context) {
    const rules = await this.db.query(`
      SELECT * FROM printer_access_rules
      WHERE printer_id = $1 AND enabled = true
      ORDER BY priority DESC
    `, [printerId]);
    
    for (const rule of rules.rows) {
      if (this.evaluateRule(rule, userId, context)) {
        return rule.actions?.allow || false;
      }
    }
    
    return false; // Default deny
  }

  evaluateRule(rule, userId, context) {
    const conditions = rule.conditions || {};
    
    // Time-based conditions
    if (conditions.timeRange) {
      const now = new Date();
      const currentHour = now.getHours();
      
      if (currentHour < conditions.timeRange.start || 
          currentHour > conditions.timeRange.end) {
        return false;
      }
    }
    
    // Day of week conditions
    if (conditions.daysOfWeek) {
      const now = new Date();
      const currentDay = now.getDay();
      
      if (!conditions.daysOfWeek.includes(currentDay)) {
        return false;
      }
    }
    
    // Location-based conditions
    if (conditions.locations && context.location) {
      if (!conditions.locations.includes(context.location)) {
        return false;
      }
    }
    
    // IP range conditions
    if (conditions.ipRanges && context.ipAddress) {
      const allowed = conditions.ipRanges.some(range => 
        this.isIpInRange(context.ipAddress, range)
      );
      
      if (!allowed) {
        return false;
      }
    }
    
    return true;
  }

  async getUserInfo(userId) {
    // This would integrate with your identity service
    // For now, return mock data
    try {
      // Query identity service or LDAP
      const userInfo = {
        id: userId,
        groups: [],
        department: null
      };
      
      // Try to get from identity service
      // const response = await axios.get(`http://identity-service:3001/users/${userId}`);
      // userInfo.groups = response.data.groups;
      // userInfo.department = response.data.department;
      
      return userInfo;
    } catch (error) {
      this.logger.warn(`Could not get user info for ${userId}`);
      return { id: userId, groups: [], department: null };
    }
  }

  async getDepartmentPrinters(departmentId) {
    const result = await this.db.query(`
      SELECT p.*, dp.is_default
      FROM printers p
      JOIN department_printers dp ON p.id = dp.printer_id
      WHERE dp.department_id = $1
      ORDER BY dp.is_default DESC, p.name
    `, [departmentId]);
    
    return result.rows;
  }

  async setDepartmentDefaultPrinter(departmentId, printerId) {
    const client = await this.db.connect();
    
    try {
      await client.query('BEGIN');
      
      // Clear existing defaults
      await client.query(`
        UPDATE department_printers
        SET is_default = false
        WHERE department_id = $1
      `, [departmentId]);
      
      // Set new default
      await client.query(`
        UPDATE department_printers
        SET is_default = true
        WHERE department_id = $1 AND printer_id = $2
      `, [departmentId, printerId]);
      
      await client.query('COMMIT');
      
      return true;
    } catch (error) {
      await client.query('ROLLBACK');
      this.logger.error('Set department default error:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  async getUserDefaultPrinter(userId) {
    const result = await this.db.query(`
      SELECT printer_id FROM user_printer_defaults
      WHERE user_id = $1
    `, [userId]);
    
    if (result.rows.length > 0) {
      return result.rows[0].printer_id;
    }
    
    // Check department default
    const userInfo = await this.getUserInfo(userId);
    if (userInfo.department) {
      const deptResult = await this.db.query(`
        SELECT printer_id FROM department_printers
        WHERE department_id = $1 AND is_default = true
      `, [userInfo.department]);
      
      if (deptResult.rows.length > 0) {
        return deptResult.rows[0].printer_id;
      }
    }
    
    return null;
  }

  async setUserDefaultPrinter(userId, printerId) {
    await this.db.query(`
      INSERT INTO user_printer_defaults (user_id, printer_id)
      VALUES ($1, $2)
      ON CONFLICT (user_id) 
      DO UPDATE SET printer_id = $2, updated_at = CURRENT_TIMESTAMP
    `, [userId, printerId]);
    
    return true;
  }

  async getAccessiblePrinters(userId) {
    // Get all printers the user has access to
    const userInfo = await this.getUserInfo(userId);
    
    let query = `
      SELECT DISTINCT p.* FROM printers p
      LEFT JOIN printer_permissions pp ON p.id = pp.printer_id
      WHERE 
        pp.entity_type = 'all' AND pp.entity_id = '*' AND pp.allow = true
        OR (pp.entity_type = 'user' AND pp.entity_id = $1 AND pp.allow = true)
    `;
    
    const params = [userId];
    
    if (userInfo.groups && userInfo.groups.length > 0) {
      query += ` OR (pp.entity_type = 'group' AND pp.entity_id = ANY($2) AND pp.allow = true)`;
      params.push(userInfo.groups);
    }
    
    if (userInfo.department) {
      const paramNum = params.length + 1;
      query += ` OR (pp.entity_type = 'department' AND pp.entity_id = $${paramNum} AND pp.allow = true)`;
      params.push(userInfo.department);
    }
    
    query += ` ORDER BY p.name`;
    
    const result = await this.db.query(query, params);
    return result.rows;
  }

  async createAccessRule(printerId, rule) {
    const result = await this.db.query(`
      INSERT INTO printer_access_rules 
      (printer_id, rule_name, rule_type, conditions, actions, priority, enabled)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
    `, [
      printerId,
      rule.name,
      rule.type,
      JSON.stringify(rule.conditions),
      JSON.stringify(rule.actions),
      rule.priority || 0,
      rule.enabled !== false
    ]);
    
    // Clear cache for this printer
    await this.clearPermissionCache(printerId);
    
    return result.rows[0];
  }

  async updateAccessRule(ruleId, updates) {
    const fields = [];
    const values = [];
    let paramCount = 1;
    
    Object.entries(updates).forEach(([key, value]) => {
      if (key !== 'id') {
        fields.push(`${key} = $${paramCount}`);
        values.push(key === 'conditions' || key === 'actions' ? JSON.stringify(value) : value);
        paramCount++;
      }
    });
    
    values.push(ruleId);
    
    const result = await this.db.query(`
      UPDATE printer_access_rules
      SET ${fields.join(', ')}
      WHERE id = $${paramCount}
      RETURNING printer_id
    `, values);
    
    if (result.rows.length > 0) {
      await this.clearPermissionCache(result.rows[0].printer_id);
    }
    
    return true;
  }

  async deleteAccessRule(ruleId) {
    const result = await this.db.query(`
      DELETE FROM printer_access_rules
      WHERE id = $1
      RETURNING printer_id
    `, [ruleId]);
    
    if (result.rows.length > 0) {
      await this.clearPermissionCache(result.rows[0].printer_id);
    }
    
    return true;
  }

  async cacheAccess(key, allowed) {
    await this.redis.setEx(key, 300, allowed ? 'true' : 'false'); // Cache for 5 minutes
  }

  async clearPermissionCache(printerId) {
    // Clear all cached permissions for this printer
    const keys = await this.redis.keys(`access:${printerId}:*`);
    
    if (keys.length > 0) {
      await this.redis.del(...keys);
    }
  }

  isIpInRange(ip, range) {
    // Simple IP range check
    // In production, use proper IP range library
    return ip.startsWith(range.split('.').slice(0, 3).join('.'));
  }
}

module.exports = PermissionManager;