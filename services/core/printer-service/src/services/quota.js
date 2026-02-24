const { Pool } = require('pg');
const winston = require('winston');
const Redis = require('redis');
const EventEmitter = require('events');

class QuotaManager extends EventEmitter {
  constructor() {
    super();
    
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.simple(),
      transports: [new winston.transports.Console()]
    });
    
    this.db = new Pool({
      connectionString: process.env.DATABASE_URL || 'postgres://opendirectory:changeme@localhost/printers'
    });
    
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
        CREATE TABLE IF NOT EXISTS user_quotas (
          user_id VARCHAR(255) PRIMARY KEY,
          daily_limit INTEGER DEFAULT 100,
          monthly_limit INTEGER DEFAULT 3000,
          color_limit INTEGER DEFAULT 50,
          color_monthly_limit INTEGER DEFAULT 500,
          scan_limit INTEGER DEFAULT 100,
          scan_monthly_limit INTEGER DEFAULT 1000,
          current_daily_usage INTEGER DEFAULT 0,
          current_monthly_usage INTEGER DEFAULT 0,
          current_color_usage INTEGER DEFAULT 0,
          current_color_monthly INTEGER DEFAULT 0,
          current_scan_usage INTEGER DEFAULT 0,
          current_scan_monthly INTEGER DEFAULT 0,
          last_reset_daily TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          last_reset_monthly TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS group_quotas (
          group_id VARCHAR(255) PRIMARY KEY,
          daily_limit INTEGER DEFAULT 500,
          monthly_limit INTEGER DEFAULT 15000,
          color_limit INTEGER DEFAULT 200,
          shared_pool BOOLEAN DEFAULT true,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS department_quotas (
          department_id VARCHAR(255) PRIMARY KEY,
          monthly_budget DECIMAL(10,2),
          cost_per_page DECIMAL(10,4) DEFAULT 0.05,
          cost_per_color DECIMAL(10,4) DEFAULT 0.15,
          current_month_cost DECIMAL(10,2) DEFAULT 0,
          current_month_pages INTEGER DEFAULT 0,
          last_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS quota_usage_history (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id VARCHAR(255),
          printer_id UUID,
          job_id UUID,
          pages INTEGER,
          color_pages INTEGER,
          cost DECIMAL(10,2),
          timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          quota_type VARCHAR(50)
        );

        CREATE TABLE IF NOT EXISTS quota_alerts (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id VARCHAR(255),
          alert_type VARCHAR(50),
          threshold INTEGER,
          current_usage INTEGER,
          message TEXT,
          sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          acknowledged BOOLEAN DEFAULT false
        );

        CREATE INDEX idx_quota_history_user ON quota_usage_history(user_id, timestamp);
        CREATE INDEX idx_quota_history_time ON quota_usage_history(timestamp);
        CREATE INDEX idx_quota_alerts_user ON quota_alerts(user_id, sent_at);
      `);
      
      this.logger.info('Quota database initialized');
    } catch (error) {
      this.logger.error('Database initialization error:', error);
    }
  }

  async checkQuota(userId, printerId, jobDetails = {}) {
    try {
      // Get user quota
      const quota = await this.getUserQuota(userId);
      
      if (!quota) {
        // Create default quota for new user
        await this.createDefaultQuota(userId);
        return true; // Allow first print
      }
      
      const pages = jobDetails.pages || 1;
      const copies = jobDetails.copies || 1;
      const totalPages = pages * copies;
      const isColor = jobDetails.color || false;
      
      // Check daily limit
      if (quota.daily_limit > 0 && 
          quota.current_daily_usage + totalPages > quota.daily_limit) {
        await this.sendQuotaAlert(userId, 'daily_exceeded', quota.daily_limit, quota.current_daily_usage);
        return false;
      }
      
      // Check monthly limit
      if (quota.monthly_limit > 0 && 
          quota.current_monthly_usage + totalPages > quota.monthly_limit) {
        await this.sendQuotaAlert(userId, 'monthly_exceeded', quota.monthly_limit, quota.current_monthly_usage);
        return false;
      }
      
      // Check color limits if applicable
      if (isColor) {
        if (quota.color_limit > 0 && 
            quota.current_color_usage + totalPages > quota.color_limit) {
          await this.sendQuotaAlert(userId, 'color_exceeded', quota.color_limit, quota.current_color_usage);
          return false;
        }
        
        if (quota.color_monthly_limit > 0 && 
            quota.current_color_monthly + totalPages > quota.color_monthly_limit) {
          await this.sendQuotaAlert(userId, 'color_monthly_exceeded', quota.color_monthly_limit, quota.current_color_monthly);
          return false;
        }
      }
      
      // Check department budget if applicable
      const deptQuotaOk = await this.checkDepartmentQuota(userId, totalPages, isColor);
      if (!deptQuotaOk) {
        return false;
      }
      
      // Check group quota if applicable
      const groupQuotaOk = await this.checkGroupQuota(userId, totalPages);
      if (!groupQuotaOk) {
        return false;
      }
      
      // Send warning if approaching limits
      await this.checkAndSendWarnings(userId, quota, totalPages, isColor);
      
      return true;
    } catch (error) {
      this.logger.error(`Quota check error for user ${userId}:`, error);
      return true; // Allow printing on error
    }
  }

  async updateUsage(userId, printerId, jobDetails) {
    const client = await this.db.connect();
    
    try {
      await client.query('BEGIN');
      
      const pages = jobDetails.pages || 1;
      const copies = jobDetails.copies || 1;
      const totalPages = pages * copies;
      const isColor = jobDetails.color || false;
      const cost = jobDetails.cost || this.calculateCost(totalPages, isColor);
      
      // Update user quota usage
      if (isColor) {
        await client.query(`
          UPDATE user_quotas
          SET current_daily_usage = current_daily_usage + $1,
              current_monthly_usage = current_monthly_usage + $1,
              current_color_usage = current_color_usage + $1,
              current_color_monthly = current_color_monthly + $1,
              updated_at = CURRENT_TIMESTAMP
          WHERE user_id = $2
        `, [totalPages, userId]);
      } else {
        await client.query(`
          UPDATE user_quotas
          SET current_daily_usage = current_daily_usage + $1,
              current_monthly_usage = current_monthly_usage + $1,
              updated_at = CURRENT_TIMESTAMP
          WHERE user_id = $2
        `, [totalPages, userId]);
      }
      
      // Record usage history
      await client.query(`
        INSERT INTO quota_usage_history 
        (user_id, printer_id, job_id, pages, color_pages, cost, quota_type)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [
        userId,
        printerId,
        jobDetails.jobId,
        totalPages,
        isColor ? totalPages : 0,
        cost,
        'print'
      ]);
      
      // Update department quota if applicable
      await this.updateDepartmentUsage(client, userId, totalPages, isColor, cost);
      
      await client.query('COMMIT');
      
      // Update cache
      await this.updateQuotaCache(userId);
      
      // Emit usage event
      this.emit('usage:updated', {
        userId,
        printerId,
        pages: totalPages,
        color: isColor,
        cost
      });
      
      return true;
    } catch (error) {
      await client.query('ROLLBACK');
      this.logger.error(`Update usage error for user ${userId}:`, error);
      throw error;
    } finally {
      client.release();
    }
  }

  async getUserQuota(userId) {
    // Check cache first
    const cached = await this.redis.get(`quota:${userId}`);
    if (cached) {
      return JSON.parse(cached);
    }
    
    const result = await this.db.query(
      'SELECT * FROM user_quotas WHERE user_id = $1',
      [userId]
    );
    
    if (result.rows.length === 0) {
      return null;
    }
    
    const quota = result.rows[0];
    
    // Cache for 5 minutes
    await this.redis.setEx(`quota:${userId}`, 300, JSON.stringify(quota));
    
    return quota;
  }

  async setUserQuota(userId, limits) {
    await this.db.query(`
      INSERT INTO user_quotas (
        user_id, daily_limit, monthly_limit, 
        color_limit, color_monthly_limit,
        scan_limit, scan_monthly_limit
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT (user_id)
      DO UPDATE SET
        daily_limit = COALESCE($2, user_quotas.daily_limit),
        monthly_limit = COALESCE($3, user_quotas.monthly_limit),
        color_limit = COALESCE($4, user_quotas.color_limit),
        color_monthly_limit = COALESCE($5, user_quotas.color_monthly_limit),
        scan_limit = COALESCE($6, user_quotas.scan_limit),
        scan_monthly_limit = COALESCE($7, user_quotas.scan_monthly_limit),
        updated_at = CURRENT_TIMESTAMP
    `, [
      userId,
      limits.daily,
      limits.monthly,
      limits.colorDaily,
      limits.colorMonthly,
      limits.scanDaily,
      limits.scanMonthly
    ]);
    
    // Clear cache
    await this.redis.del(`quota:${userId}`);
    
    this.emit('quota:updated', { userId, limits });
    
    return true;
  }

  async createDefaultQuota(userId) {
    await this.db.query(`
      INSERT INTO user_quotas (user_id)
      VALUES ($1)
      ON CONFLICT (user_id) DO NOTHING
    `, [userId]);
  }

  async resetDailyQuotas() {
    const result = await this.db.query(`
      UPDATE user_quotas
      SET current_daily_usage = 0,
          current_color_usage = 0,
          current_scan_usage = 0,
          last_reset_daily = CURRENT_TIMESTAMP
      WHERE last_reset_daily < CURRENT_DATE
      RETURNING user_id
    `);
    
    // Clear cache for affected users
    for (const row of result.rows) {
      await this.redis.del(`quota:${row.user_id}`);
    }
    
    this.logger.info(`Reset daily quotas for ${result.rowCount} users`);
    this.emit('quota:daily_reset', { count: result.rowCount });
    
    return result.rowCount;
  }

  async resetMonthlyQuotas() {
    const result = await this.db.query(`
      UPDATE user_quotas
      SET current_monthly_usage = 0,
          current_color_monthly = 0,
          current_scan_monthly = 0,
          last_reset_monthly = CURRENT_TIMESTAMP
      WHERE EXTRACT(MONTH FROM last_reset_monthly) != EXTRACT(MONTH FROM CURRENT_DATE)
         OR EXTRACT(YEAR FROM last_reset_monthly) != EXTRACT(YEAR FROM CURRENT_DATE)
      RETURNING user_id
    `);
    
    // Reset department quotas
    await this.db.query(`
      UPDATE department_quotas
      SET current_month_cost = 0,
          current_month_pages = 0,
          last_reset = CURRENT_TIMESTAMP
      WHERE EXTRACT(MONTH FROM last_reset) != EXTRACT(MONTH FROM CURRENT_DATE)
         OR EXTRACT(YEAR FROM last_reset) != EXTRACT(YEAR FROM CURRENT_DATE)
    `);
    
    // Clear cache
    for (const row of result.rows) {
      await this.redis.del(`quota:${row.user_id}`);
    }
    
    this.logger.info(`Reset monthly quotas for ${result.rowCount} users`);
    this.emit('quota:monthly_reset', { count: result.rowCount });
    
    return result.rowCount;
  }

  async checkDepartmentQuota(userId, pages, isColor) {
    // Get user's department
    const userInfo = await this.getUserDepartment(userId);
    if (!userInfo.department) {
      return true;
    }
    
    const result = await this.db.query(
      'SELECT * FROM department_quotas WHERE department_id = $1',
      [userInfo.department]
    );
    
    if (result.rows.length === 0) {
      return true;
    }
    
    const dept = result.rows[0];
    const cost = this.calculateCost(pages, isColor, dept);
    
    if (dept.monthly_budget && dept.current_month_cost + cost > dept.monthly_budget) {
      await this.sendQuotaAlert(userId, 'department_budget_exceeded', 
                               dept.monthly_budget, dept.current_month_cost);
      return false;
    }
    
    return true;
  }

  async checkGroupQuota(userId, pages) {
    // Get user's groups
    const userInfo = await this.getUserGroups(userId);
    if (!userInfo.groups || userInfo.groups.length === 0) {
      return true;
    }
    
    // Check each group quota
    for (const groupId of userInfo.groups) {
      const result = await this.db.query(
        'SELECT * FROM group_quotas WHERE group_id = $1',
        [groupId]
      );
      
      if (result.rows.length > 0) {
        const group = result.rows[0];
        
        if (group.shared_pool) {
          // Check shared pool usage
          const usageResult = await this.db.query(`
            SELECT SUM(current_monthly_usage) as total
            FROM user_quotas
            WHERE user_id IN (
              SELECT user_id FROM user_groups WHERE group_id = $1
            )
          `, [groupId]);
          
          const currentUsage = usageResult.rows[0]?.total || 0;
          
          if (group.monthly_limit && currentUsage + pages > group.monthly_limit) {
            await this.sendQuotaAlert(userId, 'group_quota_exceeded',
                                     group.monthly_limit, currentUsage);
            return false;
          }
        }
      }
    }
    
    return true;
  }

  async updateDepartmentUsage(client, userId, pages, isColor, cost) {
    const userInfo = await this.getUserDepartment(userId);
    if (!userInfo.department) {
      return;
    }
    
    await client.query(`
      UPDATE department_quotas
      SET current_month_cost = current_month_cost + $1,
          current_month_pages = current_month_pages + $2
      WHERE department_id = $3
    `, [cost, pages, userInfo.department]);
  }

  async checkAndSendWarnings(userId, quota, plannedPages, isColor) {
    // Check if approaching limits (80% threshold)
    const warnings = [];
    
    if (quota.daily_limit > 0) {
      const usage = quota.current_daily_usage + plannedPages;
      const percentage = (usage / quota.daily_limit) * 100;
      
      if (percentage >= 80 && percentage < 100) {
        warnings.push({
          type: 'daily_warning',
          limit: quota.daily_limit,
          current: usage,
          percentage: Math.round(percentage)
        });
      }
    }
    
    if (quota.monthly_limit > 0) {
      const usage = quota.current_monthly_usage + plannedPages;
      const percentage = (usage / quota.monthly_limit) * 100;
      
      if (percentage >= 80 && percentage < 100) {
        warnings.push({
          type: 'monthly_warning',
          limit: quota.monthly_limit,
          current: usage,
          percentage: Math.round(percentage)
        });
      }
    }
    
    // Send warnings
    for (const warning of warnings) {
      await this.sendQuotaAlert(userId, warning.type, warning.limit, warning.current);
    }
  }

  async sendQuotaAlert(userId, alertType, limit, current) {
    const messages = {
      daily_exceeded: `Daily print quota exceeded. Limit: ${limit}, Current: ${current}`,
      monthly_exceeded: `Monthly print quota exceeded. Limit: ${limit}, Current: ${current}`,
      color_exceeded: `Color print quota exceeded. Limit: ${limit}, Current: ${current}`,
      department_budget_exceeded: `Department budget exceeded. Budget: $${limit}, Current: $${current}`,
      group_quota_exceeded: `Group quota exceeded. Limit: ${limit}, Current: ${current}`,
      daily_warning: `Warning: Approaching daily limit. ${current}/${limit} pages (${Math.round(current/limit*100)}%)`,
      monthly_warning: `Warning: Approaching monthly limit. ${current}/${limit} pages (${Math.round(current/limit*100)}%)`
    };
    
    const message = messages[alertType] || 'Quota limit reached';
    
    await this.db.query(`
      INSERT INTO quota_alerts (user_id, alert_type, threshold, current_usage, message)
      VALUES ($1, $2, $3, $4, $5)
    `, [userId, alertType, limit, current, message]);
    
    this.emit('quota:alert', {
      userId,
      alertType,
      message,
      limit,
      current
    });
    
    this.logger.warn(`Quota alert for user ${userId}: ${message}`);
  }

  async getUsageReport(userId, startDate, endDate) {
    const result = await this.db.query(`
      SELECT 
        DATE(timestamp) as date,
        COUNT(*) as jobs,
        SUM(pages) as total_pages,
        SUM(color_pages) as color_pages,
        SUM(cost) as total_cost
      FROM quota_usage_history
      WHERE user_id = $1 
        AND timestamp >= $2 
        AND timestamp <= $3
      GROUP BY DATE(timestamp)
      ORDER BY date
    `, [userId, startDate, endDate]);
    
    return result.rows;
  }

  async getDepartmentReport(departmentId, startDate, endDate) {
    // Get all users in department
    const usersResult = await this.db.query(`
      SELECT user_id FROM user_departments WHERE department_id = $1
    `, [departmentId]);
    
    const userIds = usersResult.rows.map(r => r.user_id);
    
    if (userIds.length === 0) {
      return [];
    }
    
    const result = await this.db.query(`
      SELECT 
        DATE(timestamp) as date,
        COUNT(DISTINCT user_id) as users,
        COUNT(*) as jobs,
        SUM(pages) as total_pages,
        SUM(color_pages) as color_pages,
        SUM(cost) as total_cost
      FROM quota_usage_history
      WHERE user_id = ANY($1)
        AND timestamp >= $2 
        AND timestamp <= $3
      GROUP BY DATE(timestamp)
      ORDER BY date
    `, [userIds, startDate, endDate]);
    
    return result.rows;
  }

  calculateCost(pages, isColor, deptSettings = null) {
    if (deptSettings) {
      const costPerPage = isColor ? 
        (deptSettings.cost_per_color || 0.15) : 
        (deptSettings.cost_per_page || 0.05);
      return pages * costPerPage;
    }
    
    // Default costs
    const costPerPage = isColor ? 0.10 : 0.02;
    return pages * costPerPage;
  }

  async updateQuotaCache(userId) {
    const quota = await this.db.query(
      'SELECT * FROM user_quotas WHERE user_id = $1',
      [userId]
    );
    
    if (quota.rows.length > 0) {
      await this.redis.setEx(`quota:${userId}`, 300, JSON.stringify(quota.rows[0]));
    }
  }

  async getUserDepartment(userId) {
    // This would integrate with identity service
    // Mock implementation
    return { department: null };
  }

  async getUserGroups(userId) {
    // This would integrate with identity service
    // Mock implementation
    return { groups: [] };
  }

  async startQuotaReset() {
    // Schedule daily reset at midnight
    const dailyReset = () => {
      const now = new Date();
      const tomorrow = new Date(now);
      tomorrow.setDate(tomorrow.getDate() + 1);
      tomorrow.setHours(0, 0, 0, 0);
      
      const msToMidnight = tomorrow.getTime() - now.getTime();
      
      setTimeout(() => {
        this.resetDailyQuotas();
        dailyReset(); // Schedule next reset
      }, msToMidnight);
    };
    
    // Schedule monthly reset
    const monthlyReset = () => {
      const now = new Date();
      const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1, 0, 0, 0, 0);
      const msToNextMonth = nextMonth.getTime() - now.getTime();
      
      setTimeout(() => {
        this.resetMonthlyQuotas();
        monthlyReset(); // Schedule next reset
      }, msToNextMonth);
    };
    
    dailyReset();
    monthlyReset();
    
    this.logger.info('Quota reset scheduler started');
  }
}

module.exports = QuotaManager;