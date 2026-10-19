class PrintPoolManager {
  constructor({ db, cupsService, printerManager }) {
    this.db = db;
    this.cupsService = cupsService;
    this.printerManager = printerManager;
  }

  async initDatabase() {
    await this.db.query(`
      CREATE TABLE IF NOT EXISTS print_pools (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL UNIQUE,
        display_name VARCHAR(255),
        description TEXT,
        algorithm VARCHAR(20) DEFAULT 'round_robin' CHECK (algorithm IN ('round_robin','least_jobs','priority','failover')),
        cups_queue_name VARCHAR(255),
        active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await this.db.query(`
      CREATE TABLE IF NOT EXISTS print_pool_members (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        pool_id UUID NOT NULL REFERENCES print_pools(id) ON DELETE CASCADE,
        printer_id VARCHAR(255) NOT NULL,
        printer_name VARCHAR(255),
        printer_uri VARCHAR(500),
        weight INTEGER DEFAULT 1,
        priority INTEGER DEFAULT 100,
        active BOOLEAN DEFAULT true,
        current_jobs INTEGER DEFAULT 0,
        total_jobs INTEGER DEFAULT 0,
        last_used_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(pool_id, printer_id)
      )
    `);
  }

  async createPool(data) {
    const {
      name,
      displayName,
      description,
      algorithm = 'round_robin',
      cupsQueueName,
    } = data;

    const result = await this.db.query(
      `INSERT INTO print_pools (name, display_name, description, algorithm, cups_queue_name)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [name, displayName, description, algorithm, cupsQueueName || null]
    );

    const pool = result.rows[0];

    // Optionally create a CUPS class queue if cupsService supports it
    if (cupsQueueName && this.cupsService && typeof this.cupsService.createClass === 'function') {
      try {
        await this.cupsService.createClass(cupsQueueName, displayName || name, description);
      } catch (err) {
        console.warn(`Could not create CUPS class queue '${cupsQueueName}':`, err.message);
      }
    }

    return pool;
  }

  async deletePool(poolId) {
    // Members are cascade-deleted via FK
    const result = await this.db.query(
      `DELETE FROM print_pools WHERE id = $1 RETURNING *`,
      [poolId]
    );
    return result.rows[0] || null;
  }

  async addMember(poolId, printerData) {
    const {
      printerId,
      printerName,
      printerUri,
      weight = 1,
      priority = 100,
    } = printerData;

    const result = await this.db.query(
      `INSERT INTO print_pool_members (pool_id, printer_id, printer_name, printer_uri, weight, priority)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (pool_id, printer_id)
       DO UPDATE SET
         printer_name = EXCLUDED.printer_name,
         printer_uri  = EXCLUDED.printer_uri,
         weight       = EXCLUDED.weight,
         priority     = EXCLUDED.priority
       RETURNING *`,
      [poolId, printerId, printerName, printerUri, weight, priority]
    );

    return result.rows[0];
  }

  async removeMember(poolId, printerId) {
    const result = await this.db.query(
      `DELETE FROM print_pool_members WHERE pool_id = $1 AND printer_id = $2 RETURNING id`,
      [poolId, printerId]
    );
    return result.rowCount > 0;
  }

  async getPool(poolId) {
    const poolResult = await this.db.query(
      `SELECT * FROM print_pools WHERE id = $1`,
      [poolId]
    );
    const pool = poolResult.rows[0];
    if (!pool) return null;

    const membersResult = await this.db.query(
      `SELECT * FROM print_pool_members WHERE pool_id = $1 ORDER BY priority DESC, created_at`,
      [poolId]
    );

    return { ...pool, members: membersResult.rows };
  }

  async listPools() {
    const result = await this.db.query(
      `SELECT p.*,
              COUNT(m.id)::int AS member_count
       FROM print_pools p
       LEFT JOIN print_pool_members m ON m.pool_id = p.id
       GROUP BY p.id
       ORDER BY p.name`
    );
    return result.rows;
  }

  async selectPrinter(poolId) {
    const poolResult = await this.db.query(
      `SELECT algorithm FROM print_pools WHERE id = $1`,
      [poolId]
    );
    if (!poolResult.rows[0]) throw new Error(`Pool ${poolId} not found`);
    const { algorithm } = poolResult.rows[0];

    let member;

    if (algorithm === 'round_robin') {
      // Pick member with oldest last_used_at (or never used)
      const res = await this.db.query(
        `SELECT * FROM print_pool_members
         WHERE pool_id = $1 AND active = true
         ORDER BY last_used_at ASC NULLS FIRST, created_at ASC
         LIMIT 1`,
        [poolId]
      );
      member = res.rows[0];

      if (member) {
        await this.db.query(
          `UPDATE print_pool_members SET last_used_at = CURRENT_TIMESTAMP WHERE id = $1`,
          [member.id]
        );
      }
    } else if (algorithm === 'least_jobs') {
      const res = await this.db.query(
        `SELECT * FROM print_pool_members
         WHERE pool_id = $1 AND active = true
         ORDER BY current_jobs ASC, created_at ASC
         LIMIT 1`,
        [poolId]
      );
      member = res.rows[0];
    } else if (algorithm === 'failover') {
      // Highest priority (largest number = highest priority)
      const res = await this.db.query(
        `SELECT * FROM print_pool_members
         WHERE pool_id = $1 AND active = true
         ORDER BY priority DESC, created_at ASC
         LIMIT 1`,
        [poolId]
      );
      member = res.rows[0];
    } else if (algorithm === 'priority') {
      // Weighted random selection by priority
      const res = await this.db.query(
        `SELECT * FROM print_pool_members
         WHERE pool_id = $1 AND active = true
         ORDER BY priority DESC, weight DESC, created_at ASC
         LIMIT 1`,
        [poolId]
      );
      member = res.rows[0];
    }

    return member || null;
  }

  async routeJob(poolId, jobData) {
    const member = await this.selectPrinter(poolId);
    if (!member) throw new Error(`No active members in pool ${poolId}`);

    // Increment current_jobs counter
    await this.db.query(
      `UPDATE print_pool_members SET current_jobs = current_jobs + 1 WHERE id = $1`,
      [member.id]
    );

    return {
      printerId: member.printer_id,
      printerUri: member.printer_uri,
      memberDbId: member.id,
    };
  }

  async jobCompleted(memberDbId) {
    await this.db.query(
      `UPDATE print_pool_members
       SET current_jobs  = GREATEST(0, current_jobs - 1),
           total_jobs    = total_jobs + 1,
           last_used_at  = CURRENT_TIMESTAMP
       WHERE id = $1`,
      [memberDbId]
    );
  }
}

module.exports = PrintPoolManager;
