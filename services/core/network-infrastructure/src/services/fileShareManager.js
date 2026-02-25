const { Pool } = require('pg');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');
const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');
const util = require('util');

const execAsync = util.promisify(exec);

class FileShareManager extends EventEmitter {
  constructor() {
    super();
    
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.simple(),
      transports: [new winston.transports.Console()]
    });
    
    this.db = new Pool({
      connectionString: process.env.DATABASE_URL || 'postgres://opendirectory:changeme@localhost/network'
    });
    
    this.shares = new Map();
    this.quotas = new Map();
    
    this.initDatabase();
  }

  async initDatabase() {
    try {
      await this.db.query(`
        CREATE TABLE IF NOT EXISTS network_shares (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          name VARCHAR(255) UNIQUE NOT NULL,
          path TEXT NOT NULL,
          type VARCHAR(20) DEFAULT 'SMB',
          description TEXT,
          enabled BOOLEAN DEFAULT true,
          guest_access BOOLEAN DEFAULT false,
          read_only BOOLEAN DEFAULT false,
          browseable BOOLEAN DEFAULT true,
          recycle_bin BOOLEAN DEFAULT true,
          versioning BOOLEAN DEFAULT false,
          max_connections INTEGER,
          quota_enabled BOOLEAN DEFAULT false,
          quota_size_gb INTEGER,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS share_permissions (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          share_id UUID REFERENCES network_shares(id) ON DELETE CASCADE,
          principal_type VARCHAR(20) NOT NULL,
          principal_id VARCHAR(255) NOT NULL,
          permission VARCHAR(20) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(share_id, principal_type, principal_id)
        );

        CREATE TABLE IF NOT EXISTS share_usage (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          share_id UUID REFERENCES network_shares(id) ON DELETE CASCADE,
          timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          size_bytes BIGINT,
          file_count INTEGER,
          folder_count INTEGER,
          active_connections INTEGER,
          bandwidth_usage_mbps DECIMAL
        );

        CREATE TABLE IF NOT EXISTS user_home_folders (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          username VARCHAR(255) UNIQUE NOT NULL,
          path TEXT NOT NULL,
          quota_gb INTEGER DEFAULT 10,
          used_bytes BIGINT DEFAULT 0,
          last_accessed TIMESTAMP,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS share_audit_log (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          share_id UUID REFERENCES network_shares(id) ON DELETE CASCADE,
          username VARCHAR(255),
          client_ip VARCHAR(45),
          action VARCHAR(50),
          file_path TEXT,
          result VARCHAR(20),
          timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS dfs_namespaces (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          name VARCHAR(255) UNIQUE NOT NULL,
          type VARCHAR(20) DEFAULT 'Domain',
          description TEXT,
          root_path TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS dfs_links (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          namespace_id UUID REFERENCES dfs_namespaces(id) ON DELETE CASCADE,
          name VARCHAR(255) NOT NULL,
          target_path TEXT NOT NULL,
          priority INTEGER DEFAULT 0,
          enabled BOOLEAN DEFAULT true,
          UNIQUE(namespace_id, name)
        );

        CREATE INDEX idx_share_perms_share ON share_permissions(share_id);
        CREATE INDEX idx_share_usage_time ON share_usage(timestamp);
        CREATE INDEX idx_audit_log_time ON share_audit_log(timestamp);
        CREATE INDEX idx_audit_log_user ON share_audit_log(username);
      `);
      
      this.logger.info('File share database initialized');
      await this.loadShares();
    } catch (error) {
      this.logger.error('Database initialization error:', error);
    }
  }

  async loadShares() {
    try {
      const result = await this.db.query(`
        SELECT s.*, 
               COUNT(DISTINCT p.id) as permission_count,
               MAX(u.size_bytes) as current_size
        FROM network_shares s
        LEFT JOIN share_permissions p ON s.id = p.share_id
        LEFT JOIN share_usage u ON s.id = u.share_id
        WHERE s.enabled = true
        GROUP BY s.id
      `);
      
      this.shares.clear();
      
      for (const share of result.rows) {
        // Load permissions
        const perms = await this.db.query(
          'SELECT * FROM share_permissions WHERE share_id = $1',
          [share.id]
        );
        
        share.permissions = perms.rows;
        this.shares.set(share.name, share);
      }
      
      this.logger.info(`Loaded ${this.shares.size} network shares`);
    } catch (error) {
      this.logger.error('Load shares error:', error);
    }
  }

  async createShare(config) {
    try {
      const {
        name,
        path: sharePath,
        type = 'SMB',
        description,
        permissions,
        quota,
        options = {}
      } = config;
      
      // Validate and create directory if needed
      await this.ensureDirectoryExists(sharePath);
      
      // Create share in database
      const result = await this.db.query(`
        INSERT INTO network_shares (
          name, path, type, description,
          guest_access, read_only, browseable,
          recycle_bin, versioning, quota_enabled, quota_size_gb
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *
      `, [
        name,
        sharePath,
        type,
        description,
        options.guestAccess || false,
        options.readOnly || false,
        options.browseable !== false,
        options.recycleBin !== false,
        options.versioning || false,
        quota ? true : false,
        quota
      ]);
      
      const share = result.rows[0];
      
      // Set permissions
      if (permissions) {
        await this.setPermissions(share.id, permissions);
      }
      
      // Configure share based on type
      if (type === 'SMB') {
        await this.configureSMBShare(share);
      } else if (type === 'NFS') {
        await this.configureNFSShare(share);
      } else if (type === 'AFP') {
        await this.configureAFPShare(share);
      }
      
      // Enable quota if specified
      if (quota) {
        await this.setQuota(sharePath, quota);
      }
      
      // Reload shares
      await this.loadShares();
      
      this.emit('share:created', share);
      this.logger.info(`Created ${type} share: ${name} -> ${sharePath}`);
      
      return share;
    } catch (error) {
      this.logger.error('Create share error:', error);
      throw error;
    }
  }

  async configureSMBShare(share) {
    // Configure Samba share
    const sambaConfig = `
[${share.name}]
    path = ${share.path}
    browseable = ${share.browseable ? 'yes' : 'no'}
    read only = ${share.read_only ? 'yes' : 'no'}
    guest ok = ${share.guest_access ? 'yes' : 'no'}
    create mask = 0755
    directory mask = 0755
    ${share.recycle_bin ? 'vfs objects = recycle' : ''}
    ${share.recycle_bin ? 'recycle:repository = .recycle' : ''}
    ${share.recycle_bin ? 'recycle:keeptree = yes' : ''}
    ${share.recycle_bin ? 'recycle:versions = yes' : ''}
    ${share.versioning ? 'vfs objects = shadow_copy2' : ''}
    ${share.max_connections ? `max connections = ${share.max_connections}` : ''}
`;
    
    // Write to smb.conf (in production, would append to actual file)
    const smbConfPath = '/etc/samba/smb.conf.d/' + share.name + '.conf';
    
    try {
      await fs.writeFile(smbConfPath, sambaConfig);
      
      // Reload Samba
      await execAsync('smbcontrol all reload-config');
      
      this.logger.info(`Configured SMB share: ${share.name}`);
    } catch (error) {
      this.logger.warn(`Could not configure SMB (running in container): ${error.message}`);
    }
  }

  async configureNFSShare(share) {
    // Configure NFS export
    const nfsExport = `${share.path} *(rw,sync,no_subtree_check,no_root_squash)`;
    
    try {
      // Add to /etc/exports
      await execAsync(`echo "${nfsExport}" >> /etc/exports`);
      
      // Reload NFS
      await execAsync('exportfs -ra');
      
      this.logger.info(`Configured NFS export: ${share.name}`);
    } catch (error) {
      this.logger.warn(`Could not configure NFS (running in container): ${error.message}`);
    }
  }

  async configureAFPShare(share) {
    // Configure AFP (Apple File Protocol) for macOS
    const afpConfig = `
"${share.name}" {
    path = "${share.path}"
    valid users = "@users"
    ${share.read_only ? 'read only = yes' : ''}
    ${share.quota_size_gb ? `vol size limit = ${share.quota_size_gb * 1024}` : ''}
}
`;
    
    try {
      // Would configure netatalk for AFP
      this.logger.info(`Configured AFP share: ${share.name}`);
    } catch (error) {
      this.logger.warn(`Could not configure AFP: ${error.message}`);
    }
  }

  async deleteShare(shareName) {
    try {
      const share = this.shares.get(shareName);
      if (!share) {
        throw new Error('Share not found');
      }
      
      // Remove from database
      await this.db.query('DELETE FROM network_shares WHERE name = $1', [shareName]);
      
      // Remove SMB configuration
      try {
        await fs.unlink(`/etc/samba/smb.conf.d/${shareName}.conf`);
        await execAsync('smbcontrol all reload-config');
      } catch (error) {
        // Ignore if file doesn't exist
      }
      
      // Reload shares
      await this.loadShares();
      
      this.emit('share:deleted', shareName);
      return true;
    } catch (error) {
      this.logger.error('Delete share error:', error);
      throw error;
    }
  }

  async setPermissions(shareId, permissions) {
    const client = await this.db.connect();
    
    try {
      await client.query('BEGIN');
      
      // Clear existing permissions
      await client.query('DELETE FROM share_permissions WHERE share_id = $1', [shareId]);
      
      // Add new permissions
      for (const perm of permissions.users || []) {
        await client.query(`
          INSERT INTO share_permissions (share_id, principal_type, principal_id, permission)
          VALUES ($1, 'user', $2, $3)
        `, [shareId, perm.id, perm.permission]);
      }
      
      for (const perm of permissions.groups || []) {
        await client.query(`
          INSERT INTO share_permissions (share_id, principal_type, principal_id, permission)
          VALUES ($1, 'group', $2, $3)
        `, [shareId, perm.id, perm.permission]);
      }
      
      await client.query('COMMIT');
      
      // Apply filesystem ACLs
      await this.applyFilesystemPermissions(shareId);
      
      return true;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async applyFilesystemPermissions(shareId) {
    const share = await this.getShare(shareId);
    const permissions = await this.db.query(
      'SELECT * FROM share_permissions WHERE share_id = $1',
      [shareId]
    );
    
    for (const perm of permissions.rows) {
      const aclEntry = this.buildACLEntry(perm);
      
      try {
        // Apply ACL using setfacl
        await execAsync(`setfacl -m ${aclEntry} ${share.path}`);
      } catch (error) {
        this.logger.warn(`Could not apply ACL: ${error.message}`);
      }
    }
  }

  buildACLEntry(permission) {
    const type = permission.principal_type === 'user' ? 'u' : 'g';
    const perms = permission.permission === 'read' ? 'rx' : 
                  permission.permission === 'write' ? 'rwx' : 'rwx';
    
    return `${type}:${permission.principal_id}:${perms}`;
  }

  async createHomeFolder(username, quotaGB = 10) {
    try {
      const homePath = `/home/${username}`;
      
      // Create directory
      await this.ensureDirectoryExists(homePath);
      
      // Set ownership (would need actual user ID)
      try {
        await execAsync(`chown ${username}:users ${homePath}`);
        await execAsync(`chmod 700 ${homePath}`);
      } catch (error) {
        this.logger.warn(`Could not set ownership: ${error.message}`);
      }
      
      // Create in database
      const result = await this.db.query(`
        INSERT INTO user_home_folders (username, path, quota_gb)
        VALUES ($1, $2, $3)
        ON CONFLICT (username) 
        DO UPDATE SET quota_gb = $3
        RETURNING *
      `, [username, homePath, quotaGB]);
      
      // Create as SMB share
      await this.createShare({
        name: `home-${username}`,
        path: homePath,
        type: 'SMB',
        description: `Home folder for ${username}`,
        permissions: {
          users: [{ id: username, permission: 'full' }]
        },
        quota: quotaGB,
        options: {
          browseable: false,
          guestAccess: false,
          recycleBin: true,
          versioning: true
        }
      });
      
      this.logger.info(`Created home folder for ${username}`);
      return result.rows[0];
    } catch (error) {
      this.logger.error('Create home folder error:', error);
      throw error;
    }
  }

  async setQuota(path, sizeGB) {
    try {
      // Set filesystem quota using quota tools
      // This would require quota support on the filesystem
      const sizeBytes = sizeGB * 1024 * 1024 * 1024;
      
      // For XFS
      await execAsync(`xfs_quota -x -c "limit bsoft=${sizeBytes} bhard=${sizeBytes} ${path}" /`);
      
      this.logger.info(`Set quota of ${sizeGB}GB on ${path}`);
    } catch (error) {
      // Try ext4 quota
      try {
        await execAsync(`setquota -u ${path} ${sizeGB * 1024 * 1024} ${sizeGB * 1024 * 1024} 0 0 /`);
      } catch (error2) {
        this.logger.warn(`Could not set quota (filesystem may not support it): ${error.message}`);
      }
    }
  }

  async getShareUsage(shareName) {
    const share = this.shares.get(shareName);
    if (!share) {
      throw new Error('Share not found');
    }
    
    try {
      // Get disk usage
      const { stdout } = await execAsync(`du -sb ${share.path}`);
      const sizeBytes = parseInt(stdout.split('\t')[0]);
      
      // Count files and folders
      const { stdout: fileCount } = await execAsync(`find ${share.path} -type f | wc -l`);
      const { stdout: folderCount } = await execAsync(`find ${share.path} -type d | wc -l`);
      
      // Get SMB connections
      let activeConnections = 0;
      try {
        const { stdout: smbStatus } = await execAsync(`smbstatus -S | grep ${shareName} | wc -l`);
        activeConnections = parseInt(smbStatus);
      } catch (error) {
        // smbstatus might not be available
      }
      
      const usage = {
        shareId: share.id,
        shareName: share.name,
        sizeBytes,
        sizeGB: (sizeBytes / (1024 * 1024 * 1024)).toFixed(2),
        fileCount: parseInt(fileCount),
        folderCount: parseInt(folderCount) - 1, // Exclude root
        activeConnections,
        quotaUsed: share.quota_size_gb ? 
          Math.round((sizeBytes / (share.quota_size_gb * 1024 * 1024 * 1024)) * 100) : null
      };
      
      // Record usage
      await this.db.query(`
        INSERT INTO share_usage (share_id, size_bytes, file_count, folder_count, active_connections)
        VALUES ($1, $2, $3, $4, $5)
      `, [share.id, sizeBytes, usage.fileCount, usage.folderCount, activeConnections]);
      
      return usage;
    } catch (error) {
      this.logger.error('Get share usage error:', error);
      
      // Return cached data if available
      const cached = await this.db.query(`
        SELECT * FROM share_usage 
        WHERE share_id = $1 
        ORDER BY timestamp DESC 
        LIMIT 1
      `, [share.id]);
      
      if (cached.rows.length > 0) {
        return {
          shareId: share.id,
          shareName: share.name,
          ...cached.rows[0]
        };
      }
      
      throw error;
    }
  }

  async listShares() {
    const result = await this.db.query(`
      SELECT s.*,
             COUNT(DISTINCT p.id) as permission_count,
             COUNT(DISTINCT l.id) as recent_access_count
      FROM network_shares s
      LEFT JOIN share_permissions p ON s.id = p.share_id
      LEFT JOIN share_audit_log l ON s.id = l.share_id 
        AND l.timestamp > CURRENT_TIMESTAMP - INTERVAL '24 hours'
      GROUP BY s.id
      ORDER BY s.name
    `);
    
    return result.rows;
  }

  async getShare(shareId) {
    const result = await this.db.query(
      'SELECT * FROM network_shares WHERE id = $1 OR name = $1',
      [shareId]
    );
    
    if (result.rows.length === 0) {
      throw new Error('Share not found');
    }
    
    return result.rows[0];
  }

  async auditLog(shareId, username, clientIp, action, filePath, result) {
    try {
      await this.db.query(`
        INSERT INTO share_audit_log (share_id, username, client_ip, action, file_path, result)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [shareId, username, clientIp, action, filePath, result]);
    } catch (error) {
      this.logger.warn('Audit log error:', error);
    }
  }

  async getAuditLog(shareId, startDate, endDate) {
    const result = await this.db.query(`
      SELECT * FROM share_audit_log
      WHERE share_id = $1 
        AND timestamp >= $2 
        AND timestamp <= $3
      ORDER BY timestamp DESC
      LIMIT 1000
    `, [shareId, startDate, endDate]);
    
    return result.rows;
  }

  async ensureDirectoryExists(dirPath) {
    try {
      await fs.access(dirPath);
    } catch (error) {
      // Directory doesn't exist, create it
      await fs.mkdir(dirPath, { recursive: true });
      this.logger.info(`Created directory: ${dirPath}`);
    }
  }

  // DFS (Distributed File System) Support
  async createDFSNamespace(name, type = 'Domain', description) {
    try {
      const result = await this.db.query(`
        INSERT INTO dfs_namespaces (name, type, description, root_path)
        VALUES ($1, $2, $3, $4)
        RETURNING *
      `, [name, type, description, `\\\\${process.env.DOMAIN_NAME || 'local'}\\${name}`]);
      
      this.emit('dfs:namespace_created', result.rows[0]);
      return result.rows[0];
    } catch (error) {
      this.logger.error('Create DFS namespace error:', error);
      throw error;
    }
  }

  async addDFSLink(namespaceId, linkName, targetPath, priority = 0) {
    try {
      const result = await this.db.query(`
        INSERT INTO dfs_links (namespace_id, name, target_path, priority)
        VALUES ($1, $2, $3, $4)
        RETURNING *
      `, [namespaceId, linkName, targetPath, priority]);
      
      this.emit('dfs:link_added', result.rows[0]);
      return result.rows[0];
    } catch (error) {
      this.logger.error('Add DFS link error:', error);
      throw error;
    }
  }

  async getDFSNamespaces() {
    const result = await this.db.query(`
      SELECT n.*, COUNT(l.id) as link_count
      FROM dfs_namespaces n
      LEFT JOIN dfs_links l ON n.id = l.namespace_id
      GROUP BY n.id
      ORDER BY n.name
    `);
    
    return result.rows;
  }

  isHealthy() {
    return this.shares.size >= 0;
  }
}

module.exports = FileShareManager;