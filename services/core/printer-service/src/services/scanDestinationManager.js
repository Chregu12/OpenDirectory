const { exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');

class ScanDestinationManager {
  constructor({ db }) {
    this.db = db;
  }

  async initDatabase() {
    await this.db.query(`
      CREATE TABLE IF NOT EXISTS scan_destinations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        entity_type VARCHAR(10) NOT NULL CHECK (entity_type IN ('user','group')),
        entity_id VARCHAR(255) NOT NULL,
        destination_type VARCHAR(20) NOT NULL DEFAULT 'smb',
        smb_server VARCHAR(255),
        smb_share VARCHAR(255),
        smb_path VARCHAR(500) DEFAULT '',
        smb_username VARCHAR(255),
        smb_password_enc TEXT,
        smb_domain VARCHAR(255),
        local_path VARCHAR(500),
        label VARCHAR(100),
        is_default BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(entity_type, entity_id)
      )
    `);

    await this.db.query(`
      CREATE TABLE IF NOT EXISTS scan_destination_overrides (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id VARCHAR(255) NOT NULL,
        scanner_id VARCHAR(255),
        destination_id UUID REFERENCES scan_destinations(id) ON DELETE SET NULL,
        custom_subpath VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, scanner_id)
      )
    `);
  }

  _encodePassword(password) {
    // NOTE: In production, use a secrets vault (e.g. HashiCorp Vault) instead of base64 encoding
    if (!password) return null;
    return Buffer.from(password).toString('base64');
  }

  _decodePassword(encoded) {
    if (!encoded) return null;
    return Buffer.from(encoded, 'base64').toString('utf8');
  }

  _rowToDestination(row) {
    if (!row) return null;
    return {
      id: row.id,
      entityType: row.entity_type,
      entityId: row.entity_id,
      type: row.destination_type,
      smbServer: row.smb_server,
      smbShare: row.smb_share,
      smbPath: row.smb_path,
      smbUsername: row.smb_username,
      smbPassword: this._decodePassword(row.smb_password_enc),
      smbDomain: row.smb_domain,
      localPath: row.local_path,
      label: row.label,
      isDefault: row.is_default,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  async setUserDestination(userId, destination) {
    return this._upsertDestination('user', userId, destination);
  }

  async setGroupDestination(groupId, destination) {
    return this._upsertDestination('group', groupId, destination);
  }

  async _upsertDestination(entityType, entityId, destination) {
    const {
      type = 'smb',
      smbServer,
      smbShare,
      smbPath = '',
      smbUsername,
      smbPassword,
      smbDomain,
      localPath,
      label,
    } = destination;

    const passwordEnc = this._encodePassword(smbPassword);

    const result = await this.db.query(
      `INSERT INTO scan_destinations
         (entity_type, entity_id, destination_type, smb_server, smb_share, smb_path,
          smb_username, smb_password_enc, smb_domain, local_path, label, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CURRENT_TIMESTAMP)
       ON CONFLICT (entity_type, entity_id)
       DO UPDATE SET
         destination_type  = EXCLUDED.destination_type,
         smb_server        = EXCLUDED.smb_server,
         smb_share         = EXCLUDED.smb_share,
         smb_path          = EXCLUDED.smb_path,
         smb_username      = EXCLUDED.smb_username,
         smb_password_enc  = EXCLUDED.smb_password_enc,
         smb_domain        = EXCLUDED.smb_domain,
         local_path        = EXCLUDED.local_path,
         label             = EXCLUDED.label,
         updated_at        = CURRENT_TIMESTAMP
       RETURNING *`,
      [entityType, entityId, type, smbServer, smbShare, smbPath,
       smbUsername, passwordEnc, smbDomain, localPath, label]
    );

    return this._rowToDestination(result.rows[0]);
  }

  async getUserDestination(userId) {
    const result = await this.db.query(
      `SELECT * FROM scan_destinations WHERE entity_type = 'user' AND entity_id = $1`,
      [userId]
    );
    return this._rowToDestination(result.rows[0] || null);
  }

  async getGroupDestination(groupId) {
    const result = await this.db.query(
      `SELECT * FROM scan_destinations WHERE entity_type = 'group' AND entity_id = $1`,
      [groupId]
    );
    return this._rowToDestination(result.rows[0] || null);
  }

  // Replace @{username}, @{email}, and %U / %u placeholders with the actual user values.
  // userId may be a full email (jdoe@corp.com) or a plain login name (jdoe).
  _resolveVariables(dest, userId) {
    if (!dest || !userId) return dest;
    const email    = userId.includes('@') ? userId : `${userId}@opendirectory.local`;
    const username = userId.includes('@') ? userId.split('@')[0] : userId;

    const replace = str =>
      str ? str
        .replace(/@\{username\}/g, username)
        .replace(/@\{email\}/g,    email)
        .replace(/%U/g,            username)
        .replace(/%u/g,            username)
      : str;

    return {
      ...dest,
      smbPath:   replace(dest.smbPath),
      localPath: replace(dest.localPath),
    };
  }

  async resolveDestination(userId, userGroups = []) {
    // 1. User-specific destination
    const userDest = await this.getUserDestination(userId);
    if (userDest) return this._resolveVariables(userDest, userId);

    // 2. First matching group destination — variables resolved against requesting user
    for (const groupId of userGroups) {
      const groupDest = await this.getGroupDestination(groupId);
      if (groupDest) return this._resolveVariables(groupDest, userId);
    }

    // 3. No destination found — caller uses default /var/scans/{userId}
    return null;
  }

  async listAll() {
    const result = await this.db.query(
      `SELECT * FROM scan_destinations ORDER BY entity_type, entity_id`
    );
    return result.rows.map(row => this._rowToDestination(row));
  }

  async deleteDestination(entityType, entityId) {
    const result = await this.db.query(
      `DELETE FROM scan_destinations WHERE entity_type = $1 AND entity_id = $2 RETURNING id`,
      [entityType, entityId]
    );
    return result.rowCount > 0;
  }

  buildSmbPath(dest) {
    const sharePath = dest.smbPath ? `/${dest.smbPath}` : '';
    return `//${dest.smbServer}/${dest.smbShare}${sharePath}`;
  }

  async writeToSmb(localFile, dest) {
    const filename = path.basename(localFile);
    const remotePath = dest.smbPath ? `${dest.smbPath}/${filename}` : filename;
    const share = `//${dest.smbServer}/${dest.smbShare}`;

    // Build auth string
    const domain = dest.smbDomain ? `${dest.smbDomain}\\` : '';
    const authStr = `${domain}${dest.smbUsername}%${dest.smbPassword}`;

    // Try smbclient first
    try {
      await this._execCommand(
        `smbclient '${share}' -U '${authStr}' -c "put '${localFile}' '${remotePath}'"`,
      );
      return;
    } catch (smbErr) {
      // smbclient failed — try mount.cifs fallback
      const mountPoint = `/tmp/smbmount-${uuidv4()}`;
      try {
        await fs.mkdir(mountPoint, { recursive: true });
        const mountOpts = [
          `user=${dest.smbUsername}`,
          `pass=${dest.smbPassword}`,
          dest.smbDomain ? `dom=${dest.smbDomain}` : null,
        ].filter(Boolean).join(',');

        await this._execCommand(`mount.cifs '${share}' '${mountPoint}' -o ${mountOpts}`);

        const destDir = dest.smbPath ? path.join(mountPoint, dest.smbPath) : mountPoint;
        await fs.mkdir(destDir, { recursive: true });
        await fs.copyFile(localFile, path.join(destDir, filename));

        await this._execCommand(`umount '${mountPoint}'`).catch(() => {});
        await fs.rmdir(mountPoint).catch(() => {});
        return;
      } catch (mountErr) {
        // Both methods failed — save locally with a warning
        await fs.rmdir(mountPoint).catch(() => {});
        const warningMsg = `SMB write failed (smbclient: ${smbErr.message}, mount.cifs: ${mountErr.message}). File kept locally at ${localFile}`;
        console.warn(warningMsg);
        // File remains at localFile; do not throw so the scan result is still returned
        return;
      }
    }
  }

  _execCommand(cmd) {
    return new Promise((resolve, reject) => {
      exec(cmd, (error, stdout, stderr) => {
        if (error) {
          reject(new Error(stderr || error.message));
        } else {
          resolve(stdout);
        }
      });
    });
  }
}

module.exports = ScanDestinationManager;
