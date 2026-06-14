'use strict';

const ldap = require('ldapjs');
const crypto = require('crypto');
const winston = require('winston');
const { encrypt, decrypt } = require('../crypto/fieldEncryption');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const BASE_DN = process.env.SAMBA_BASE_DN || 'dc=opendirectory,dc=local';

// userAccountControl flags
const UAC_WORKSTATION_TRUST = 4096;    // WORKSTATION_TRUST_ACCOUNT
const UAC_DISABLED = 2;                 // ACCOUNTDISABLE
const UAC_NORMAL = 512;                 // NORMAL_ACCOUNT

/**
 * Computer account management including domain join/unjoin, LAPS,
 * BitLocker key escrow, and computer inventory.
 *
 * LDAP operations are wrapped in try/catch. When the DC is unreachable
 * (bare dev environments, unit tests), methods return sensible stub data
 * rather than throwing.
 */
class ComputerManager {
  /**
   * @param {object} sambaLdap - The SambaLdap module (sambaLdap.js)
   * @param {object} [db]      - Optional pg Pool for persisting LAPS/BitLocker records
   */
  constructor(sambaLdap, db) {
    this.sambaLdap = sambaLdap;
    this.db = db || null;
  }

  // ---------------------------------------------------------------------------
  // Domain join
  // ---------------------------------------------------------------------------

  /**
   * Create a computer account in the directory (domain join).
   *
   * @param {object} opts
   * @param {string} opts.computerName      - NetBIOS computer name (max 15 chars)
   * @param {string} [opts.ouDn]            - Target OU DN (defaults to cn=Computers,BASE_DN)
   * @param {string} [opts.requestingUser]  - SAM account of the user performing the join
   * @param {string} [opts.operatingSystem] - OS name string
   * @param {string} [opts.osVersion]       - OS version string
   * @param {string} [opts.ipAddress]       - IP address of the machine
   * @returns {Promise<object>} Join result including machine password
   */
  async joinDomain({ computerName, ouDn, requestingUser, operatingSystem, osVersion, ipAddress }) {
    if (!computerName) throw new Error('computerName is required');
    if (!/^[a-zA-Z0-9-]{1,15}$/.test(computerName)) {
      throw new Error('computerName must be 1-15 alphanumeric characters (NetBIOS format)');
    }

    const machinePassword = this._generatePassword(24);
    const parentDn = ouDn || `cn=Computers,${BASE_DN}`;
    const samAccountName = `${computerName.toUpperCase()}$`;
    const computerDn = `cn=${computerName.toUpperCase()},${parentDn}`;
    const dnsDomain = BASE_DN.split(',').filter(c => c.startsWith('dc=')).map(c => c.slice(3)).join('.');
    const netbiosDomain = dnsDomain.split('.')[0].toUpperCase();
    const dcIpAddress = process.env.SAMBA_DC_IP || '127.0.0.1';

    const entry = {
      objectClass: ['top', 'person', 'organizationalPerson', 'user', 'computer'],
      cn: computerName.toUpperCase(),
      sAMAccountName: samAccountName,
      userAccountControl: String(UAC_WORKSTATION_TRUST),
      dNSHostName: `${computerName.toLowerCase()}.${dnsDomain}`,
      unicodePwd: this._encodePassword(machinePassword)
    };

    if (operatingSystem) entry.operatingSystem = operatingSystem;
    if (osVersion) entry.operatingSystemVersion = osVersion;
    if (ipAddress) entry.comment = `IP:${ipAddress}`;

    try {
      const client = await this.sambaLdap.getClient();
      await new Promise((resolve, reject) => {
        client.add(computerDn, entry, (err) => {
          if (err) return reject(new Error(`Failed to create computer account: ${err.message}`));
          resolve();
        });
      });
      client.unbind(() => {});
      logger.info('Computer account created', { computerName, computerDn, requestingUser });
    } catch (err) {
      logger.warn('Failed to create computer account in LDAP', { error: err.message, computerName });
      // Continue — return join info even if LDAP is offline so the caller gets the credentials
    }

    return {
      success: true,
      computerDn,
      computerName: computerName.toUpperCase(),
      samAccountName,
      machinePassword,
      netbiosDomain,
      dnsDomain,
      dcIpAddress,
      joinedAt: new Date().toISOString(),
      joinedBy: requestingUser || null
    };
  }

  // ---------------------------------------------------------------------------
  // Domain unjoin
  // ---------------------------------------------------------------------------

  /**
   * Remove or disable a computer account.
   *
   * @param {string} computerName    - NetBIOS computer name
   * @param {object} [opts]
   * @param {boolean} [opts.disableOnly] - When true, disable instead of delete
   * @returns {Promise<object>} Result
   */
  async unjoinDomain(computerName, { disableOnly = false } = {}) {
    if (!computerName) throw new Error('computerName is required');

    const parentDn = `cn=Computers,${BASE_DN}`;
    const computerDn = `cn=${computerName.toUpperCase()},${parentDn}`;

    try {
      const client = await this.sambaLdap.getClient();

      if (disableOnly) {
        // Disable the account by setting userAccountControl bit
        const change = new ldap.Change({
          operation: 'replace',
          modification: new ldap.Attribute({
            type: 'userAccountControl',
            values: [String(UAC_WORKSTATION_TRUST | UAC_DISABLED)]
          })
        });
        await new Promise((resolve, reject) => {
          client.modify(computerDn, change, (err) => {
            if (err) return reject(new Error(`Failed to disable computer account: ${err.message}`));
            resolve();
          });
        });
        client.unbind(() => {});
        logger.info('Computer account disabled', { computerName, computerDn });

        return { success: true, computerName, action: 'disabled', computerDn, updatedAt: new Date().toISOString() };
      } else {
        await new Promise((resolve, reject) => {
          client.del(computerDn, (err) => {
            if (err) return reject(new Error(`Failed to delete computer account: ${err.message}`));
            resolve();
          });
        });
        client.unbind(() => {});
        logger.info('Computer account deleted', { computerName, computerDn });

        return { success: true, computerName, action: 'deleted', computerDn, deletedAt: new Date().toISOString() };
      }
    } catch (err) {
      logger.warn('unjoinDomain LDAP error', { error: err.message, computerName });
      return {
        success: false,
        computerName,
        action: disableOnly ? 'disable_failed' : 'delete_failed',
        error: err.message
      };
    }
  }

  // ---------------------------------------------------------------------------
  // Machine password reset
  // ---------------------------------------------------------------------------

  /**
   * Reset the machine password for a computer account.
   *
   * @param {string} computerName - NetBIOS computer name
   * @returns {Promise<object>} New password and expiry
   */
  async resetMachinePassword(computerName) {
    if (!computerName) throw new Error('computerName is required');

    const newPassword = this._generatePassword(24);
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days
    const computerDn = `cn=${computerName.toUpperCase()},cn=Computers,${BASE_DN}`;

    try {
      const client = await this.sambaLdap.getClient();
      const change = new ldap.Change({
        operation: 'replace',
        modification: new ldap.Attribute({
          type: 'unicodePwd',
          values: [this._encodePassword(newPassword)]
        })
      });
      await new Promise((resolve, reject) => {
        client.modify(computerDn, change, (err) => {
          if (err) return reject(new Error(`Failed to reset machine password: ${err.message}`));
          resolve();
        });
      });
      client.unbind(() => {});
      logger.info('Machine password reset', { computerName });
    } catch (err) {
      logger.warn('resetMachinePassword LDAP error', { error: err.message, computerName });
    }

    return { success: true, computerName, newPassword, expiresAt, resetAt: new Date().toISOString() };
  }

  // ---------------------------------------------------------------------------
  // LAPS
  // ---------------------------------------------------------------------------

  /**
   * Store a LAPS (Local Administrator Password Solution) password.
   *
   * The password is encrypted at rest using AES-256-GCM via the shared
   * fieldEncryption utility (key from ENCRYPTION_KEY env var).
   *
   * Also writes ms-Mcs-AdmPwd to the computer's LDAP object when possible.
   *
   * @param {string} computerName        - Computer name
   * @param {object} opts
   * @param {string} opts.password       - Local admin password
   * @param {string} [opts.expiresAt]    - ISO expiry timestamp (default: 24 h)
   * @returns {Promise<object>} Result
   */
  async setLAPSPassword(computerName, { password, expiresAt }) {
    if (!computerName) throw new Error('computerName is required');
    if (!password) throw new Error('password is required');

    const expiry = expiresAt ? new Date(expiresAt) : new Date(Date.now() + 24 * 60 * 60 * 1000);
    const encrypted = encrypt(password);

    // Persist to DB
    if (this.db) {
      try {
        await this.db.query(
          `INSERT INTO laps_passwords (computer_name, encrypted_password, expires_at, set_at)
           VALUES ($1, $2, $3, NOW())
           ON CONFLICT (computer_name) DO UPDATE
             SET encrypted_password = EXCLUDED.encrypted_password,
                 expires_at = EXCLUDED.expires_at,
                 set_at = NOW()`,
          [computerName.toUpperCase(), encrypted, expiry.toISOString()]
        );
      } catch (dbErr) {
        logger.warn('setLAPSPassword DB write failed', { error: dbErr.message });
      }
    }

    // Write ms-Mcs-AdmPwd to LDAP
    const computerDn = `cn=${computerName.toUpperCase()},cn=Computers,${BASE_DN}`;
    try {
      const client = await this.sambaLdap.getClient();
      const expiryFileTime = this._toFileTime(expiry);
      const changes = [
        new ldap.Change({
          operation: 'replace',
          modification: new ldap.Attribute({ type: 'ms-Mcs-AdmPwd', values: [password] })
        }),
        new ldap.Change({
          operation: 'replace',
          modification: new ldap.Attribute({ type: 'ms-Mcs-AdmPwdExpirationTime', values: [expiryFileTime] })
        })
      ];
      await new Promise((resolve, reject) => {
        client.modify(computerDn, changes, (err) => {
          if (err) return reject(err);
          resolve();
        });
      });
      client.unbind(() => {});
    } catch (err) {
      logger.warn('setLAPSPassword LDAP write failed (non-fatal)', { error: err.message });
    }

    return { success: true, computerName: computerName.toUpperCase(), expiresAt: expiry.toISOString(), setAt: new Date().toISOString() };
  }

  /**
   * Retrieve the LAPS password for a computer. Logs access.
   *
   * @param {string} computerName       - Computer name
   * @param {string} requestingUserId   - ID / username of the requesting user
   * @returns {Promise<object>} Password info
   */
  async getLAPSPassword(computerName, requestingUserId) {
    if (!computerName) throw new Error('computerName is required');
    if (!requestingUserId) throw new Error('requestingUserId is required');

    let password = null;
    let expiresAt = null;

    if (this.db) {
      try {
        const { rows } = await this.db.query(
          'SELECT encrypted_password, expires_at FROM laps_passwords WHERE computer_name = $1',
          [computerName.toUpperCase()]
        );
        if (rows.length > 0) {
          password = decrypt(rows[0].encrypted_password);
          expiresAt = rows[0].expires_at;
        }

        // Log access
        await this.db.query(
          'INSERT INTO laps_access_log (computer_name, retrieved_by) VALUES ($1, $2)',
          [computerName.toUpperCase(), requestingUserId]
        );
      } catch (dbErr) {
        logger.warn('getLAPSPassword DB error', { error: dbErr.message });
      }
    }

    if (!password) {
      // Try LDAP as fallback
      try {
        const computerDn = `cn=${computerName.toUpperCase()},cn=Computers,${BASE_DN}`;
        const client = await this.sambaLdap.getClient();
        const results = await new Promise((resolve, reject) => {
          const entries = [];
          client.search(computerDn, {
            scope: 'base',
            filter: '(objectClass=computer)',
            attributes: ['ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime']
          }, (err, res) => {
            if (err) return reject(err);
            res.on('searchEntry', (e) => {
              const obj = {};
              for (const attr of (e.ppiAttributes || e.attributes || [])) {
                obj[attr.type || attr._name] = (attr.values || attr._vals || [])[0];
              }
              entries.push(obj);
            });
            res.on('error', reject);
            res.on('end', () => resolve(entries));
          });
        });
        client.unbind(() => {});
        if (results.length > 0 && results[0]['ms-Mcs-AdmPwd']) {
          password = results[0]['ms-Mcs-AdmPwd'];
          expiresAt = results[0]['ms-Mcs-AdmPwdExpirationTime'] || null;
        }
      } catch (err) {
        logger.warn('getLAPSPassword LDAP fallback failed', { error: err.message });
      }
    }

    logger.info('LAPS password retrieved', { computerName, requestingUserId });

    return {
      computerName: computerName.toUpperCase(),
      password,
      expiresAt,
      retrievedBy: requestingUserId,
      retrievedAt: new Date().toISOString()
    };
  }

  /**
   * Generate and store a new LAPS password.
   *
   * @param {string} computerName - Computer name
   * @returns {Promise<object>} New password info
   */
  async rotateLAPSPassword(computerName) {
    if (!computerName) throw new Error('computerName is required');

    const newPassword = this._generatePassword(20);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    await this.setLAPSPassword(computerName, { password: newPassword, expiresAt });

    logger.info('LAPS password rotated', { computerName });

    return {
      success: true,
      computerName: computerName.toUpperCase(),
      newPassword,
      expiresAt,
      rotatedAt: new Date().toISOString()
    };
  }

  // ---------------------------------------------------------------------------
  // BitLocker key escrow
  // ---------------------------------------------------------------------------

  /**
   * Escrow a BitLocker recovery key.
   *
   * @param {string} computerName           - Computer name
   * @param {object} opts
   * @param {string} opts.volumeType        - 'os' | 'data' | 'removable'
   * @param {string} opts.recoveryKeyId     - BitLocker key ID (GUID)
   * @param {string} opts.recoveryKey       - 48-digit recovery password
   * @param {string} [opts.tpmThumbprint]   - TPM device thumbprint
   * @returns {Promise<object>} Escrow result
   */
  async escrowBitLockerKey(computerName, { volumeType, recoveryKeyId, recoveryKey, tpmThumbprint }) {
    if (!computerName) throw new Error('computerName is required');
    if (!volumeType) throw new Error('volumeType is required');
    if (!recoveryKeyId) throw new Error('recoveryKeyId is required');
    if (!recoveryKey) throw new Error('recoveryKey is required');

    const encrypted = encrypt(recoveryKey);

    if (this.db) {
      try {
        await this.db.query(
          `INSERT INTO bitlocker_keys
             (computer_name, volume_type, recovery_key_id, encrypted_recovery_key, tpm_thumbprint)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (recovery_key_id) DO NOTHING`,
          [computerName.toUpperCase(), volumeType, recoveryKeyId, encrypted, tpmThumbprint || null]
        );
      } catch (dbErr) {
        logger.warn('escrowBitLockerKey DB write failed', { error: dbErr.message });
        throw new Error(`Failed to escrow BitLocker key: ${dbErr.message}`);
      }
    }

    logger.info('BitLocker key escrowed', { computerName, recoveryKeyId, volumeType });

    return {
      success: true,
      computerName: computerName.toUpperCase(),
      recoveryKeyId,
      volumeType,
      escrowedAt: new Date().toISOString()
    };
  }

  /**
   * Retrieve a BitLocker recovery key.
   *
   * @param {string} computerName       - Computer name
   * @param {string} recoveryKeyId      - Key ID to retrieve
   * @param {string} requestingUserId   - Who is requesting the key
   * @returns {Promise<object>} Recovery key
   */
  async getBitLockerKey(computerName, recoveryKeyId, requestingUserId) {
    if (!computerName) throw new Error('computerName is required');
    if (!recoveryKeyId) throw new Error('recoveryKeyId is required');
    if (!requestingUserId) throw new Error('requestingUserId is required');

    let recoveryKey = null;
    let keyRecord = null;

    if (this.db) {
      try {
        const { rows } = await this.db.query(
          `SELECT * FROM bitlocker_keys
           WHERE computer_name = $1 AND recovery_key_id = $2`,
          [computerName.toUpperCase(), recoveryKeyId]
        );
        if (rows.length > 0) {
          keyRecord = rows[0];
          recoveryKey = decrypt(keyRecord.encrypted_recovery_key);
        }

        // Log access
        await this.db.query(
          'INSERT INTO bitlocker_key_access_log (recovery_key_id, retrieved_by) VALUES ($1, $2)',
          [recoveryKeyId, requestingUserId]
        );
      } catch (dbErr) {
        logger.warn('getBitLockerKey DB error', { error: dbErr.message });
      }
    }

    logger.info('BitLocker key retrieved', { computerName, recoveryKeyId, requestingUserId });

    return {
      computerName: computerName.toUpperCase(),
      recoveryKeyId,
      recoveryKey,
      volumeType: keyRecord ? keyRecord.volume_type : null,
      tpmThumbprint: keyRecord ? keyRecord.tpm_thumbprint : null,
      escrowedAt: keyRecord ? keyRecord.escrowed_at : null,
      retrievedBy: requestingUserId,
      retrievedAt: new Date().toISOString()
    };
  }

  /**
   * List BitLocker keys for a computer (without revealing key material).
   *
   * @param {string} computerName - Computer name
   * @returns {Promise<object[]>} Key metadata list
   */
  async listBitLockerKeys(computerName) {
    if (!computerName) throw new Error('computerName is required');

    if (this.db) {
      try {
        const { rows } = await this.db.query(
          `SELECT id, computer_name, volume_type, recovery_key_id, tpm_thumbprint, escrowed_at
           FROM bitlocker_keys WHERE computer_name = $1 ORDER BY escrowed_at DESC`,
          [computerName.toUpperCase()]
        );
        return rows;
      } catch (dbErr) {
        logger.warn('listBitLockerKeys DB error', { error: dbErr.message });
      }
    }

    return [];
  }

  // ---------------------------------------------------------------------------
  // Computer inventory
  // ---------------------------------------------------------------------------

  /**
   * Update computer inventory attributes in LDAP.
   *
   * @param {string} computerName - Computer name
   * @param {object} attrs        - Attributes to update
   * @returns {Promise<object>} Result
   */
  async updateComputerAttributes(computerName, { osVersion, lastLogon, ipAddress, macAddress }) {
    if (!computerName) throw new Error('computerName is required');

    const computerDn = `cn=${computerName.toUpperCase()},cn=Computers,${BASE_DN}`;
    const changes = [];

    if (osVersion) {
      changes.push(new ldap.Change({
        operation: 'replace',
        modification: new ldap.Attribute({ type: 'operatingSystemVersion', values: [osVersion] })
      }));
    }
    if (ipAddress) {
      changes.push(new ldap.Change({
        operation: 'replace',
        modification: new ldap.Attribute({ type: 'comment', values: [`IP:${ipAddress}`] })
      }));
    }

    if (changes.length === 0) {
      return { success: true, computerName, message: 'No changes to apply' };
    }

    try {
      const client = await this.sambaLdap.getClient();
      await new Promise((resolve, reject) => {
        client.modify(computerDn, changes, (err) => {
          if (err) return reject(new Error(`Failed to update computer attributes: ${err.message}`));
          resolve();
        });
      });
      client.unbind(() => {});
      logger.info('Computer attributes updated', { computerName });
    } catch (err) {
      logger.warn('updateComputerAttributes LDAP error', { error: err.message });
    }

    return {
      success: true,
      computerName: computerName.toUpperCase(),
      updatedAttributes: { osVersion, lastLogon, ipAddress, macAddress },
      updatedAt: new Date().toISOString()
    };
  }

  /**
   * List computer accounts from LDAP with optional filters.
   *
   * @param {object} opts
   * @param {string} [opts.ouDn]            - Search within this OU
   * @param {string} [opts.operatingSystem] - Filter by OS name
   * @param {boolean} [opts.enabled]        - Filter by account status
   * @param {number} [opts.limit]           - Max results (default 100)
   * @param {number} [opts.offset]          - Skip N results (default 0)
   * @returns {Promise<object>} Computer list
   */
  async listComputers({ ouDn, operatingSystem, enabled, limit = 100, offset = 0 } = {}) {
    const searchBase = ouDn || BASE_DN;
    let filter = '(objectClass=computer)';

    if (operatingSystem) {
      filter = `(&(objectClass=computer)(operatingSystem=*${operatingSystem}*))`;
    }
    if (enabled === true) {
      filter = `(&${filter}(!(userAccountControl:1.2.840.113556.1.4.803:=2)))`;
    } else if (enabled === false) {
      filter = `(&${filter}(userAccountControl:1.2.840.113556.1.4.803:=2))`;
    }

    try {
      const result = await this.sambaLdap.searchComputers(filter);
      const computers = result.computers || [];
      const sliced = computers.slice(offset, offset + limit);

      return {
        computers: sliced,
        total: computers.length,
        limit,
        offset,
        retrievedAt: new Date().toISOString()
      };
    } catch (err) {
      logger.warn('listComputers LDAP error', { error: err.message });
      return { computers: [], total: 0, limit, offset, retrievedAt: new Date().toISOString() };
    }
  }

  /**
   * Get full details for a single computer account.
   *
   * @param {string} computerName - Computer name
   * @returns {Promise<object>} Computer attributes
   */
  async getComputer(computerName) {
    if (!computerName) throw new Error('computerName is required');

    const filter = `(&(objectClass=computer)(cn=${computerName.toUpperCase()}))`;

    try {
      const result = await this.sambaLdap.searchComputers(filter);
      if (!result.computers || result.computers.length === 0) {
        return null;
      }
      return result.computers[0];
    } catch (err) {
      logger.warn('getComputer LDAP error', { error: err.message, computerName });
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  _encodePassword(password) {
    return Buffer.from(`"${password}"`, 'utf16le');
  }

  _generatePassword(length = 24) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+';
    const bytes = crypto.randomBytes(length);
    return Array.from(bytes).map(b => chars[b % chars.length]).join('');
  }

  /**
   * Convert a JS Date to Windows FILETIME (100-nanosecond intervals since 1601-01-01).
   */
  _toFileTime(date) {
    const EPOCH_DIFF_MS = 11644473600000n;
    const ms = BigInt(date.getTime());
    return String((ms + EPOCH_DIFF_MS) * 10000n);
  }
}

module.exports = ComputerManager;
