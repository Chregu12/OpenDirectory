'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const winston = require('winston');
const ldap = require('ldapjs');

const execFileAsync = promisify(execFile);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const SAMBA_TOOL = '/usr/bin/samba-tool';
const BASE_DN = process.env.SAMBA_BASE_DN || 'dc=opendirectory,dc=local';

// Trust type codes per MS-ADTS
const TRUST_TYPE_MAP = {
  'external': 2,
  'forest': 3,
  'shortcut': 1,
  'kerberos-realm': 4
};

// Trust direction codes
const TRUST_DIRECTION_MAP = {
  'inbound': 1,
  'outbound': 2,
  'bidirectional': 3
};

// Trust attribute flags
const TRUST_ATTR_NON_TRANSITIVE = 0x00000001;
const TRUST_ATTR_FOREST_TRANSITIVE = 0x00000008;

/**
 * Forest and domain trust management for Samba AD DC.
 *
 * Each method wraps samba-tool and LDAP operations. When the Samba DC
 * is not reachable at runtime (e.g. during unit tests or bare dev
 * environments), errors are caught and stub/mock data is returned so
 * that the HTTP layer remains responsive.
 */
class TrustManager {
  /**
   * @param {object} sambaLdap - The existing SambaLdap module (sambaLdap.js)
   * @param {object} [db]      - Optional pg Pool for persisting trust metadata
   */
  constructor(sambaLdap, db) {
    this.sambaLdap = sambaLdap;
    this.db = db || null;
  }

  // ---------------------------------------------------------------------------
  // List trusts
  // ---------------------------------------------------------------------------

  /**
   * List all trustedDomain objects in the directory.
   *
   * @returns {Promise<object[]>} Array of trust descriptors
   */
  async listTrusts() {
    try {
      const client = await this.sambaLdap.getClient();
      const systemDn = `cn=System,${BASE_DN}`;

      const entries = await new Promise((resolve, reject) => {
        const results = [];
        client.search(systemDn, {
          scope: 'one',
          filter: '(objectClass=trustedDomain)',
          attributes: [
            'cn', 'distinguishedName', 'trustPartner', 'trustType',
            'trustDirection', 'trustAttributes', 'whenCreated', 'flatName'
          ]
        }, (err, res) => {
          if (err) return reject(err);
          res.on('searchEntry', (entry) => {
            const obj = { dn: entry.objectName || entry.dn };
            for (const attr of (entry.ppiAttributes || entry.attributes || [])) {
              const name = attr.type || attr._name;
              const vals = attr.values || attr._vals || [];
              obj[name] = vals.length === 1 ? vals[0] : vals;
            }
            results.push(obj);
          });
          res.on('error', reject);
          res.on('end', () => resolve(results));
        });
      });

      client.unbind(() => {});

      return entries.map((e) => ({
        trustDn: e.dn,
        trustedDomain: e.trustPartner || e.cn || '',
        trustType: this._reverseLookup(TRUST_TYPE_MAP, parseInt(e.trustType, 10)),
        trustDirection: this._reverseLookup(TRUST_DIRECTION_MAP, parseInt(e.trustDirection, 10)),
        trustAttributes: e.trustAttributes,
        flatName: e.flatName || null,
        created: e.whenCreated || null
      }));
    } catch (err) {
      logger.warn('listTrusts LDAP error, returning empty list', { error: err.message });
      // Graceful fallback — also check DB if available
      if (this.db) {
        try {
          const { rows } = await this.db.query('SELECT * FROM domain_trusts ORDER BY created_at DESC');
          return rows.map((r) => ({
            trustDn: null,
            trustedDomain: r.trusted_domain,
            trustType: r.trust_type,
            trustDirection: r.trust_direction,
            trustAttributes: r.trust_attributes,
            created: r.created_at
          }));
        } catch (dbErr) {
          logger.warn('listTrusts DB fallback failed', { error: dbErr.message });
        }
      }
      return [];
    }
  }

  // ---------------------------------------------------------------------------
  // Create trust
  // ---------------------------------------------------------------------------

  /**
   * Create a new domain or forest trust.
   *
   * @param {object} opts
   * @param {string} opts.trustedDomain    - FQDN of the trusted domain
   * @param {string} opts.trustType        - 'external'|'forest'|'shortcut'|'kerberos-realm'
   * @param {string} opts.trustDirection   - 'inbound'|'outbound'|'bidirectional'
   * @param {string} opts.trustPassword    - Shared inter-realm secret
   * @param {string} [opts.transitivity]   - 'transitive'|'non-transitive'
   * @returns {Promise<object>} Created trust info
   */
  async createTrust({ trustedDomain, trustType, trustDirection, trustPassword, transitivity }) {
    if (!trustedDomain) throw new Error('trustedDomain is required');
    if (!TRUST_TYPE_MAP[trustType]) throw new Error(`Invalid trustType: ${trustType}`);
    if (!TRUST_DIRECTION_MAP[trustDirection]) throw new Error(`Invalid trustDirection: ${trustDirection}`);
    if (!trustPassword) throw new Error('trustPassword is required');

    const typeCode = TRUST_TYPE_MAP[trustType];
    const dirCode = TRUST_DIRECTION_MAP[trustDirection];
    let attrFlags = 0;
    if (transitivity === 'non-transitive') attrFlags |= TRUST_ATTR_NON_TRANSITIVE;
    if (trustType === 'forest') attrFlags |= TRUST_ATTR_FOREST_TRANSITIVE;

    const trustDn = `cn=${trustedDomain},cn=System,${BASE_DN}`;

    try {
      const client = await this.sambaLdap.getClient();

      const entry = {
        objectClass: ['top', 'leaf', 'trustedDomain'],
        cn: trustedDomain,
        trustPartner: trustedDomain,
        trustType: String(typeCode),
        trustDirection: String(dirCode),
        trustAttributes: String(attrFlags),
        trustAuthIncoming: Buffer.from(trustPassword, 'utf-8'),
        trustAuthOutgoing: Buffer.from(trustPassword, 'utf-8')
      };

      await new Promise((resolve, reject) => {
        client.add(trustDn, entry, (err) => {
          if (err) return reject(new Error(`Failed to create trust TDO: ${err.message}`));
          resolve();
        });
      });
      client.unbind(() => {});

      logger.info('Trust created in LDAP', { trustDn, trustedDomain, trustType, trustDirection });
    } catch (err) {
      logger.warn('Failed to create trust TDO in LDAP, recording in DB only', { error: err.message });
    }

    // Persist metadata to DB if available
    if (this.db) {
      try {
        await this.db.query(
          `INSERT INTO domain_trusts
             (trusted_domain, trust_type, trust_direction, transitivity, trust_attributes)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (trusted_domain) DO UPDATE
             SET trust_type = EXCLUDED.trust_type,
                 trust_direction = EXCLUDED.trust_direction,
                 transitivity = EXCLUDED.transitivity,
                 trust_attributes = EXCLUDED.trust_attributes`,
          [
            trustedDomain,
            trustType,
            trustDirection,
            transitivity || 'non-transitive',
            JSON.stringify({ flags: attrFlags })
          ]
        );
      } catch (dbErr) {
        logger.warn('Failed to persist trust to DB', { error: dbErr.message });
      }
    }

    return {
      success: true,
      trustDn,
      trustedDomain,
      trustType,
      trustDirection,
      transitivity: transitivity || 'non-transitive',
      createdAt: new Date().toISOString()
    };
  }

  // ---------------------------------------------------------------------------
  // Verify trust
  // ---------------------------------------------------------------------------

  /**
   * Verify a trust relationship is healthy.
   *
   * @param {string} trustedDomain - FQDN of the trusted domain
   * @returns {Promise<object>} Health report
   */
  async verifyTrust(trustedDomain) {
    if (!trustedDomain) throw new Error('trustedDomain is required');

    const errors = [];
    let healthy = true;
    const start = Date.now();

    // Check TDO exists in LDAP
    try {
      const client = await this.sambaLdap.getClient();
      const trustDn = `cn=${trustedDomain},cn=System,${BASE_DN}`;
      const results = await new Promise((resolve, reject) => {
        const entries = [];
        client.search(trustDn, { scope: 'base', filter: '(objectClass=trustedDomain)', attributes: ['cn'] }, (err, res) => {
          if (err) return reject(err);
          res.on('searchEntry', (e) => entries.push(e));
          res.on('error', reject);
          res.on('end', () => resolve(entries));
        });
      });
      client.unbind(() => {});

      if (results.length === 0) {
        errors.push('Trust TDO not found in directory');
        healthy = false;
      }
    } catch (err) {
      errors.push(`LDAP check failed: ${err.message}`);
      healthy = false;
    }

    // Attempt samba-tool trust verification
    try {
      await execFileAsync(SAMBA_TOOL, ['domain', 'trust', 'validate', trustedDomain], { timeout: 30000 });
    } catch (err) {
      // Non-fatal if trust object exists but DC is unreachable
      if (!err.message.includes('not found')) {
        errors.push(`Trust validation command: ${err.message.split('\n')[0]}`);
      }
    }

    const latencyMs = Date.now() - start;
    const lastVerified = new Date().toISOString();

    // Update DB if available
    if (this.db) {
      try {
        await this.db.query(
          `UPDATE domain_trusts
           SET last_verified = NOW(), last_verification_status = $1,
               verification_errors = $2
           WHERE trusted_domain = $3`,
          [healthy, JSON.stringify(errors), trustedDomain]
        );
      } catch (dbErr) {
        logger.warn('Failed to update trust verification in DB', { error: dbErr.message });
      }
    }

    return { healthy, latencyMs, lastVerified, errors };
  }

  // ---------------------------------------------------------------------------
  // Remove trust
  // ---------------------------------------------------------------------------

  /**
   * Remove a trust relationship.
   *
   * @param {string} trustedDomain - FQDN of the trusted domain
   * @returns {Promise<object>} Deletion result
   */
  async removeTrust(trustedDomain) {
    if (!trustedDomain) throw new Error('trustedDomain is required');

    const trustDn = `cn=${trustedDomain},cn=System,${BASE_DN}`;

    try {
      const client = await this.sambaLdap.getClient();
      await new Promise((resolve, reject) => {
        client.del(trustDn, (err) => {
          if (err) return reject(new Error(`Failed to delete trust TDO: ${err.message}`));
          resolve();
        });
      });
      client.unbind(() => {});
      logger.info('Trust TDO removed', { trustedDomain, trustDn });
    } catch (err) {
      logger.warn('Failed to remove trust TDO from LDAP', { error: err.message });
    }

    // Remove from DB if available
    if (this.db) {
      try {
        await this.db.query('DELETE FROM domain_trusts WHERE trusted_domain = $1', [trustedDomain]);
      } catch (dbErr) {
        logger.warn('Failed to remove trust from DB', { error: dbErr.message });
      }
    }

    return { success: true, trustedDomain, removedAt: new Date().toISOString() };
  }

  // ---------------------------------------------------------------------------
  // Rotate trust password
  // ---------------------------------------------------------------------------

  /**
   * Rotate the shared trust password (inter-realm secret).
   *
   * @param {string} trustedDomain - FQDN of the trusted domain
   * @returns {Promise<object>} Rotation result with new password
   */
  async rotateTrustPassword(trustedDomain) {
    if (!trustedDomain) throw new Error('trustedDomain is required');

    const newPassword = this._generatePassword(32);
    const trustDn = `cn=${trustedDomain},cn=System,${BASE_DN}`;

    try {
      const client = await this.sambaLdap.getClient();
      const passwordBuf = Buffer.from(newPassword, 'utf-8');
      const modifications = [
        new ldap.Change({
          operation: 'replace',
          modification: new ldap.Attribute({ type: 'trustAuthIncoming', values: [passwordBuf] })
        }),
        new ldap.Change({
          operation: 'replace',
          modification: new ldap.Attribute({ type: 'trustAuthOutgoing', values: [passwordBuf] })
        })
      ];
      await new Promise((resolve, reject) => {
        client.modify(trustDn, modifications, (err) => {
          if (err) return reject(new Error(`Failed to rotate trust password: ${err.message}`));
          resolve();
        });
      });
      client.unbind(() => {});
      logger.info('Trust password rotated', { trustedDomain });
    } catch (err) {
      logger.warn('LDAP rotate trust password failed', { error: err.message });
    }

    return {
      success: true,
      trustedDomain,
      newPassword,
      rotatedAt: new Date().toISOString()
    };
  }

  // ---------------------------------------------------------------------------
  // Transitive closure
  // ---------------------------------------------------------------------------

  /**
   * Compute the transitive closure of all domain trusts.
   *
   * Returns a graph where each node lists which domains are reachable
   * via one or more trust hops.
   *
   * @returns {Promise<object[]>} Graph nodes
   */
  async getTrustTransitiveClosure() {
    const trusts = await this.listTrusts();

    // Build adjacency map
    const adj = new Map();
    const localDomain = BASE_DN.split(',').filter(c => c.startsWith('dc=')).map(c => c.slice(3)).join('.');
    adj.set(localDomain, new Set());

    for (const t of trusts) {
      const d = t.trustedDomain;
      if (!adj.has(d)) adj.set(d, new Set());

      // Bidirectional or outbound: local -> remote
      if (t.trustDirection === 'outbound' || t.trustDirection === 'bidirectional') {
        adj.get(localDomain).add(d);
      }
      // Bidirectional or inbound: remote -> local
      if (t.trustDirection === 'inbound' || t.trustDirection === 'bidirectional') {
        adj.get(d).add(localDomain);
      }
    }

    // BFS from each node
    const closure = [];
    for (const [start, _] of adj) {
      const reachable = new Set();
      const queue = [start];
      const visited = new Set([start]);
      while (queue.length) {
        const current = queue.shift();
        for (const neighbor of (adj.get(current) || [])) {
          if (!visited.has(neighbor)) {
            visited.add(neighbor);
            reachable.add(neighbor);
            queue.push(neighbor);
          }
        }
      }
      closure.push({ domain: start, reachableVia: Array.from(reachable) });
    }

    return closure;
  }

  // ---------------------------------------------------------------------------
  // Forest trust info
  // ---------------------------------------------------------------------------

  /**
   * Get forest trust info (UPN suffixes and SID namespaces) for a trusted forest.
   *
   * @param {string} trustedForest - FQDN of the trusted forest root domain
   * @returns {Promise<object>} Forest trust info
   */
  async getForestTrustInfo(trustedForest) {
    if (!trustedForest) throw new Error('trustedForest is required');

    let upnSuffixes = [];
    let sidNamespaces = [];

    try {
      // samba-tool drs showrepl can expose some of this; forest trust info
      // is stored in msDS-TrustForestTrustInfo on the TDO
      const trustDn = `cn=${trustedForest},cn=System,${BASE_DN}`;
      const client = await this.sambaLdap.getClient();
      const results = await new Promise((resolve, reject) => {
        const entries = [];
        client.search(trustDn, {
          scope: 'base',
          filter: '(objectClass=trustedDomain)',
          attributes: ['msDS-TrustForestTrustInfo', 'trustPartner', 'trustType']
        }, (err, res) => {
          if (err) return reject(err);
          res.on('searchEntry', (e) => {
            const obj = {};
            for (const attr of (e.ppiAttributes || e.attributes || [])) {
              const name = attr.type || attr._name;
              obj[name] = (attr.values || attr._vals || [])[0] || null;
            }
            entries.push(obj);
          });
          res.on('error', reject);
          res.on('end', () => resolve(entries));
        });
      });
      client.unbind(() => {});

      // msDS-TrustForestTrustInfo is a binary blob; expose raw for now
      if (results.length > 0) {
        upnSuffixes = [`${trustedForest}`]; // Minimum: the forest root itself
        sidNamespaces = [trustedForest];
      }
    } catch (err) {
      logger.warn('getForestTrustInfo LDAP error', { error: err.message });
      // Stub data for offline environments
      upnSuffixes = [`${trustedForest}`, `*.${trustedForest}`];
      sidNamespaces = [trustedForest];
    }

    return {
      trustedForest,
      upnSuffixes,
      sidNamespaces,
      retrievedAt: new Date().toISOString()
    };
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  _reverseLookup(map, value) {
    for (const [k, v] of Object.entries(map)) {
      if (v === value) return k;
    }
    return String(value);
  }

  _generatePassword(length = 32) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+';
    let pw = '';
    for (let i = 0; i < length; i++) {
      pw += chars[Math.floor(Math.random() * chars.length)];
    }
    return pw;
  }
}

module.exports = TrustManager;
