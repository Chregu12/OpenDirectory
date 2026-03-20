'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const winston = require('winston');
const sambaLdap = require('../ldap/sambaLdap');

const execFileAsync = promisify(execFile);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const SAMBA_TOOL = '/usr/bin/samba-tool';

/**
 * Validate a GPO ID (GUID format).
 */
function validateGpoId(gpoId) {
  if (!gpoId || typeof gpoId !== 'string') {
    throw new Error('GPO ID is required');
  }
  const cleaned = gpoId.startsWith('{') ? gpoId : `{${gpoId}}`;
  if (!/^\{[A-F0-9-]{36}\}$/i.test(cleaned)) {
    throw new Error('Invalid GPO ID format');
  }
  return cleaned;
}

/**
 * Validate a Distinguished Name.
 */
function validateDn(dn) {
  if (!dn || typeof dn !== 'string') {
    throw new Error('Distinguished Name is required');
  }
  if (!/^(ou|dc|cn)=/i.test(dn)) {
    throw new Error('Invalid DN format');
  }
}

/**
 * Link a GPO to an OU, Domain, or Site.
 *
 * @param {string} gpoId - GPO GUID
 * @param {string} targetDn - Target DN to link to (OU, Domain, or Site)
 * @param {boolean} enforced - Whether the link is enforced
 * @param {boolean} disabled - Whether the link is disabled
 * @returns {Promise<object>} Link result
 */
async function linkGPO(gpoId, targetDn, enforced = false, disabled = false) {
  gpoId = validateGpoId(gpoId);
  validateDn(targetDn);

  logger.info('Linking GPO', { gpoId, targetDn, enforced, disabled });

  try {
    // Build the gPLink attribute value
    // Format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;OPTIONS]
    // Options: 0 = enabled/not enforced, 1 = disabled, 2 = enforced, 3 = disabled+enforced
    let options = 0;
    if (disabled) options |= 1;
    if (enforced) options |= 2;

    // Use samba-tool to link GPO
    const args = ['gpo', 'setlink', targetDn, gpoId];

    const { stdout } = await execFileAsync(SAMBA_TOOL, args, { timeout: 30000 });

    // If enforced or disabled, update the link options
    if (enforced || disabled) {
      await updateLinkOptions(gpoId, targetDn, options);
    }

    logger.info('GPO linked successfully', { gpoId, targetDn });

    return {
      success: true,
      gpoId,
      targetDn,
      enforced,
      disabled,
      linkedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error linking GPO', { gpoId, targetDn, error: err.message });
    throw new Error(`Failed to link GPO: ${err.message}`);
  }
}

/**
 * Update link options (enforced/disabled) via LDAP.
 */
async function updateLinkOptions(gpoId, targetDn, options) {
  const client = await sambaLdap.getClient();

  try {
    // Read current gPLink value
    const ldap = require('ldapjs');
    const searchResults = await new Promise((resolve, reject) => {
      const entries = [];
      client.search(targetDn, {
        scope: 'base',
        filter: '(objectClass=*)',
        attributes: ['gPLink']
      }, (err, res) => {
        if (err) return reject(err);
        res.on('searchEntry', (entry) => entries.push(entry));
        res.on('error', reject);
        res.on('end', () => resolve(entries));
      });
    });

    if (searchResults.length === 0) return;

    const entry = searchResults[0];
    let gpLink = '';
    if (entry.ppiAttributes || entry.attributes) {
      const attrs = entry.ppiAttributes || entry.attributes;
      for (const attr of attrs) {
        if ((attr.type || attr._name) === 'gPLink') {
          gpLink = (attr.values || attr._vals || [])[0] || '';
        }
      }
    }

    // Update options for the specific GPO in the gPLink string
    const gpoPattern = new RegExp(
      `(\\[LDAP://[^;]*${gpoId.replace(/[{}]/g, '\\$&')}[^;]*;)\\d+(\\])`,
      'i'
    );

    if (gpoPattern.test(gpLink)) {
      gpLink = gpLink.replace(gpoPattern, `$1${options}$2`);

      const change = new ldap.Change({
        operation: 'replace',
        modification: new ldap.Attribute({
          type: 'gPLink',
          values: [gpLink]
        })
      });

      await new Promise((resolve, reject) => {
        client.modify(targetDn, change, (err) => {
          if (err) return reject(err);
          resolve();
        });
      });
    }
  } finally {
    client.unbind(() => {});
  }
}

/**
 * Unlink a GPO from a target.
 *
 * @param {string} gpoId - GPO GUID
 * @param {string} targetDn - Target DN to unlink from
 * @returns {Promise<object>} Unlink result
 */
async function unlinkGPO(gpoId, targetDn) {
  gpoId = validateGpoId(gpoId);
  validateDn(targetDn);

  logger.info('Unlinking GPO', { gpoId, targetDn });

  try {
    const args = ['gpo', 'dellink', targetDn, gpoId];

    const { stdout } = await execFileAsync(SAMBA_TOOL, args, { timeout: 30000 });

    logger.info('GPO unlinked successfully', { gpoId, targetDn });

    return {
      success: true,
      gpoId,
      targetDn,
      unlinkedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error unlinking GPO', { gpoId, targetDn, error: err.message });
    throw new Error(`Failed to unlink GPO: ${err.message}`);
  }
}

/**
 * Get GPOs linked to a specific target (OU, Domain, or Site).
 *
 * @param {string} targetDn - Target DN
 * @returns {Promise<object>} Linked GPOs
 */
async function getLinkedGPOs(targetDn) {
  validateDn(targetDn);

  try {
    const client = await sambaLdap.getClient();

    const results = await new Promise((resolve, reject) => {
      const entries = [];
      client.search(targetDn, {
        scope: 'base',
        filter: '(objectClass=*)',
        attributes: ['gPLink', 'gPOptions']
      }, (err, res) => {
        if (err) return reject(err);
        res.on('searchEntry', (entry) => entries.push(entry));
        res.on('error', reject);
        res.on('end', () => resolve(entries));
      });
    });

    client.unbind(() => {});

    if (results.length === 0) {
      return { linkedGPOs: [], targetDn, total: 0 };
    }

    const entry = results[0];
    let gpLink = '';
    let gpOptions = 0;

    if (entry.ppiAttributes || entry.attributes) {
      const attrs = entry.ppiAttributes || entry.attributes;
      for (const attr of attrs) {
        const name = attr.type || attr._name;
        const values = attr.values || attr._vals || [];
        if (name === 'gPLink') gpLink = values[0] || '';
        if (name === 'gPOptions') gpOptions = parseInt(values[0] || '0', 10);
      }
    }

    // Parse gPLink: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;OPTIONS][...]
    const linkedGPOs = [];
    const linkPattern = /\[LDAP:\/\/([^;]+);(\d+)\]/gi;
    let match;
    let order = 0;

    while ((match = linkPattern.exec(gpLink)) !== null) {
      const dn = match[1];
      const options = parseInt(match[2], 10);

      const guidMatch = dn.match(/\{[A-F0-9-]{36}\}/i);
      const gpoId = guidMatch ? guidMatch[0] : null;

      linkedGPOs.push({
        gpoId,
        gpoDn: dn,
        options,
        enforced: (options & 2) !== 0,
        disabled: (options & 1) !== 0,
        order: order++
      });
    }

    return {
      linkedGPOs,
      targetDn,
      total: linkedGPOs.length,
      blockInheritance: (gpOptions & 1) !== 0,
      retrievedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error getting linked GPOs', { targetDn, error: err.message });
    throw new Error(`Failed to get linked GPOs: ${err.message}`);
  }
}

/**
 * Set the processing order of GPOs linked to a target.
 *
 * @param {string} targetDn - Target DN
 * @param {string[]} gpoIds - Ordered array of GPO GUIDs (first = lowest priority)
 * @returns {Promise<object>} Reorder result
 */
async function setLinkOrder(targetDn, gpoIds) {
  validateDn(targetDn);

  if (!Array.isArray(gpoIds) || gpoIds.length === 0) {
    throw new Error('GPO IDs array is required');
  }

  logger.info('Setting GPO link order', { targetDn, gpoIds });

  try {
    // Get current links to preserve options
    const current = await getLinkedGPOs(targetDn);
    const currentMap = new Map(current.linkedGPOs.map(l => [l.gpoId, l]));

    // Build new gPLink string in specified order
    const baseDn = process.env.SAMBA_BASE_DN || 'dc=opendirectory,dc=local';
    let newGpLink = '';

    for (const gpoId of gpoIds) {
      const cleaned = validateGpoId(gpoId);
      const existing = currentMap.get(cleaned);
      const options = existing ? existing.options : 0;
      const dn = `cn=${cleaned},cn=policies,cn=system,${baseDn}`;
      newGpLink += `[LDAP://${dn};${options}]`;
    }

    // Update via LDAP
    const ldap = require('ldapjs');
    const client = await sambaLdap.getClient();

    const change = new ldap.Change({
      operation: 'replace',
      modification: new ldap.Attribute({
        type: 'gPLink',
        values: [newGpLink]
      })
    });

    await new Promise((resolve, reject) => {
      client.modify(targetDn, change, (err) => {
        if (err) return reject(err);
        resolve();
      });
    });

    client.unbind(() => {});

    logger.info('GPO link order updated', { targetDn });

    return {
      success: true,
      targetDn,
      order: gpoIds,
      updatedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error setting link order', { targetDn, error: err.message });
    throw new Error(`Failed to set GPO link order: ${err.message}`);
  }
}

/**
 * Set the enforced flag on a GPO link.
 *
 * @param {string} gpoId - GPO GUID
 * @param {string} targetDn - Target DN
 * @param {boolean} enforced - Whether to enforce
 * @returns {Promise<object>} Update result
 */
async function setEnforced(gpoId, targetDn, enforced) {
  gpoId = validateGpoId(gpoId);
  validateDn(targetDn);

  logger.info('Setting GPO enforced flag', { gpoId, targetDn, enforced });

  try {
    const current = await getLinkedGPOs(targetDn);
    const link = current.linkedGPOs.find(l => l.gpoId === gpoId);

    if (!link) {
      throw new Error(`GPO ${gpoId} is not linked to ${targetDn}`);
    }

    let options = link.options;
    if (enforced) {
      options |= 2;
    } else {
      options &= ~2;
    }

    await updateLinkOptions(gpoId, targetDn, options);

    logger.info('GPO enforced flag updated', { gpoId, targetDn, enforced });

    return {
      success: true,
      gpoId,
      targetDn,
      enforced,
      updatedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error setting enforced flag', { gpoId, targetDn, error: err.message });
    throw new Error(`Failed to set enforced flag: ${err.message}`);
  }
}

module.exports = {
  linkGPO,
  unlinkGPO,
  getLinkedGPOs,
  setLinkOrder,
  setEnforced
};
