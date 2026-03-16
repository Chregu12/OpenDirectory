'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;
const winston = require('winston');

const execFileAsync = promisify(execFile);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const SAMBA_TOOL = '/usr/bin/samba-tool';

/**
 * Get overall DC status including process state, SYSVOL health, and DNS status.
 *
 * @returns {Promise<object>} DC status
 */
async function getDCStatus() {
  const checks = {};

  // Check Samba process
  try {
    await execFileAsync('/usr/bin/pgrep', ['-x', 'samba'], { timeout: 5000 });
    checks.sambaProcess = { status: 'running' };
  } catch {
    checks.sambaProcess = { status: 'stopped' };
  }

  // Check LDAP connectivity
  try {
    const { stdout } = await execFileAsync(SAMBA_TOOL, ['ldapcmp', '--help'], { timeout: 10000 }).catch(() => ({ stdout: '' }));
    // Alternative: just test with a basic search
    await execFileAsync(SAMBA_TOOL, ['domain', 'level', 'show'], { timeout: 10000 });
    checks.ldap = { status: 'connected' };
  } catch {
    checks.ldap = { status: 'disconnected' };
  }

  // Check SYSVOL
  try {
    const sysvolPath = '/var/lib/samba/sysvol';
    const stats = await fs.stat(sysvolPath);
    checks.sysvol = {
      status: stats.isDirectory() ? 'available' : 'error',
      path: sysvolPath
    };
  } catch {
    checks.sysvol = { status: 'unavailable' };
  }

  // Check DNS
  try {
    await execFileAsync('/usr/bin/nslookup', ['localhost', '127.0.0.1'], { timeout: 10000 });
    checks.dns = { status: 'operational' };
  } catch {
    checks.dns = { status: 'degraded' };
  }

  // Check Kerberos
  try {
    await fs.access('/etc/krb5.conf');
    checks.kerberos = { status: 'configured' };
  } catch {
    checks.kerberos = { status: 'not_configured' };
  }

  const allHealthy = Object.values(checks).every(c => !['stopped', 'disconnected', 'unavailable', 'not_configured'].includes(c.status));

  return {
    healthy: allHealthy,
    checks,
    timestamp: new Date().toISOString()
  };
}

/**
 * Get FSMO role holders.
 *
 * @returns {Promise<object>} FSMO roles
 */
async function getFSMORoles() {
  try {
    const { stdout } = await execFileAsync(SAMBA_TOOL, ['fsmo', 'show'], { timeout: 30000 });
    const roles = {};
    const roleMap = {
      'SchemaMasterRole': 'schema',
      'InfrastructureMasterRole': 'infrastructure',
      'RidAllocationMasterRole': 'rid',
      'PdcEmulationMasterRole': 'pdc',
      'DomainNamingMasterRole': 'naming',
      'DomainDnsZonesMasterRole': 'domainDnsZones',
      'ForestDnsZonesMasterRole': 'forestDnsZones'
    };

    const lines = stdout.split('\n').filter(l => l.includes('owner:'));
    for (const line of lines) {
      const parts = line.split(' owner: ');
      if (parts.length === 2) {
        const roleName = parts[0].trim();
        const holder = parts[1].trim();
        const mappedName = roleMap[roleName] || roleName;
        roles[mappedName] = {
          holder,
          dn: holder
        };
      }
    }

    return {
      roles,
      totalRoles: Object.keys(roles).length,
      retrievedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error retrieving FSMO roles', { error: err.message });
    throw new Error(`Failed to get FSMO roles: ${err.message}`);
  }
}

/**
 * Transfer an FSMO role to a target DC.
 *
 * @param {string} role - Role to transfer (schema, rid, pdc, naming, infrastructure)
 * @param {string} targetDC - Target DC hostname or DN
 * @returns {Promise<object>} Transfer result
 */
async function transferFSMORole(role, targetDC) {
  const validRoles = ['schema', 'rid', 'pdc', 'naming', 'infrastructure', 'all'];
  if (!validRoles.includes(role)) {
    throw new Error(`Invalid FSMO role: ${role}. Must be one of: ${validRoles.join(', ')}`);
  }

  if (!targetDC || typeof targetDC !== 'string') {
    throw new Error('Target DC must be specified');
  }

  logger.info('Transferring FSMO role', { role, targetDC });

  try {
    const args = ['fsmo', 'transfer', `--role=${role}`];

    const { stdout, stderr } = await execFileAsync(SAMBA_TOOL, args, {
      timeout: 60000,
      env: { ...process.env }
    });

    logger.info('FSMO role transferred', { role, targetDC });

    return {
      success: true,
      role,
      targetDC,
      output: stdout,
      warnings: stderr || null,
      transferredAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('FSMO transfer failed', { role, targetDC, error: err.message });
    throw new Error(`Failed to transfer FSMO role ${role}: ${err.message}`);
  }
}

/**
 * Get replication status for the DC.
 *
 * @returns {Promise<object>} Replication health info
 */
async function getReplicationStatus() {
  try {
    const { stdout } = await execFileAsync(SAMBA_TOOL, ['drs', 'showrepl'], { timeout: 30000 });

    const partitions = [];
    const sections = stdout.split(/={10,}/);

    for (const section of sections) {
      const ncMatch = section.match(/Naming Context:\s*(.+)/);
      if (ncMatch) {
        const partition = {
          namingContext: ncMatch[1].trim()
        };

        const lastAttemptMatch = section.match(/Last attempt @\s*(.+)/);
        const lastSuccessMatch = section.match(/Last success @\s*(.+)/);
        const statusMatch = section.match(/result:\s*(\d+)\s*\((.+)\)/);

        if (lastAttemptMatch) partition.lastAttempt = lastAttemptMatch[1].trim();
        if (lastSuccessMatch) partition.lastSuccess = lastSuccessMatch[1].trim();
        if (statusMatch) {
          partition.resultCode = parseInt(statusMatch[1], 10);
          partition.resultText = statusMatch[2].trim();
        }

        partitions.push(partition);
      }
    }

    const healthy = partitions.length === 0 || partitions.every(p => p.resultCode === 0 || p.resultCode === undefined);

    return {
      healthy,
      partitions,
      partitionCount: partitions.length,
      retrievedAt: new Date().toISOString()
    };
  } catch (err) {
    // Single DC deployments may not have replication configured
    if (err.message.includes('no replication') || err.stderr?.includes('no replication')) {
      return {
        healthy: true,
        partitions: [],
        partitionCount: 0,
        message: 'Single DC deployment - no replication partners configured',
        retrievedAt: new Date().toISOString()
      };
    }
    logger.error('Error getting replication status', { error: err.message });
    throw new Error(`Failed to get replication status: ${err.message}`);
  }
}

/**
 * Get domain and forest functional levels.
 *
 * @returns {Promise<object>} Functional level info
 */
async function getDomainLevel() {
  try {
    const { stdout } = await execFileAsync(SAMBA_TOOL, ['domain', 'level', 'show'], { timeout: 30000 });

    const levels = {};
    const domainMatch = stdout.match(/Domain function level:\s*(.+)/);
    const forestMatch = stdout.match(/Forest function level:\s*(.+)/);
    const dcMatch = stdout.match(/Lowest function level of a DC:\s*(.+)/);

    if (domainMatch) levels.domain = domainMatch[1].trim();
    if (forestMatch) levels.forest = forestMatch[1].trim();
    if (dcMatch) levels.lowestDC = dcMatch[1].trim();

    return {
      levels,
      retrievedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error getting domain level', { error: err.message });
    throw new Error(`Failed to get domain level: ${err.message}`);
  }
}

module.exports = {
  getDCStatus,
  getFSMORoles,
  transferFSMORole,
  getReplicationStatus,
  getDomainLevel
};
