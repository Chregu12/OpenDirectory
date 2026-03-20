'use strict';

const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const SYSVOL_BASE = process.env.SYSVOL_PATH || '/var/lib/samba/sysvol';
const DOMAIN = process.env.SAMBA_REALM ? process.env.SAMBA_REALM.toLowerCase() : 'opendirectory.local';

/**
 * Get the Policies directory path in SYSVOL.
 */
function getPoliciesPath() {
  return path.join(SYSVOL_BASE, DOMAIN, 'Policies');
}

/**
 * Generate a GPO GUID in standard format.
 */
function generateGPOGuid() {
  return `{${uuidv4().toUpperCase()}}`;
}

/**
 * Validate GPO ID format.
 */
function validateGpoId(gpoId) {
  if (!gpoId || typeof gpoId !== 'string') {
    throw new Error('GPO ID is required');
  }
  // Accept with or without braces
  const cleaned = gpoId.startsWith('{') ? gpoId : `{${gpoId}}`;
  if (!/^\{[A-F0-9-]{36}\}$/i.test(cleaned)) {
    throw new Error('Invalid GPO ID format. Must be a GUID.');
  }
  return cleaned;
}

/**
 * Create the standard GPO directory structure in SYSVOL.
 *
 * @param {string} name - GPO display name
 * @param {object} settings - Initial GPO settings
 * @returns {Promise<object>} Created GPO info
 */
async function createGPO(name, settings = {}) {
  if (!name || typeof name !== 'string') {
    throw new Error('GPO name is required');
  }

  if (!/^[a-zA-Z0-9._\s-]+$/.test(name)) {
    throw new Error('Invalid GPO name. Use alphanumeric characters, spaces, dots, underscores, and hyphens.');
  }

  const gpoId = generateGPOGuid();
  const gpoPath = path.join(getPoliciesPath(), gpoId);

  logger.info('Creating GPO', { name, gpoId });

  try {
    // Create GPO directory structure
    await fs.mkdir(path.join(gpoPath, 'Machine', 'Scripts', 'Startup'), { recursive: true });
    await fs.mkdir(path.join(gpoPath, 'Machine', 'Scripts', 'Shutdown'), { recursive: true });
    await fs.mkdir(path.join(gpoPath, 'Machine', 'Preferences'), { recursive: true });
    await fs.mkdir(path.join(gpoPath, 'User', 'Scripts', 'Logon'), { recursive: true });
    await fs.mkdir(path.join(gpoPath, 'User', 'Scripts', 'Logoff'), { recursive: true });
    await fs.mkdir(path.join(gpoPath, 'User', 'Preferences'), { recursive: true });

    // Create GPT.INI (GPO version tracking)
    const gptIni = [
      '[General]',
      `displayName=${name}`,
      'Version=0',
      ''
    ].join('\r\n');
    await fs.writeFile(path.join(gpoPath, 'GPT.INI'), gptIni, 'utf-8');

    // Create GPO metadata
    const metadata = {
      id: gpoId,
      name,
      displayName: name,
      version: 0,
      machineVersion: 0,
      userVersion: 0,
      settings: settings || {},
      flags: 0, // 0 = enabled for both user and machine
      createdAt: new Date().toISOString(),
      modifiedAt: new Date().toISOString()
    };

    await fs.writeFile(
      path.join(gpoPath, 'opendirectory-metadata.json'),
      JSON.stringify(metadata, null, 2),
      'utf-8'
    );

    // Write initial machine settings if provided
    if (settings.machine) {
      await fs.writeFile(
        path.join(gpoPath, 'Machine', 'registry.pol.json'),
        JSON.stringify(settings.machine, null, 2),
        'utf-8'
      );
    }

    // Write initial user settings if provided
    if (settings.user) {
      await fs.writeFile(
        path.join(gpoPath, 'User', 'registry.pol.json'),
        JSON.stringify(settings.user, null, 2),
        'utf-8'
      );
    }

    logger.info('GPO created successfully', { name, gpoId, path: gpoPath });

    return {
      id: gpoId,
      name,
      path: gpoPath,
      version: 0,
      createdAt: metadata.createdAt
    };
  } catch (err) {
    // Clean up on failure
    try {
      await fs.rm(gpoPath, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
    logger.error('Error creating GPO', { name, error: err.message });
    throw new Error(`Failed to create GPO: ${err.message}`);
  }
}

/**
 * Update GPO settings.
 *
 * @param {string} gpoId - GPO GUID
 * @param {object} settings - Updated settings
 * @returns {Promise<object>} Update result
 */
async function updateGPOSettings(gpoId, settings) {
  gpoId = validateGpoId(gpoId);
  if (!settings || typeof settings !== 'object') {
    throw new Error('Settings object is required');
  }

  const gpoPath = path.join(getPoliciesPath(), gpoId);

  try {
    // Verify GPO exists
    await fs.access(gpoPath);

    // Read current metadata
    const metadataPath = path.join(gpoPath, 'opendirectory-metadata.json');
    let metadata;
    try {
      const content = await fs.readFile(metadataPath, 'utf-8');
      metadata = JSON.parse(content);
    } catch {
      metadata = { id: gpoId, version: 0 };
    }

    // Update version
    metadata.version = (metadata.version || 0) + 1;
    metadata.settings = { ...metadata.settings, ...settings };
    metadata.modifiedAt = new Date().toISOString();

    // Update machine settings
    if (settings.machine) {
      metadata.machineVersion = (metadata.machineVersion || 0) + 1;
      await fs.writeFile(
        path.join(gpoPath, 'Machine', 'registry.pol.json'),
        JSON.stringify(settings.machine, null, 2),
        'utf-8'
      );
    }

    // Update user settings
    if (settings.user) {
      metadata.userVersion = (metadata.userVersion || 0) + 1;
      await fs.writeFile(
        path.join(gpoPath, 'User', 'registry.pol.json'),
        JSON.stringify(settings.user, null, 2),
        'utf-8'
      );
    }

    // Write updated metadata
    await fs.writeFile(metadataPath, JSON.stringify(metadata, null, 2), 'utf-8');

    // Update GPT.INI version
    const combinedVersion = ((metadata.userVersion || 0) << 16) + (metadata.machineVersion || 0);
    const gptIni = [
      '[General]',
      `displayName=${metadata.name || metadata.displayName || gpoId}`,
      `Version=${combinedVersion}`,
      ''
    ].join('\r\n');
    await fs.writeFile(path.join(gpoPath, 'GPT.INI'), gptIni, 'utf-8');

    logger.info('GPO settings updated', { gpoId, version: metadata.version });

    return {
      id: gpoId,
      version: metadata.version,
      machineVersion: metadata.machineVersion,
      userVersion: metadata.userVersion,
      modifiedAt: metadata.modifiedAt
    };
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(`GPO not found: ${gpoId}`);
    }
    logger.error('Error updating GPO settings', { gpoId, error: err.message });
    throw new Error(`Failed to update GPO settings: ${err.message}`);
  }
}

/**
 * Delete a GPO from SYSVOL.
 *
 * @param {string} gpoId - GPO GUID
 * @returns {Promise<object>} Deletion result
 */
async function deleteGPO(gpoId) {
  gpoId = validateGpoId(gpoId);
  const gpoPath = path.join(getPoliciesPath(), gpoId);

  try {
    // Verify GPO exists
    await fs.access(gpoPath);

    // Read metadata before deletion for logging
    let name = gpoId;
    try {
      const content = await fs.readFile(path.join(gpoPath, 'opendirectory-metadata.json'), 'utf-8');
      name = JSON.parse(content).name || gpoId;
    } catch {
      // Use ID as name
    }

    // Remove GPO directory tree
    await fs.rm(gpoPath, { recursive: true, force: true });

    logger.info('GPO deleted', { gpoId, name });

    return {
      success: true,
      id: gpoId,
      name,
      deletedAt: new Date().toISOString()
    };
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(`GPO not found: ${gpoId}`);
    }
    logger.error('Error deleting GPO', { gpoId, error: err.message });
    throw new Error(`Failed to delete GPO: ${err.message}`);
  }
}

/**
 * List all GPOs in SYSVOL.
 *
 * @returns {Promise<object>} List of GPOs
 */
async function listGPOs() {
  const policiesPath = getPoliciesPath();

  try {
    let entries;
    try {
      entries = await fs.readdir(policiesPath, { withFileTypes: true });
    } catch (err) {
      if (err.code === 'ENOENT') {
        return { gpos: [], total: 0, sysvolPath: policiesPath };
      }
      throw err;
    }

    const gpos = [];

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;

      // GPO directories are GUIDs wrapped in braces
      if (!/^\{[A-F0-9-]{36}\}$/i.test(entry.name)) continue;

      const gpoPath = path.join(policiesPath, entry.name);
      const gpo = { id: entry.name, path: gpoPath };

      // Read metadata
      try {
        const metadataContent = await fs.readFile(
          path.join(gpoPath, 'opendirectory-metadata.json'), 'utf-8'
        );
        const metadata = JSON.parse(metadataContent);
        gpo.name = metadata.name || metadata.displayName;
        gpo.version = metadata.version;
        gpo.flags = metadata.flags;
        gpo.createdAt = metadata.createdAt;
        gpo.modifiedAt = metadata.modifiedAt;
      } catch {
        // Try GPT.INI fallback
        try {
          const gptIni = await fs.readFile(path.join(gpoPath, 'GPT.INI'), 'utf-8');
          const nameMatch = gptIni.match(/displayName=(.+)/);
          const versionMatch = gptIni.match(/Version=(\d+)/);
          if (nameMatch) gpo.name = nameMatch[1].trim();
          if (versionMatch) gpo.version = parseInt(versionMatch[1], 10);
        } catch {
          gpo.name = entry.name;
        }
      }

      gpos.push(gpo);
    }

    return {
      gpos,
      total: gpos.length,
      sysvolPath: policiesPath,
      retrievedAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error listing GPOs', { error: err.message });
    throw new Error(`Failed to list GPOs: ${err.message}`);
  }
}

/**
 * Get detailed GPO settings.
 *
 * @param {string} gpoId - GPO GUID
 * @returns {Promise<object>} GPO settings
 */
async function getGPOSettings(gpoId) {
  gpoId = validateGpoId(gpoId);
  const gpoPath = path.join(getPoliciesPath(), gpoId);

  try {
    await fs.access(gpoPath);

    const result = { id: gpoId, path: gpoPath };

    // Read metadata
    try {
      const content = await fs.readFile(path.join(gpoPath, 'opendirectory-metadata.json'), 'utf-8');
      Object.assign(result, JSON.parse(content));
    } catch {
      // Try GPT.INI
      try {
        const gptIni = await fs.readFile(path.join(gpoPath, 'GPT.INI'), 'utf-8');
        const nameMatch = gptIni.match(/displayName=(.+)/);
        const versionMatch = gptIni.match(/Version=(\d+)/);
        if (nameMatch) result.name = nameMatch[1].trim();
        if (versionMatch) result.version = parseInt(versionMatch[1], 10);
      } catch {
        // Minimal info
      }
    }

    // Read machine settings
    try {
      const machineSettings = await fs.readFile(
        path.join(gpoPath, 'Machine', 'registry.pol.json'), 'utf-8'
      );
      result.machineSettings = JSON.parse(machineSettings);
    } catch {
      result.machineSettings = null;
    }

    // Read user settings
    try {
      const userSettings = await fs.readFile(
        path.join(gpoPath, 'User', 'registry.pol.json'), 'utf-8'
      );
      result.userSettings = JSON.parse(userSettings);
    } catch {
      result.userSettings = null;
    }

    // List scripts
    const scripts = { machine: { startup: [], shutdown: [] }, user: { logon: [], logoff: [] } };

    for (const [section, dirs] of Object.entries({
      machine: { startup: 'Machine/Scripts/Startup', shutdown: 'Machine/Scripts/Shutdown' },
      user: { logon: 'User/Scripts/Logon', logoff: 'User/Scripts/Logoff' }
    })) {
      for (const [event, dir] of Object.entries(dirs)) {
        try {
          const files = await fs.readdir(path.join(gpoPath, dir));
          scripts[section][event] = files;
        } catch {
          // Directory may not exist
        }
      }
    }

    result.scripts = scripts;
    result.retrievedAt = new Date().toISOString();

    return result;
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(`GPO not found: ${gpoId}`);
    }
    logger.error('Error reading GPO settings', { gpoId, error: err.message });
    throw new Error(`Failed to read GPO settings: ${err.message}`);
  }
}

/**
 * Backup a GPO to a target directory.
 *
 * @param {string} gpoId - GPO GUID
 * @param {string} backupDir - Backup target directory (optional)
 * @returns {Promise<object>} Backup result
 */
async function backupGPO(gpoId, backupDir) {
  gpoId = validateGpoId(gpoId);
  const gpoPath = path.join(getPoliciesPath(), gpoId);

  try {
    await fs.access(gpoPath);

    const backupId = uuidv4();
    const targetDir = backupDir || path.join('/var/backups/samba/gpo', backupId);
    await fs.mkdir(targetDir, { recursive: true });

    // Copy GPO recursively
    await copyDir(gpoPath, path.join(targetDir, gpoId));

    // Write backup manifest
    const manifest = {
      backupId,
      gpoId,
      backedUpAt: new Date().toISOString(),
      sourcePath: gpoPath,
      backupPath: targetDir
    };

    await fs.writeFile(
      path.join(targetDir, 'backup-manifest.json'),
      JSON.stringify(manifest, null, 2),
      'utf-8'
    );

    logger.info('GPO backed up', { gpoId, backupId, targetDir });

    return manifest;
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(`GPO not found: ${gpoId}`);
    }
    logger.error('Error backing up GPO', { gpoId, error: err.message });
    throw new Error(`Failed to backup GPO: ${err.message}`);
  }
}

/**
 * Restore a GPO from a backup.
 *
 * @param {string} backupPath - Path to backup directory
 * @returns {Promise<object>} Restore result
 */
async function restoreGPO(backupPath) {
  if (!backupPath) throw new Error('Backup path is required');

  try {
    // Read manifest
    const manifestContent = await fs.readFile(
      path.join(backupPath, 'backup-manifest.json'), 'utf-8'
    );
    const manifest = JSON.parse(manifestContent);

    const gpoId = manifest.gpoId;
    const sourcePath = path.join(backupPath, gpoId);
    const targetPath = path.join(getPoliciesPath(), gpoId);

    // Check if GPO already exists
    try {
      await fs.access(targetPath);
      // Backup existing before overwrite
      const existingBackup = path.join('/var/backups/samba/gpo', `pre-restore-${Date.now()}`);
      await fs.mkdir(existingBackup, { recursive: true });
      await copyDir(targetPath, path.join(existingBackup, gpoId));
      await fs.rm(targetPath, { recursive: true, force: true });
    } catch {
      // GPO doesn't exist, nothing to backup
    }

    // Copy from backup
    await copyDir(sourcePath, targetPath);

    logger.info('GPO restored', { gpoId, backupPath });

    return {
      success: true,
      gpoId,
      restoredFrom: backupPath,
      restoredAt: new Date().toISOString()
    };
  } catch (err) {
    logger.error('Error restoring GPO', { backupPath, error: err.message });
    throw new Error(`Failed to restore GPO: ${err.message}`);
  }
}

/**
 * Recursively copy a directory.
 */
async function copyDir(src, dest) {
  await fs.mkdir(dest, { recursive: true });
  const entries = await fs.readdir(src, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      await copyDir(srcPath, destPath);
    } else {
      await fs.copyFile(srcPath, destPath);
    }
  }
}

module.exports = {
  createGPO,
  updateGPOSettings,
  deleteGPO,
  listGPOs,
  getGPOSettings,
  backupGPO,
  restoreGPO
};
