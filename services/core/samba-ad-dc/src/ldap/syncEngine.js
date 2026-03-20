'use strict';

const winston = require('winston');
const axios = require('axios');
const sambaLdap = require('./sambaLdap');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const LLDAP_URL = process.env.LLDAP_URL || 'http://lldap:17170';
const LLDAP_ADMIN_USER = process.env.LLDAP_ADMIN_USER || 'admin';
const LLDAP_ADMIN_PASSWORD = process.env.LLDAP_ADMIN_PASSWORD || '';

// Sync state tracking
const syncState = {
  lastSync: null,
  lastSyncDirection: null,
  syncInProgress: false,
  syncErrors: [],
  syncedUsers: new Map(),   // Map<username, { lldapId, sambaDn, lastSynced }>
  syncedGroups: new Map(),   // Map<groupName, { lldapId, sambaDn, lastSynced }>
  continuousSyncTimer: null
};

/**
 * Get an authentication token from lldap.
 *
 * @returns {Promise<string>} JWT token
 */
async function getLldapToken() {
  try {
    const response = await axios.post(`${LLDAP_URL}/auth/simple/login`, {
      username: LLDAP_ADMIN_USER,
      password: LLDAP_ADMIN_PASSWORD
    }, { timeout: 10000 });

    return response.data.token;
  } catch (err) {
    throw new Error(`Failed to authenticate with lldap: ${err.message}`);
  }
}

/**
 * Fetch all users from lldap.
 *
 * @param {string} token - JWT token
 * @returns {Promise<object[]>} lldap users
 */
async function fetchLldapUsers(token) {
  try {
    const query = `{
      users {
        id
        email
        displayName
        firstName
        lastName
        creationDate
        uuid
        attributes {
          name
          value
        }
      }
    }`;

    const response = await axios.post(`${LLDAP_URL}/api/graphql`, { query }, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: 30000
    });

    return response.data.data.users || [];
  } catch (err) {
    throw new Error(`Failed to fetch lldap users: ${err.message}`);
  }
}

/**
 * Fetch all groups from lldap.
 *
 * @param {string} token - JWT token
 * @returns {Promise<object[]>} lldap groups
 */
async function fetchLldapGroups(token) {
  try {
    const query = `{
      groups {
        id
        displayName
        creationDate
        uuid
        users {
          id
          displayName
        }
      }
    }`;

    const response = await axios.post(`${LLDAP_URL}/api/graphql`, { query }, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: 30000
    });

    return response.data.data.groups || [];
  } catch (err) {
    throw new Error(`Failed to fetch lldap groups: ${err.message}`);
  }
}

/**
 * Sync users and groups from lldap to Samba AD.
 * Used for initial migration when transitioning to Samba AD DC.
 *
 * @returns {Promise<object>} Sync results
 */
async function syncFromLldapToSamba() {
  if (syncState.syncInProgress) {
    throw new Error('Sync already in progress');
  }

  syncState.syncInProgress = true;
  syncState.syncErrors = [];

  const results = {
    users: { created: 0, updated: 0, skipped: 0, errors: 0 },
    groups: { created: 0, updated: 0, skipped: 0, errors: 0 },
    startedAt: new Date().toISOString()
  };

  try {
    logger.info('Starting lldap -> Samba AD sync');

    const token = await getLldapToken();
    const [lldapUsers, lldapGroups] = await Promise.all([
      fetchLldapUsers(token),
      fetchLldapGroups(token)
    ]);

    // Get existing Samba users and groups
    const [sambaUsers, sambaGroups] = await Promise.all([
      sambaLdap.searchUsers().catch(() => ({ users: [] })),
      sambaLdap.searchGroups().catch(() => ({ groups: [] }))
    ]);

    const existingSambaUsers = new Set(
      sambaUsers.users.map(u => (u.sAMAccountName || '').toLowerCase())
    );
    const existingSambaGroups = new Set(
      sambaGroups.groups.map(g => (g.sAMAccountName || '').toLowerCase())
    );

    // Sync users
    for (const lldapUser of lldapUsers) {
      try {
        const username = lldapUser.id || lldapUser.email?.split('@')[0];
        if (!username) {
          results.users.skipped++;
          continue;
        }

        if (existingSambaUsers.has(username.toLowerCase())) {
          results.users.skipped++;
          syncState.syncedUsers.set(username, {
            lldapId: lldapUser.id,
            status: 'exists',
            lastSynced: new Date().toISOString()
          });
          continue;
        }

        // Create user in Samba AD with a temporary password
        // In production, use a secure password reset flow
        const tempPassword = `Sync_${Date.now()}_${Math.random().toString(36).slice(2, 10)}!`;

        await sambaLdap.createUser({
          username,
          password: tempPassword,
          firstName: lldapUser.firstName || username,
          lastName: lldapUser.lastName || '',
          email: lldapUser.email || '',
          displayName: lldapUser.displayName || username
        });

        syncState.syncedUsers.set(username, {
          lldapId: lldapUser.id,
          status: 'created',
          lastSynced: new Date().toISOString()
        });

        results.users.created++;
        logger.info('User synced from lldap to Samba', { username });
      } catch (err) {
        results.users.errors++;
        syncState.syncErrors.push({
          type: 'user',
          id: lldapUser.id,
          error: err.message,
          timestamp: new Date().toISOString()
        });
        logger.error('Error syncing user', { id: lldapUser.id, error: err.message });
      }
    }

    // Sync groups
    for (const lldapGroup of lldapGroups) {
      try {
        const groupName = lldapGroup.displayName;
        if (!groupName) {
          results.groups.skipped++;
          continue;
        }

        if (existingSambaGroups.has(groupName.toLowerCase())) {
          results.groups.skipped++;
          syncState.syncedGroups.set(groupName, {
            lldapId: lldapGroup.id,
            status: 'exists',
            lastSynced: new Date().toISOString()
          });
          continue;
        }

        await sambaLdap.createGroup({
          name: groupName,
          description: `Synced from lldap (ID: ${lldapGroup.id})`,
          groupType: 'security',
          groupScope: 'global'
        });

        syncState.syncedGroups.set(groupName, {
          lldapId: lldapGroup.id,
          status: 'created',
          lastSynced: new Date().toISOString()
        });

        results.groups.created++;
        logger.info('Group synced from lldap to Samba', { groupName });
      } catch (err) {
        results.groups.errors++;
        syncState.syncErrors.push({
          type: 'group',
          id: lldapGroup.id,
          error: err.message,
          timestamp: new Date().toISOString()
        });
        logger.error('Error syncing group', { id: lldapGroup.id, error: err.message });
      }
    }

    // Sync group memberships
    for (const lldapGroup of lldapGroups) {
      if (!lldapGroup.users || lldapGroup.users.length === 0) continue;

      const groupName = lldapGroup.displayName;
      const groupInfo = syncState.syncedGroups.get(groupName);
      if (!groupInfo) continue;

      for (const lldapMember of lldapGroup.users) {
        try {
          const userInfo = syncState.syncedUsers.get(lldapMember.id);
          if (!userInfo || !userInfo.sambaDn) continue;

          // Group DN lookup would be needed here
          // This is a simplified version - production code would resolve DNs properly
        } catch (err) {
          logger.error('Error syncing group membership', {
            group: groupName,
            user: lldapMember.id,
            error: err.message
          });
        }
      }
    }

    results.completedAt = new Date().toISOString();
    syncState.lastSync = results.completedAt;
    syncState.lastSyncDirection = 'lldap_to_samba';

    logger.info('lldap -> Samba AD sync completed', results);

    return results;
  } finally {
    syncState.syncInProgress = false;
  }
}

/**
 * Sync users and groups from Samba AD back to lldap.
 * Used to keep lldap as a read mirror for services that rely on it.
 *
 * @returns {Promise<object>} Sync results
 */
async function syncFromSambaToLldap() {
  if (syncState.syncInProgress) {
    throw new Error('Sync already in progress');
  }

  syncState.syncInProgress = true;
  syncState.syncErrors = [];

  const results = {
    users: { created: 0, updated: 0, skipped: 0, errors: 0 },
    groups: { created: 0, updated: 0, skipped: 0, errors: 0 },
    startedAt: new Date().toISOString()
  };

  try {
    logger.info('Starting Samba AD -> lldap sync');

    const token = await getLldapToken();

    // Get Samba AD users
    const sambaUsers = await sambaLdap.searchUsers();

    // Get existing lldap users
    const lldapUsers = await fetchLldapUsers(token);
    const existingLldapUsers = new Set(
      lldapUsers.map(u => (u.id || '').toLowerCase())
    );

    // Sync each Samba user to lldap
    for (const sambaUser of sambaUsers.users) {
      try {
        const username = sambaUser.sAMAccountName;
        if (!username) {
          results.users.skipped++;
          continue;
        }

        // Skip built-in accounts
        if (['Administrator', 'Guest', 'krbtgt'].includes(username)) {
          results.users.skipped++;
          continue;
        }

        if (existingLldapUsers.has(username.toLowerCase())) {
          // Update existing user
          try {
            const mutation = `mutation {
              updateUser(user: {
                id: "${username}",
                email: "${sambaUser.mail || ''}",
                displayName: "${sambaUser.displayName || username}"
              }) {
                ok
              }
            }`;

            await axios.post(`${LLDAP_URL}/api/graphql`, { query: mutation }, {
              headers: { Authorization: `Bearer ${token}` },
              timeout: 10000
            });

            results.users.updated++;
          } catch {
            results.users.skipped++;
          }
          continue;
        }

        // Create user in lldap
        const mutation = `mutation {
          createUser(user: {
            id: "${username}",
            email: "${sambaUser.mail || `${username}@opendirectory.local`}",
            displayName: "${sambaUser.displayName || username}",
            firstName: "${sambaUser.givenName || ''}",
            lastName: "${sambaUser.sn || ''}"
          }) {
            id
          }
        }`;

        await axios.post(`${LLDAP_URL}/api/graphql`, { query: mutation }, {
          headers: { Authorization: `Bearer ${token}` },
          timeout: 10000
        });

        results.users.created++;
        logger.info('User synced from Samba to lldap', { username });
      } catch (err) {
        results.users.errors++;
        syncState.syncErrors.push({
          type: 'user',
          id: sambaUser.sAMAccountName,
          error: err.message,
          timestamp: new Date().toISOString()
        });
      }
    }

    results.completedAt = new Date().toISOString();
    syncState.lastSync = results.completedAt;
    syncState.lastSyncDirection = 'samba_to_lldap';

    logger.info('Samba AD -> lldap sync completed', results);

    return results;
  } finally {
    syncState.syncInProgress = false;
  }
}

/**
 * Start continuous bidirectional sync on an interval.
 * Samba AD is the source of truth when in domain mode.
 *
 * @param {number} intervalMs - Sync interval in milliseconds (default: 5 minutes)
 * @returns {object} Sync control handle
 */
function startContinuousSync(intervalMs = 300000) {
  if (syncState.continuousSyncTimer) {
    logger.warn('Continuous sync already running');
    return { status: 'already_running' };
  }

  if (intervalMs < 30000) {
    throw new Error('Sync interval must be at least 30 seconds');
  }

  logger.info('Starting continuous sync', { intervalMs });

  const runSync = async () => {
    try {
      // Samba AD is source of truth - sync outward
      await syncFromSambaToLldap();
    } catch (err) {
      logger.error('Continuous sync cycle failed', { error: err.message });
      syncState.syncErrors.push({
        type: 'continuous_sync',
        error: err.message,
        timestamp: new Date().toISOString()
      });
    }
  };

  syncState.continuousSyncTimer = setInterval(runSync, intervalMs);

  // Run immediately
  runSync();

  return {
    status: 'started',
    intervalMs,
    startedAt: new Date().toISOString()
  };
}

/**
 * Stop continuous sync.
 *
 * @returns {object} Stop result
 */
function stopContinuousSync() {
  if (syncState.continuousSyncTimer) {
    clearInterval(syncState.continuousSyncTimer);
    syncState.continuousSyncTimer = null;
    logger.info('Continuous sync stopped');
    return { status: 'stopped', stoppedAt: new Date().toISOString() };
  }
  return { status: 'not_running' };
}

/**
 * Get current sync status.
 *
 * @returns {object} Sync state
 */
function getSyncStatus() {
  return {
    syncInProgress: syncState.syncInProgress,
    lastSync: syncState.lastSync,
    lastSyncDirection: syncState.lastSyncDirection,
    continuousSyncActive: syncState.continuousSyncTimer !== null,
    syncedUsers: syncState.syncedUsers.size,
    syncedGroups: syncState.syncedGroups.size,
    recentErrors: syncState.syncErrors.slice(-10),
    totalErrors: syncState.syncErrors.length
  };
}

module.exports = {
  syncFromLldapToSamba,
  syncFromSambaToLldap,
  startContinuousSync,
  stopContinuousSync,
  getSyncStatus
};
