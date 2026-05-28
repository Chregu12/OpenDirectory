'use strict';

/**
 * HTTP client for the backup/disaster-recovery service.
 * Replaces direct file imports of BackupManagementSystem, FailoverController,
 * DisasterRecoveryOrchestrator, and GeoReplicationEngine from the enterprise
 * disaster-recovery package.
 *
 * All methods return null on network failure so callers can respond with 503.
 */

const BASE = process.env.BACKUP_SERVICE_URL || 'http://backup-service:3011';
const TIMEOUT_MS = 5000;

async function _request(method, path, body) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const opts = {
      method,
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json' }
    };
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res = await fetch(`${BASE}${path}`, opts);
    if (!res.ok) {
      console.error(`[backupClient] ${method} ${path} -> HTTP ${res.status}`);
      return null;
    }
    return await res.json();
  } catch (err) {
    console.error(`[backupClient] ${method} ${path} failed:`, err.message);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Trigger a backup job.
 * Replaces: backupSystem.emit('backup:trigger', { type, jobId })
 * @param {string} type   - e.g. 'incremental' | 'full'
 * @param {string} jobId  - caller-generated job identifier
 */
async function triggerBackup(type, jobId) {
  return _request('POST', '/api/backup/trigger', { type, jobId });
}

/**
 * Get current backup status.
 * Replaces: reading from backupSystem state.
 */
async function getBackupStatus() {
  return _request('GET', '/api/backup/status');
}

/**
 * Get backup history.
 * @param {number} limit - max records to return
 */
async function getBackupHistory(limit) {
  const params = limit ? `?limit=${limit}` : '';
  return _request('GET', `/api/backup/history${params}`);
}

/**
 * Initiate a restore from a specific backup.
 * @param {string} backupId
 */
async function restoreBackup(backupId) {
  return _request('POST', '/api/backup/restore', { backupId });
}

/**
 * Get the DR / failover health status.
 * Replaces: checking this.drOrchestrator, this.failoverController, etc.
 */
async function getDrHealth() {
  return _request('GET', '/api/dr/health');
}

/**
 * Run a DR failover drill (test).
 * Replaces: using this.failoverController.
 */
async function testFailover() {
  return _request('POST', '/api/dr/failover/test', {});
}

/**
 * Execute a real failover (requires explicit confirmation).
 * @param {boolean} confirm - must be true
 */
async function executeFailover(confirm) {
  return _request('POST', '/api/dr/failover/execute', { confirm });
}

/**
 * Get geo-replication status.
 * Replaces: reading from this.geoReplication.
 */
async function getReplicationStatus() {
  return _request('GET', '/api/dr/replication/status');
}

module.exports = {
  triggerBackup,
  getBackupStatus,
  getBackupHistory,
  restoreBackup,
  getDrHealth,
  testFailover,
  executeFailover,
  getReplicationStatus
};
