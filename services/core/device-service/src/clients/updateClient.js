'use strict';

/**
 * HTTP client for the update-management service.
 * Replaces the direct file import of UpdateAgentService.
 *
 * All methods return null on network failure so callers can respond with 503.
 */

const BASE = process.env.UPDATE_SERVICE_URL || 'http://update-management:3010';
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
      console.error(`[updateClient] ${method} ${path} -> HTTP ${res.status}`);
      return null;
    }
    return await res.json();
  } catch (err) {
    console.error(`[updateClient] ${method} ${path} failed:`, err.message);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Configure update policy for a device.
 * Maps to: UpdateAgentService.configureUpdates(deviceId, policy)
 */
async function configureUpdates(deviceId, policy) {
  return _request('POST', '/api/agent/update/configure', { deviceId, policy });
}

/**
 * Check the update status for a device.
 * Maps to: UpdateAgentService.checkUpdateStatus(deviceId)
 */
async function checkUpdateStatus(deviceId) {
  return _request('POST', '/api/agent/update/check-status', { deviceId });
}

/**
 * Trigger an update on a device.
 * Maps to: UpdateAgentService.triggerUpdate(deviceId, options)
 */
async function triggerUpdate(deviceId, options) {
  return _request('POST', '/api/agent/update/trigger', { deviceId, options });
}

/**
 * Get the update status for a specific device.
 * Maps to: UpdateAgentService.getDeviceUpdateStatus(deviceId)
 */
async function getDeviceUpdateStatus(deviceId) {
  return _request('GET', `/api/agent/update/status/${encodeURIComponent(deviceId)}`);
}

/**
 * Configure Winget auto-update policy for a device.
 * Maps to: UpdateAgentService.configureWingetAutoUpdate(deviceId, policy)
 */
async function configureWingetAutoUpdate(deviceId, policy) {
  return _request('POST', '/api/agent/update/configure-winget', { deviceId, policy });
}

/**
 * Forward a command result to the update service.
 * Maps to: UpdateAgentService.handleCommandResult(deviceId, data)
 */
async function handleCommandResult(deviceId, data) {
  return _request('POST', '/api/agent/update/command-result', { deviceId, data });
}

module.exports = {
  configureUpdates,
  checkUpdateStatus,
  triggerUpdate,
  getDeviceUpdateStatus,
  configureWingetAutoUpdate,
  handleCommandResult
};
