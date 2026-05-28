'use strict';

/**
 * HTTP client for the certificate-network service.
 * Replaces the direct file import of NetworkProfileAgentService.
 *
 * All methods return null on network failure so callers can respond with 503.
 */

const BASE = process.env.CERTIFICATE_NETWORK_URL || 'http://certificate-network:3015';
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
      console.error(`[networkProfileClient] ${method} ${path} -> HTTP ${res.status}`);
      return null;
    }
    return await res.json();
  } catch (err) {
    console.error(`[networkProfileClient] ${method} ${path} failed:`, err.message);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Configure a Wi-Fi profile on a device.
 * Maps to: NetworkProfileAgentService.configureWiFi(deviceId, profile)
 */
async function configureWiFi(deviceId, profile) {
  return _request('POST', '/api/agent/network/configure-wifi', { deviceId, profile });
}

/**
 * Remove a Wi-Fi profile from a device.
 * Maps to: NetworkProfileAgentService.removeWiFi(deviceId, profileId, ssid)
 */
async function removeWiFi(deviceId, profileId, ssid) {
  return _request('POST', '/api/agent/network/remove-wifi', { deviceId, profileId, ssid });
}

/**
 * Configure a VPN profile on a device.
 * Maps to: NetworkProfileAgentService.configureVPN(deviceId, profile)
 */
async function configureVPN(deviceId, profile) {
  return _request('POST', '/api/agent/network/configure-vpn', { deviceId, profile });
}

/**
 * Remove a VPN profile from a device.
 * Maps to: NetworkProfileAgentService.removeVPN(deviceId, profileId)
 */
async function removeVPN(deviceId, profileId) {
  return _request('POST', '/api/agent/network/remove-vpn', { deviceId, profileId });
}

/**
 * Configure an email profile on a device.
 * Maps to: NetworkProfileAgentService.configureEmail(deviceId, profile)
 */
async function configureEmail(deviceId, profile) {
  return _request('POST', '/api/agent/network/configure-email', { deviceId, profile });
}

/**
 * Remove an email profile from a device.
 * Maps to: NetworkProfileAgentService.removeEmail(deviceId, profileId)
 */
async function removeEmail(deviceId, profileId) {
  return _request('POST', '/api/agent/network/remove-email', { deviceId, profileId });
}

/**
 * Get the current network profile state for a device.
 * Maps to: NetworkProfileAgentService.getDeviceProfileState(deviceId)
 */
async function getDeviceProfileState(deviceId) {
  return _request('GET', `/api/agent/network/status/${encodeURIComponent(deviceId)}`);
}

/**
 * Forward a command result to the network profile service.
 * Maps to: NetworkProfileAgentService.handleCommandResult(deviceId, data)
 */
async function handleCommandResult(deviceId, data) {
  return _request('POST', '/api/agent/network/command-result', { deviceId, data });
}

module.exports = {
  configureWiFi,
  removeWiFi,
  configureVPN,
  removeVPN,
  configureEmail,
  removeEmail,
  getDeviceProfileState,
  handleCommandResult
};
