'use strict';

/**
 * HTTP client for the license-management service.
 * Replaces the direct file import of DashboardService from license-management.
 *
 * All methods return null on network failure so callers can respond with 503.
 */

const BASE = process.env.LICENSE_SERVICE_URL || 'http://license-management:3018';
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
      console.error(`[licenseClient] ${method} ${path} -> HTTP ${res.status}`);
      return null;
    }
    return await res.json();
  } catch (err) {
    console.error(`[licenseClient] ${method} ${path} failed:`, err.message);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Retrieve aggregated dashboard data.
 * Maps to: DashboardService.getDashboardData()
 */
async function getDashboardData() {
  return _request('GET', '/api/dashboard');
}

/**
 * Retrieve time-series data for a given metric and timeframe.
 * Maps to: DashboardService.getTimeSeries(metric, timeframe)
 */
async function getTimeSeries(metric, timeframe) {
  const params = new URLSearchParams({ timeframe });
  return _request('GET', `/api/dashboard/timeseries/${encodeURIComponent(metric)}?${params}`);
}

/**
 * Retrieve available report templates.
 * Maps to: DashboardService.getReportTemplates()
 */
async function getReportTemplates() {
  return _request('GET', '/api/reports/templates');
}

/**
 * Generate a report with the given template, format, and params.
 * Maps to: DashboardService.generateReport(template, format, params)
 */
async function generateReport(template, format, params) {
  return _request('POST', '/api/reports/generate', { template, format, params });
}

module.exports = {
  getDashboardData,
  getTimeSeries,
  getReportTemplates,
  generateReport
};
