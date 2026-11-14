'use strict';
const PERMISSIONS = Object.freeze(['devices.compliance.read', 'devices.compliance.manage']);
const PLATFORMS = Object.freeze(['macos', 'windows', 'linux']);
const STATES = Object.freeze(['compliant', 'non-compliant', 'unknown', 'not-configured', 'pending', 'stale', 'historical']);
const DEFAULTS = Object.freeze({ enabled: false, maxReportAgeSeconds: 3600, minimumOsVersion: null, requireDiskEncryption: false, requireFirewall: false, minimumDiskFreePercent: null });
const VERSION = /^[0-9]{1,6}(?:\.[0-9]{1,6}){0,3}$/;
function fail(message = 'Exact compliance values required') { throw Object.assign(new Error(message), { status: 400 }); }
function exact(value, fields) {
 if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value)) || Object.keys(value).length !== fields.length || fields.some(field => !Object.hasOwn(value, field))) fail();
}
function version(value) { return typeof value === 'string' && VERSION.test(value) && !/\s/.test(value); }
function policy(value) {
 exact(value, Object.keys(DEFAULTS));
 if (typeof value.enabled !== 'boolean' || typeof value.requireDiskEncryption !== 'boolean' || typeof value.requireFirewall !== 'boolean'
  || !Number.isInteger(value.maxReportAgeSeconds) || value.maxReportAgeSeconds < 300 || value.maxReportAgeSeconds > 86400 || value.maxReportAgeSeconds % 60 !== 0
  || value.minimumOsVersion !== null && !version(value.minimumOsVersion)
  || value.minimumDiskFreePercent !== null && (!Number.isInteger(value.minimumDiskFreePercent) || value.minimumDiskFreePercent < 0 || value.minimumDiskFreePercent > 99)
  || value.enabled && !value.requireDiskEncryption && !value.requireFirewall && value.minimumOsVersion === null && value.minimumDiskFreePercent === null) fail();
 return value;
}
function security(value) {
 exact(value, ['schemaVersion', 'osVersion', 'diskEncryption', 'firewall']);
 if (value.schemaVersion !== 1 || value.osVersion !== null && !version(value.osVersion)) fail();
 for (const field of ['diskEncryption', 'firewall']) {
  exact(value[field], ['state', 'reason']); const entry = value[field];
  if (!['enabled', 'disabled', 'unknown'].includes(entry.state) || (entry.state === 'unknown' ? !['probe-failed', 'timeout', 'unrecognized', 'not-supported'].includes(entry.reason) : entry.reason !== 'checked')) fail();
 }
 return value;
}
function change(value) {
 exact(value, ['settings', 'reason', 'confirm']); policy(value.settings);
 if (value.confirm !== true || typeof value.reason !== 'string' || /[\u0000-\u001f\u007f-\u009f]/u.test(value.reason) || [...value.reason.trim()].length < 10 || [...value.reason.trim()].length > 500) fail('Confirmed compliance reason required');
 return { settings: value.settings, reason: value.reason.trim(), confirm: true };
}
function permissions(values) { return JSON.stringify(values) === JSON.stringify(PERMISSIONS) || JSON.stringify(values) === JSON.stringify(PERMISSIONS.slice(0, 1)); }
module.exports = { PERMISSIONS, PLATFORMS, STATES, DEFAULTS, version, policy, security, change, permissions };
