'use strict';

const DEVICE_FIELDS = Object.freeze([
  'assetId', 'serialNumber', 'manufacturer', 'model', 'deviceClass', 'platform',
  'osVersion', 'ownership', 'purchaseDate', 'warrantyEnd', 'description',
]);
const DEVICE_CLASSES = Object.freeze(['smartphone', 'tablet', 'laptop', 'desktop', 'shared', 'kiosk', 'other']);
const INVENTORY_PERMISSIONS = Object.freeze(['devices.inventory.read', 'devices.inventory.create', 'devices.inventory.assign']);
const PLATFORMS = ['macos', 'ios', 'ipados', 'windows', 'linux', 'android', 'other'];
const TEXT_FIELDS = { assetId: 120, serialNumber: 120, manufacturer: 120, model: 120, osVersion: 120, description: 2000 };
const DEFAULTS = { osVersion: '', ownership: 'corporate', purchaseDate: '', warrantyEnd: '', description: '' };
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u;
const ETAG = /^"device-([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})-([1-9][0-9]{0,18})"$/u;

function fail(status, code) {
  throw Object.assign(new Error(code), { status, code });
}

function validFields(input, fields) {
  return !!input && typeof input === 'object' && !Array.isArray(input)
    && [Object.prototype, null].includes(Object.getPrototypeOf(input))
    && Reflect.ownKeys(input).every(field => fields.includes(field));
}

function validUuid(value) {
  return typeof value === 'string' && value.length === 36 && UUID.test(value);
}

function validRevision(value) {
  return typeof value === 'string' && /^[1-9][0-9]{0,18}$/u.test(value)
    && BigInt(value).toString() === value && BigInt(value) <= 9223372036854775807n;
}

function validDate(value) {
  if (value === '') return true;
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/u.test(value) || value.startsWith('0000-')) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function validateDeviceValues(input) {
  if (!validFields(input, DEVICE_FIELDS)) fail(400, 'invalid_device_values');
  const values = {};
  for (const field of DEVICE_FIELDS) {
    const value = Object.hasOwn(input, field) ? input[field] : DEFAULTS[field];
    if (typeof value !== 'string' || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) fail(400, 'invalid_device_values');
    values[field] = value;
  }
  for (const [field, maximum] of Object.entries(TEXT_FIELDS)) {
    values[field] = values[field].trim();
    if ([...values[field]].length > maximum || !Object.hasOwn(DEFAULTS, field) && !values[field]) fail(400, 'invalid_device_values');
  }
  if (!DEVICE_CLASSES.includes(values.deviceClass) || !PLATFORMS.includes(values.platform)
    || !['corporate', 'byod', 'shared'].includes(values.ownership)
    || !validDate(values.purchaseDate) || !validDate(values.warrantyEnd)
    || values.purchaseDate && values.warrantyEnd && values.warrantyEnd < values.purchaseDate) fail(400, 'invalid_device_values');
  return values;
}

function validateDeviceAssignment(input) {
  if (!validFields(input, ['userId']) || !Object.hasOwn(input, 'userId')
    || input.userId !== null && !validUuid(input.userId)) fail(400, 'invalid_device_assignment');
  return { userId: input.userId };
}

function deviceEtag(device) {
  if (!device || typeof device !== 'object' || Array.isArray(device) || !validUuid(device.id) || !validRevision(device.revision)) fail(400, 'invalid_device_etag');
  return `"device-${device.id}-${device.revision}"`;
}

function validateDeviceEtag(value) {
  if (value === undefined || value === null || value === '') fail(428, 'device_etag_required');
  const match = typeof value === 'string' && value.match(ETAG);
  if (!match || match[0] !== value || !validRevision(match[2])) fail(400, 'invalid_device_etag');
  return value;
}

const RETURN_STATUSES = Object.freeze(['requested', 'returned', 'cancelled', 'assignment_changed']);
function exactFields(input, fields) {
  if (!validFields(input, fields) || fields.some(field => !Object.hasOwn(input, field))) fail(400, 'exact_device_return_fields_required');
}
function returnReason(value) {
  if (typeof value !== 'string' || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) fail(400, 'invalid_device_return_reason');
  value = value.trim();
  if ([...value].length < 10 || [...value].length > 500) fail(400, 'invalid_device_return_reason');
  return value;
}
function returnPage(input) {
  const page = input.page === undefined ? '1' : input.page;
  const limit = input.limit === undefined ? '25' : input.limit;
  if (typeof page !== 'string' || !/^[1-9][0-9]*$/u.test(page) || Number(page) > 1000000 || limit !== '25') fail(400, 'invalid_device_return_page');
  return { page: Number(page), limit: 25 };
}
function returnListQuery(input) {
  if (!validFields(input, ['page', 'limit', 'status']) || input.status !== undefined && !RETURN_STATUSES.includes(input.status)) fail(400, 'invalid_device_return_selectors');
  return { ...returnPage(input), status: input.status ?? null };
}
function offboardingReturnCapabilityQuery(input) {
  exactFields(input, ['workflowId']);
  if (!validUuid(input.workflowId)) fail(400, 'canonical_device_return_workflow_required');
  return { workflowId: input.workflowId };
}
function offboardingReturnQuery(input) {
  if (!validFields(input, ['workflowId', 'page', 'limit']) || !validUuid(input.workflowId)) fail(400, 'invalid_offboarding_device_return_selectors');
  return { workflowId: input.workflowId, ...returnPage(input) };
}
function deviceOffboardingValues(input) {
  exactFields(input, ['workflowId', 'userId']);
  if (!validUuid(input.workflowId) || !validUuid(input.userId)) fail(400, 'canonical_device_offboarding_target_required');
  return { workflowId: input.workflowId, userId: input.userId };
}
function offboardingReturnValues(input) {
  exactFields(input, ['workflowId', 'eligibilityRevision', 'reason', 'confirm', 'items']);
  if (!validUuid(input.workflowId) || !validRevision(input.eligibilityRevision) || input.confirm !== true
    || !Array.isArray(input.items) || input.items.length < 1 || input.items.length > 25) fail(400, 'confirmed_captured_device_return_manifest_required');
  const items = input.items.map(item => {
    exactFields(item, ['deviceId', 'deviceRevision', 'assignmentId', 'requestId']);
    if (!validUuid(item.deviceId) || !validUuid(item.assignmentId) || !validUuid(item.requestId) || !validRevision(item.deviceRevision)) fail(400, 'invalid_captured_device_return_item');
    return { deviceId: item.deviceId, deviceRevision: item.deviceRevision, assignmentId: item.assignmentId, requestId: item.requestId };
  });
  if (['deviceId', 'assignmentId', 'requestId'].some(field => new Set(items.map(item => item[field])).size !== items.length)) fail(400, 'duplicate_device_return_item');
  return { workflowId: input.workflowId, eligibilityRevision: input.eligibilityRevision, reason: returnReason(input.reason), confirm: true, items };
}
function returnDecisionValues(input) {
  exactFields(input, ['action', 'reason', 'confirm']);
  if (!['returned', 'cancelled'].includes(input.action) || input.confirm !== true) fail(400, 'explicit_device_return_decision_required');
  return { action: input.action, reason: returnReason(input.reason), confirm: true };
}
function deviceReturnEtag(request) {
  if (!request || !validUuid(request.id) || !validRevision(request.revision) || !validRevision(request.currentDeviceRevision)) fail(400, 'invalid_device_return_etag');
  return `"device-return-${request.id}-${request.revision}-${request.currentDeviceRevision}"`;
}
function validateDeviceReturnEtag(value) {
  if (value === undefined || value === null || value === '') fail(428, 'device_return_etag_required');
  const match = typeof value === 'string' && /^"device-return-([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})-([1-9][0-9]{0,18})-([1-9][0-9]{0,18})"$/u.exec(value);
  if (!match || !validRevision(match[2]) || !validRevision(match[3])) fail(400, 'invalid_device_return_etag');
  return { id: match[1], revision: match[2], deviceRevision: match[3] };
}

module.exports = { DEVICE_FIELDS, DEVICE_CLASSES, INVENTORY_PERMISSIONS, validateDeviceValues, validateDeviceAssignment, deviceEtag, validateDeviceEtag,
  RETURN_STATUSES, returnListQuery, offboardingReturnQuery, offboardingReturnCapabilityQuery, deviceOffboardingValues, offboardingReturnValues,
  returnDecisionValues, deviceReturnEtag, validateDeviceReturnEtag };
