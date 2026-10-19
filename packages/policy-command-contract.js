'use strict';

const { validUuid, validRevision } = require('./identity-authorization-contract');
const ADMISSION_SECONDS = 30;
const DELIVERY_SECONDS = 300;
const MAX_PAYLOAD_BYTES = 262144;
const TYPES = ['wifi','vpn','filevault','gatekeeper','software_update','screen_lock','certificate','webfilter','airdrop'];
class PolicyCommandError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
function fail(status, code) { throw new PolicyCommandError(status, code); }
const uuid = value => validUuid(value) && value === value.toLowerCase();
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const date = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
const integer = value => Number.isSafeInteger(value) && value > 0;
const deviceId = value => typeof value === 'string' && /^(?!\.{1,2}$)[A-Za-z0-9._~-]{1,255}$/.test(value);
function fields(value, names, status = 400) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== names.length || names.some(name => !Object.hasOwn(value, name))) fail(status, 'exact_policy_command_fields_required');
}
function reference(value, status = 400) {
  fields(value, ['resourceKind','resourceId','resourceVersion','publicationId','configurationId'], status);
  if (!['policy','blueprint'].includes(value.resourceKind) || !uuid(value.resourceId) || !uuid(value.publicationId) || !integer(value.resourceVersion)
    || (value.resourceKind === 'policy' ? value.configurationId !== null : !uuid(value.configurationId))) fail(status, 'exact_policy_command_reference_required');
  return value;
}
function json(value, status = 400, depth = 0) {
  if (depth > 20 || typeof value === 'number' && !Number.isFinite(value) || ![null,'string','number','boolean','object'].includes(value === null ? null : typeof value)) fail(status, 'bounded_policy_command_json_required');
  if (Array.isArray(value)) value.forEach(item => json(item, status, depth + 1));
  else if (value && typeof value === 'object') for (const [key, item] of Object.entries(value)) {
    if (['__proto__','prototype','constructor'].includes(key)) fail(status, 'safe_policy_command_json_required');
    json(item, status, depth + 1);
  }
  if (depth === 0 && Buffer.byteLength(JSON.stringify(value)) > MAX_PAYLOAD_BYTES) fail(status, 'bounded_policy_command_json_required');
  return value;
}
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
const same = (first, second) => JSON.stringify(canonical(first)) === JSON.stringify(canonical(second));
function frame(value, expected, now = Date.now()) {
  fields(value, ['schemaVersion','reference','deviceId','platform','operatorUserId','operationId','configurationVersion','configurationHash','publicationVersion',
    'publicationExpiresAt','observedAt','admissionValidUntil','deliverUntil','payload','payloadHash'], 503);
  reference(value.reference, 503);
  if (value.schemaVersion !== 1 || !deviceId(value.deviceId) || !['windows','macos','linux'].includes(value.platform) || !uuid(value.operatorUserId) || !uuid(value.operationId)
    || !integer(value.configurationVersion) || value.configurationVersion > value.reference.resourceVersion || !hash(value.configurationHash) || !integer(value.publicationVersion) || value.publicationVersion < 2 || !hash(value.payloadHash)
    || ['observedAt','admissionValidUntil','deliverUntil','publicationExpiresAt'].some(key => !date(value[key]))
    || Date.parse(value.observedAt) > now + 5000 || Date.parse(value.admissionValidUntil) <= now || Date.parse(value.deliverUntil) <= now
    || Date.parse(value.admissionValidUntil) > Date.parse(value.observedAt) + ADMISSION_SECONDS * 1000
    || Date.parse(value.deliverUntil) > Date.parse(value.observedAt) + DELIVERY_SECONDS * 1000
    || Date.parse(value.admissionValidUntil) > Date.parse(value.deliverUntil) || Date.parse(value.deliverUntil) > Date.parse(value.publicationExpiresAt)) fail(503, 'policy_command_frame_invalid');
  const payload = value.payload; json(payload, 503);
  const name = candidate => typeof candidate === 'string' && candidate.trim().length > 0 && candidate.length <= 255;
  if (value.reference.resourceKind === 'policy') {
    fields(payload, ['gpoId','gpoName','configurationVersion','settings'], 503);
    if (payload.gpoId !== value.reference.resourceId || !name(payload.gpoName)) fail(503, 'policy_command_payload_invalid');
  } else {
    fields(payload, ['blueprintId','blueprintName','configurationId','configurationVersion','configType','configName','settings'], 503);
    if (payload.blueprintId !== value.reference.resourceId || payload.configurationId !== value.reference.configurationId || !name(payload.blueprintName) || !name(payload.configName) || !TYPES.includes(payload.configType)) fail(503, 'policy_command_payload_invalid');
  }
  if (payload.configurationVersion !== value.reference.resourceVersion || !payload.settings || typeof payload.settings !== 'object' || Array.isArray(payload.settings)) fail(503, 'policy_command_payload_invalid');
  if (expected && (!same(value.reference, expected.reference) || value.deviceId !== expected.deviceId || value.platform !== expected.platform
    || value.operatorUserId !== expected.operatorUserId || value.operationId !== expected.operationId)) fail(503, 'policy_command_frame_mismatch');
  return value;
}
function sameFrame(first, second) {
  return same(Object.fromEntries(Object.entries(first).filter(([key]) => !['observedAt','admissionValidUntil','deliverUntil'].includes(key))),
    Object.fromEntries(Object.entries(second).filter(([key]) => !['observedAt','admissionValidUntil','deliverUntil'].includes(key))));
}
function protocol(value, user) {
  fields(value, ['schemaVersion','commandContract','receiptContract','admissionMaxSeconds','deliveryMaxSeconds','subject','userId','freshMfa'], 503);
  if (value.schemaVersion !== 1 || value.commandContract !== 'approved-content-v1' || value.receiptContract !== 'postgres-evidence-v1' || value.admissionMaxSeconds !== ADMISSION_SECONDS
    || value.deliveryMaxSeconds !== DELIVERY_SECONDS || value.subject !== user.sub || value.userId !== user.identity_authorization?.userId || value.freshMfa !== true) fail(503, 'policy_receiver_protocol_required');
  return value;
}
function receipt(value, expected, status = 503) {
  fields(value, ['schemaVersion','commandId','operationId','deviceId','deviceGeneration','operatorUserId','reference','configurationVersion','configurationHash','publicationVersion','payloadHash','expiresAt','persistence'], status);
  reference(value.reference, status);
  if (value.schemaVersion !== 1 || !uuid(value.commandId) || !uuid(value.operationId) || !deviceId(value.deviceId) || !validRevision(value.deviceGeneration)
    || !uuid(value.operatorUserId) || !integer(value.configurationVersion) || value.configurationVersion > value.reference.resourceVersion || !hash(value.configurationHash)
    || !integer(value.publicationVersion) || value.publicationVersion < 2 || !hash(value.payloadHash) || !date(value.expiresAt) || value.persistence !== 'committed') fail(status, 'policy_command_receipt_invalid');
  if (expected && (!same(value.reference, expected.reference) || value.commandId !== expected.commandId || value.deviceId !== expected.deviceId || value.operationId !== expected.operationId
    || value.operatorUserId !== expected.operatorUserId || value.configurationHash !== expected.configurationHash || value.configurationVersion !== expected.configurationVersion || value.publicationVersion !== expected.publicationVersion)) fail(status, 'policy_command_receipt_mismatch');
  return value;
}
function cancellation(value, expected) {
  fields(value, ['schemaVersion','commandId','deviceId','operationId','cancelledByUserId','cancelledAt','reason','previouslyOffered','policyReceipt','persistence','furtherOffersStopped','enforcementConfirmed'], 503);
  receipt(value.policyReceipt);
  if (value.schemaVersion !== 1 || !uuid(value.operationId) || !uuid(value.cancelledByUserId) || !date(value.cancelledAt)
    || typeof value.reason !== 'string' || value.reason.trim() !== value.reason || value.reason.length < 10 || value.reason.length > 500
    || typeof value.previouslyOffered !== 'boolean' || value.commandId !== value.policyReceipt.commandId || value.deviceId !== value.policyReceipt.deviceId
    || value.cancelledByUserId !== value.policyReceipt.operatorUserId || value.persistence !== 'committed' || value.furtherOffersStopped !== true || value.enforcementConfirmed !== false) fail(503, 'policy_command_cancellation_invalid');
  if (expected && (!same(value.policyReceipt, expected.policyReceipt) || value.operationId !== expected.operationId || value.reason !== expected.reason || value.cancelledByUserId !== expected.userId)) fail(503, 'policy_command_cancellation_mismatch');
  return value;
}
module.exports = { ADMISSION_SECONDS, DELIVERY_SECONDS, MAX_PAYLOAD_BYTES, TYPES, PolicyCommandError, fail, uuid, hash, date, integer, deviceId, fields, reference, json, same, frame, sameFrame, protocol, receipt, cancellation };
