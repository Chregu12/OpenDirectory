'use strict';

const { normalizeProfile } = require('../organization-profile-contract');
const BASE_PATH = '/internal/identity/company-registrations';
const AUDIENCE = 'opendirectory-company-registration';
const PURPOSE = 'company-registration-receiving';
const TYPE = 'od-company-registration+jwt';
const identifier = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
function invalid() { throw Object.assign(new Error('invalid_company_registration'), { status: 400 }); }
function exact(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== fields.length || fields.some(field => !Object.hasOwn(value, field))) invalid();
}
function bounded(value, maximum) { return typeof value === 'string' && value === value.trim() && value.length > 0 && value.length <= maximum && !/[\u0000-\u001f\u007f]/.test(value); }
function normalizePrincipal(value) {
  exact(value, ['username', 'email', 'displayName']);
  if (!bounded(value.username, 255) || !bounded(value.email, 254) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.email) || !bounded(value.displayName, 255)) invalid();
  return { username: value.username, email: value.email, displayName: value.displayName };
}
function normalizeInternal(operation, input) {
  if (!['submit', 'status', 'activate'].includes(operation)) invalid();
  exact(input, operation === 'submit' ? ['registrationId', 'subject', 'principal', 'profile'] : operation === 'activate' ? ['registrationId', 'subject', 'consoleClientId'] : ['registrationId', 'subject']);
  if (!identifier(input.registrationId) || !bounded(input.subject, 255)) invalid();
  const result = { registrationId: input.registrationId, subject: input.subject };
  if (operation === 'submit') {
    result.principal = normalizePrincipal(input.principal);
    result.profile = normalizeProfile(input.profile);
  }
  if (operation === 'activate') { if (typeof input.consoleClientId !== 'string' || !/^[A-Za-z0-9._~-]{1,255}$/.test(input.consoleClientId)) invalid(); result.consoleClientId = input.consoleClientId; }
  return result;
}
function normalizePublic(operation, input) {
  exact(input, operation === 'submit' ? ['registrationId', 'username', 'password', 'mfaCode', 'profile', 'confirm'] : operation === 'activate' ? ['registrationId', 'username', 'password', 'mfaCode', 'confirm'] : ['registrationId', 'username', 'password', 'mfaCode']);
  if (!['submit', 'status', 'activate'].includes(operation) || !identifier(input.registrationId) || !bounded(input.username, 255) || typeof input.password !== 'string' || !input.password || input.password.length > 4096
    || typeof input.mfaCode !== 'string' || input.mfaCode.length > 128 || /[\u0000-\u001f\u007f]/.test(input.mfaCode) || operation !== 'status' && input.confirm !== true) invalid();
  return { registrationId: input.registrationId, username: input.username, password: input.password, mfaCode: input.mfaCode,
    ...(operation === 'submit' ? { profile: normalizeProfile(input.profile), confirm: true } : operation === 'activate' ? { confirm: true } : {}) };
}
function principalFor(user) {
  if (!bounded(user?.id, 255)) invalid();
  const principal = normalizePrincipal({
    username: user?.username, email: user?.email, displayName: user?.displayName || user?.name || user?.username,
  });
  return { subject: user.id, principal };
}
function validReceipt(value, registrationId) {
  if (value?.schemaVersion === 3) {
    if (Array.isArray(value)) return false;
    const fields = ['schemaVersion', 'registrationId', 'tenantId', 'administratorId', 'createdAt', 'status', 'tenantEnabled', 'administratorEnabled', 'profileSaved', 'activationSupported', 'replayed', 'reviewedAt', 'activatedAt', 'consoleClientId', 'mfaRequired'];
    return Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field)) && value.registrationId === registrationId && identifier(registrationId) && identifier(value.tenantId) && identifier(value.administratorId)
      && ['createdAt', 'reviewedAt', 'activatedAt'].every(field => typeof value[field] === 'string' && Number.isFinite(Date.parse(value[field])))
      && Date.parse(value.createdAt) <= Date.parse(value.reviewedAt) && Date.parse(value.reviewedAt) <= Date.parse(value.activatedAt)
      && typeof value.tenantEnabled === 'boolean' && typeof value.administratorEnabled === 'boolean' && value.status === (value.tenantEnabled && value.administratorEnabled ? 'active' : 'suspended')
      && value.profileSaved === true && value.activationSupported === true && value.mfaRequired === true && typeof value.replayed === 'boolean' && typeof value.consoleClientId === 'string' && /^[A-Za-z0-9._~-]{1,255}$/.test(value.consoleClientId);
  }
  const fields = ['schemaVersion', 'registrationId', 'tenantId', 'administratorId', 'createdAt', 'status', 'tenantEnabled', 'administratorEnabled', 'profileSaved', 'activationSupported', 'replayed'];
  if (value?.schemaVersion === 2) fields.push('reviewedAt');
  return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field))
    && identifier(registrationId) && value.registrationId === registrationId && identifier(value.tenantId) && identifier(value.administratorId)
    && typeof value.createdAt === 'string' && Number.isFinite(Date.parse(value.createdAt))
    && (value.schemaVersion === 1 && value.status === 'pending-verification' || value.schemaVersion === 2 && ['pending-activation', 'rejected'].includes(value.status)
      && typeof value.reviewedAt === 'string' && Number.isFinite(Date.parse(value.reviewedAt)) && Date.parse(value.reviewedAt) >= Date.parse(value.createdAt))
    && value.tenantEnabled === false && value.administratorEnabled === false && value.profileSaved === false && value.activationSupported === false && typeof value.replayed === 'boolean';
}
function validCapabilities(value) {
  return !!value && !Array.isArray(value) && Object.keys(value).length === 5 && [1, 2].includes(value.schemaVersion) && typeof value.enabled === 'boolean' && value.requiresExistingAccount === true
    && typeof value.activationSupported === 'boolean' && (value.schemaVersion === 2 || value.activationSupported === false) && value.status === 'pending-verification';
}
function normalizeReview(value) {
  exact(value, ['decision', 'reason', 'confirm']);
  if (!['approved', 'rejected'].includes(value.decision) || typeof value.reason !== 'string' || value.reason.trim().length < 10 || value.reason.length > 500
    || /[\u0000-\u001f\u007f]/.test(value.reason) || value.confirm !== true) invalid();
  return { decision: value.decision, reason: value.reason.trim(), confirm: true };
}
module.exports = { BASE_PATH, AUDIENCE, PURPOSE, TYPE, identifier, normalizeInternal, normalizePublic, principalFor, validReceipt, normalizeReview, validCapabilities };
