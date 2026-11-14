'use strict';

const { validUuid, validRevision } = require('../../../../packages/identity-authorization-contract');
const { COMPANY_DIRECTORY_PERMISSIONS } = require('./CompanyOwner');
const PERMISSIONS = COMPANY_DIRECTORY_PERMISSIONS;
const OU_PERMISSIONS = Object.freeze(['users.read', 'users.update', 'users.status.manage']);
function fail(status, code) { throw Object.assign(new Error(code), { status, code }); }
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length
    || keys.some(key => !Object.hasOwn(value, key))) fail(400, 'exact_company_role_fields_required');
}
function text(value, minimum, maximum, multiline=false) {
  if (typeof value !== 'string' || (multiline?/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u:/[\u0000-\u001f\u007f-\u009f]/u).test(value)
    || [...value.trim()].length < minimum || [...value.trim()].length > maximum) fail(400, 'invalid_company_role_text');
  return value.trim();
}
function identifier(value) { if (!validUuid(value) || value !== value.toLowerCase()) fail(400, 'canonical_company_role_identifier_required'); return value; }
function explanation(input) { if (input.confirm !== true) fail(400, 'explicit_company_role_confirmation_required'); return text(input.reason, 10, 500); }
function definition(input, creating = false) {
  exact(input, ['name', 'description', 'permissions', 'maxDurationSeconds', ...(creating ? [] : ['enabled']), 'reason', 'confirm']);
  if (!Array.isArray(input.permissions) || !input.permissions.length || input.permissions.length > PERMISSIONS.length
    || new Set(input.permissions).size !== input.permissions.length || input.permissions.some(permission => !PERMISSIONS.includes(permission))
    || !Number.isInteger(input.maxDurationSeconds) || input.maxDurationSeconds < 60 || input.maxDurationSeconds > 36000
    || !creating && typeof input.enabled !== 'boolean') fail(400, 'invalid_company_role_definition');
  return { name: text(input.name, 2, 120), description: text(input.description, 0, 1000, true), permissions: [...input.permissions].sort(),
    maxDurationSeconds: input.maxDurationSeconds, enabled: creating ? true : input.enabled, reason: explanation(input), confirm: true };
}
function assignment(input) {
  exact(input, ['targetType', 'targetId', 'scopeType', 'ouId', 'durationSeconds', 'reason', 'confirm']);
  if (!['user', 'group'].includes(input.targetType) || !['tenant', 'ou'].includes(input.scopeType)
    || input.scopeType === 'tenant' && input.ouId !== null || input.scopeType === 'ou' && !validUuid(input.ouId)
    || !Number.isInteger(input.durationSeconds) || input.durationSeconds < 60 || input.durationSeconds > 36000) fail(400, 'invalid_company_role_assignment');
  return { targetType: input.targetType, targetId: identifier(input.targetId), scopeType: input.scopeType,
    ouId: input.ouId === null ? null : identifier(input.ouId), durationSeconds: input.durationSeconds, reason: explanation(input), confirm: true };
}
function eligibility(input){
 exact(input,['targetType','targetId','scopeType','ouId','validForSeconds','reason','confirm']);
 if(!Number.isInteger(input.validForSeconds)||input.validForSeconds<60||input.validForSeconds>31536000)fail(400,'invalid_company_pim_eligibility_duration');
 const {validForSeconds,...fields}=input;const checked=assignment({...fields,durationSeconds:60});delete checked.durationSeconds;return {...checked,validForSeconds};
}
function activation(input){exact(input,['durationSeconds','reason','confirm']);if(!Number.isInteger(input.durationSeconds)||input.durationSeconds<60||input.durationSeconds>36000)fail(400,'invalid_company_pim_activation_duration');return {durationSeconds:input.durationSeconds,...decision({reason:input.reason,confirm:input.confirm})};}
function group(input) { exact(input,['name','description','reason','confirm']); return {name:text(input.name,2,120),description:text(input.description,0,1000,true),reason:explanation(input),confirm:true}; }
function decision(input) { exact(input, ['reason', 'confirm']); return { reason: explanation(input), confirm: true }; }
function etag(kind, value) {
  if (!['role', 'grant','eligibility','activation'].includes(kind) || !validRevision(value?.revision)) fail(400, 'invalid_company_role_revision');
  return `"company-${kind}-${identifier(value.id)}-${value.revision}"`;
}
function expected(kind, value, id) {
  if (value === undefined || value === '') fail(428, 'company_role_if_match_required');
  const match = typeof value === 'string' && /^"company-(role|grant|eligibility|activation)-([a-f0-9-]{36})-([1-9][0-9]{0,18})"$/.exec(value);
  if (!match || match[0] !== value || match[1] !== kind || match[2] !== identifier(id) || !validRevision(match[3])) fail(400, 'invalid_company_role_if_match');
  return match[3];
}
function page(input = {}) {
  if (Object.keys(input).some(key => !['page', 'limit', 'search'].includes(key))) fail(400, 'invalid_company_role_selectors');
  const selected = input.page === undefined ? '1' : input.page;
  if (typeof selected !== 'string' || !/^[1-9][0-9]*$/u.test(selected) || Number(selected) > 1000000 || input.limit !== undefined && input.limit !== '25') fail(400, 'invalid_company_role_page');
  return { page: Number(selected), limit: 25, search: input.search === undefined ? '' : text(input.search, 0, 255) };
}
module.exports = { PERMISSIONS, OU_PERMISSIONS, identifier, definition, assignment, eligibility, activation, decision, group, etag, expected, page, fail };
