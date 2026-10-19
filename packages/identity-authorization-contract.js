'use strict';

const PATH = '/internal/identity/authorization-state';
const AUDIENCE = 'opendirectory-identity-authority';
const PURPOSE = 'identity-authorization-request';
const TYPE = 'od-identity-authority+jwt';
const TARGET_PATH = '/internal/identity/application-target';
const TARGET_PURPOSE = 'identity-application-target-request';
const COMPANY_CONSOLE_PATH = '/internal/identity/company-console';
const COMPANY_CONSOLE_PURPOSE = 'identity-company-console-request';
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;

function validRevision(value) {
  return typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value).toString() === value && BigInt(value) <= 9223372036854775807n;
}

function validContext(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 4
    && typeof value.userId === 'string' && value.userId.length === 36 && UUID.test(value.userId) && validRevision(value.revision) && validRevision(value.linkRevision)
    && typeof value.rolesRevision === 'string' && value.rolesRevision.length === 64 && /^[a-f0-9]{64}$/.test(value.rolesRevision);
}

function sameContext(first, second) {
  return validContext(first) && validContext(second) && first.userId === second.userId
    && first.revision === second.revision && first.linkRevision === second.linkRevision && first.rolesRevision === second.rolesRevision;
}
function validUuid(value) { return typeof value === 'string' && value.length === 36 && UUID.test(value); }
function validMemberships(value) {
  return Array.isArray(value) && value.length <= 256 && value.every((member, index) => member && typeof member === 'object'
    && Object.keys(member).length === 2 && validUuid(member.groupId) && validUuid(member.membershipId)
    && (index === 0 || value[index - 1].groupId < member.groupId));
}

module.exports = { PATH, AUDIENCE, PURPOSE, TYPE, TARGET_PATH, TARGET_PURPOSE, COMPANY_CONSOLE_PATH, COMPANY_CONSOLE_PURPOSE, validUuid, validMemberships, validRevision, validContext, sameContext };
