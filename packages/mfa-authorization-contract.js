'use strict';

const { validUuid, validRevision } = require('./identity-authorization-contract');

function validMethods(methods) {
  return Array.isArray(methods) && (JSON.stringify(methods) === '["pwd"]' || JSON.stringify(methods) === '["pwd","otp"]');
}

function validMfaContext(context) {
  return !!context && typeof context === 'object' && !Array.isArray(context)
    && Object.keys(context).length === 5 && context.schemaVersion === 1 && validUuid(context.userId)
    && (context.revision === '0' || validRevision(context.revision)) && validMethods(context.methods)
    && Number.isSafeInteger(context.authTime) && context.authTime > 0;
}

function boundMfa(payload) {
  const context = payload?.mfa_authorization;
  return payload?.actor_type === 'user' && validMfaContext(context)
    && context.userId === payload.identity_authorization?.userId && payload.auth_time === context.authTime
    && JSON.stringify(payload.amr) === JSON.stringify(context.methods);
}

function provenMfa(payload) {
  return boundMfa(payload) && payload.mfa_authorization.methods.length === 2;
}

module.exports = { validMfaContext, boundMfa, provenMfa };
