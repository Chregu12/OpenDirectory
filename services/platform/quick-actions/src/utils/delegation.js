'use strict';

const { AsyncLocalStorage } = require('node:async_hooks');
const { randomUUID } = require('node:crypto');
const { createAccessStateClient } = require('../../../../../packages/oidc-access-state');
const storage = new AsyncLocalStorage();
const validate = createAccessStateClient();
function frozen(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(frozen); Object.freeze(value); }
  return value;
}
function interrupted(message = 'Delegated operation has ended', status = 401) { return Object.assign(new Error(message), { status, code: 'DELEGATION_ENDED' }); }
function runWithOperator(authorization, claims, operation) {
  if (storage.getStore()) throw interrupted('Nested delegated operations are not accepted', 403);
  if (typeof authorization !== 'string' || !/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(authorization) || !claims?.sub || !claims.jti) throw interrupted('Verified operator context is required');
  const principal = frozen(structuredClone(claims)); const controller = new AbortController();
  const context = Object.freeze({ authorization, claims: principal, operationId: randomUUID(), signal: controller.signal,
    close: () => { if (!controller.signal.aborted) controller.abort(interrupted()); },
    block: error => { if (!controller.signal.aborted) controller.abort(error); },
    check: async () => {
      if (controller.signal.aborted) throw controller.signal.reason;
      try {
        await validate(authorization, principal);
        if (controller.signal.aborted) throw controller.signal.reason;
      } catch (error) { if (!controller.signal.aborted) controller.abort(error); throw controller.signal.reason; }
    } });
  return storage.run(context, () => operation(context));
}
function currentOperator() { const context = storage.getStore(); if (!context) throw interrupted('Verified operator context is required'); return context; }
module.exports = { runWithOperator, currentOperator, validate };
