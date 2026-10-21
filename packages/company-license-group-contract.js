'use strict';
const { exact, identifier, text } = require('./company-license-contract');
const { validRevision } = require('./identity-authorization-contract');
function linkValues(input) {
  exact(input, ['groupId', 'poolId', 'reason', 'confirm']);
  if (input.confirm !== true) throw Object.assign(new Error('Confirm license group linking'), { status: 400 });
  return { groupId: identifier(input.groupId), poolId: identifier(input.poolId), reason: text(input.reason, 10, 500), confirm: true };
}
function syncValues(input) {
  exact(input, ['groupRevision', 'cursor', 'reason', 'confirm']);
  if (input.confirm !== true || input.groupRevision !== null && !validRevision(input.groupRevision)) throw Object.assign(new Error('Capture the current license group revision'), { status: 400 });
  if (input.cursor !== null) identifier(input.cursor);
  return { ...input, reason: text(input.reason, 10, 500) };
}
function unlinkValues(input) {
  exact(input, ['reason', 'confirm']);
  if (input.confirm !== true) throw Object.assign(new Error('Confirm license group unlinking'), { status: 400 });
  return { reason: text(input.reason, 10, 500), confirm: true };
}
module.exports = { linkValues, syncValues, unlinkValues };
