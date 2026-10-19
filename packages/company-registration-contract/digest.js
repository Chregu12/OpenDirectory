'use strict';

const { createHash } = require('node:crypto');
const { normalizeInternal } = require('./index');
function requestDigest(operation, input) { return createHash('sha256').update(JSON.stringify({ operation, input: normalizeInternal(operation, input) })).digest('hex'); }
module.exports = { requestDigest };
