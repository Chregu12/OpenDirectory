'use strict';

const { generateKeyPairSync } = require('crypto');
const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const issuer = 'https://gateway.test';
const audience = 'opendirectory-api';
const publicJwk = { ...keys.publicKey.export({ format: 'jwk' }), kid: 'gateway-tests', alg: 'RS256', use: 'sig' };
module.exports = { issuer, audience, privateKey: keys.privateKey, publicJwk };
