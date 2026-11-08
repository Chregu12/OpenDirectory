'use strict';

const fs = require('node:fs');
const { createPrivateKey } = require('node:crypto');
const { fields, uuid } = require('../fulfillment/contracts');
const { bearer } = require('../fulfillment/transport');
const email = value => typeof value === 'string' && value.length <= 254 && /^[^\s@\x00-\x1f\x7f]+@[^\s@\x00-\x1f\x7f]+$/.test(value) && !/[\p{Cc}]/u.test(value);
const productId = value => typeof value === 'string' && /^[A-Za-z0-9-]{1,64}$/.test(value);
const login = value => typeof value === 'string' && /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(value) && !value.includes('--');

const userLogin = value => login(value) || typeof value === 'string' && value.length <= 39 && value.split('_').length === 2 && login(value.split('_')[0]) && /^[A-Za-z0-9]{3,8}$/.test(value.split('_')[1]);
const text = (value, limit) => typeof value === 'string' && value.trim().length > 0 && value.length <= limit && !/[\p{Cc}]/u.test(value);
const adobeOrg = value => typeof value === 'string' && /^[A-Fa-f0-9]{1,64}@AdobeOrg$/.test(value);
const profileId = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 18446744073709551615n;
const slackId = (value, prefixes) => typeof value === 'string' && value.length >= 2 && value.length <= 64 && prefixes.includes(value[0]) && /^[A-Z0-9]+$/.test(value);

function validateConfiguration(data) {
  const common = ['schemaVersion', 'provider', 'consentReviewed'];
  if (data?.provider === 'google-workspace') {
    fields(data, [...common, 'customerId', 'productId', 'skuId', 'serviceAccountEmail', 'delegatedSubject', 'privateKey']);
    if (typeof data.customerId !== 'string' || !/^C[A-Za-z0-9]{1,63}$/.test(data.customerId) || !productId(data.productId) || !productId(data.skuId)
      || !email(data.serviceAccountEmail) || !data.serviceAccountEmail.endsWith('.gserviceaccount.com') || !email(data.delegatedSubject)
      || typeof data.privateKey !== 'string' || data.privateKey.length > 16384) throw new Error('Invalid Google read configuration');
    try {
      const key = createPrivateKey(data.privateKey);
      if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength < 2048 || key.asymmetricKeyDetails.modulusLength > 8192) throw new Error();
    } catch { throw new Error('Valid RSA service account key required'); }
  } else if (data?.provider === 'github-copilot') {
    fields(data, [...common, 'organization', 'accessToken']);
    if (!login(data.organization) || !bearer(data.accessToken)) throw new Error('Invalid GitHub read configuration');
  } else if (data?.provider === 'adobe-enterprise') {
    fields(data, [...common, 'organizationId', 'profileId', 'profileName', 'clientId', 'clientSecret']);
    if (!adobeOrg(data.organizationId) || !profileId(data.profileId) || !text(data.profileName, 255) || ['.', '..'].includes(data.profileName)
      || typeof data.clientId !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(data.clientId) || !text(data.clientSecret, 4096) || data.clientSecret.length < 12) throw new Error('Invalid Adobe read configuration');
  } else if (data?.provider === 'slack-scim') {
    fields(data, [...common, 'directoryKind', 'directoryId', 'accessToken']);
    if (!(data.directoryKind === 'workspace' && slackId(data.directoryId, 'T') || data.directoryKind === 'enterprise' && slackId(data.directoryId, 'E')) || !bearer(data.accessToken)) throw new Error('Invalid Slack read configuration');
  } else if (data?.provider === 'atlassian-cloud') {
    fields(data, [...common, 'organizationId', 'directoryId', 'accessToken']);
    uuid(data.organizationId); uuid(data.directoryId);
    if (!bearer(data.accessToken)) throw new Error('Invalid Atlassian read configuration');
  } else if (data?.provider === 'gitlab-cloud') {
    fields(data, [...common, 'groupId', 'groupPath', 'accessToken']);
    if (!profileId(data.groupId) || BigInt(data.groupId) > 9007199254740991n || typeof data.groupPath !== 'string'
      || !/^[A-Za-z0-9_.-]{1,255}$/.test(data.groupPath) || ['.', '..'].includes(data.groupPath) || !bearer(data.accessToken)) throw new Error('Invalid GitLab read configuration');
  } else throw new Error('Unsupported read provider');
  if (data.schemaVersion !== 1 || data.consentReviewed !== true) throw new Error('Explicit reviewed provider consent required');
  return Object.freeze({ ...data });
}

function configuration(filename) {
  if (!filename || typeof process.getuid !== 'function') throw new Error('Protected provider file required');
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0 || stat.size > 65536) throw new Error('Owner-only regular provider file required');
    const bytes = Buffer.alloc(65537); const size = fs.readSync(descriptor, bytes, 0, bytes.length, 0);
    if (size !== stat.size || size > 65536) throw new Error('Provider file changed or exceeds limit');
    return validateConfiguration(JSON.parse(bytes.subarray(0, size).toString('utf8')));
  } finally { fs.closeSync(descriptor); }
}

module.exports = { configuration, validateConfiguration, email, productId, login, userLogin, text, slackId };
