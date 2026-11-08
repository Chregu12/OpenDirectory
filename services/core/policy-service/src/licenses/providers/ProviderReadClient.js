'use strict';

const { createPrivateKey } = require('node:crypto');
const { SignJWT } = require('jose');
const { ProviderError, jsonRequest, bearer, ClientCredentialToken } = require('../fulfillment/transport');
const { runConnector } = require('../fulfillment/rustConnector');
const { validateConfiguration, email, userLogin, text, slackId } = require('./ReadConfiguration');
const GOOGLE_SCOPE = 'https://www.googleapis.com/auth/apps.licensing';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const ADOBE_TOKEN_URL = 'https://ims-na1.adobelogin.com/ims/token/v3';
const ADOBE_SCOPE = 'openid,AdobeID,user_management_sdk';
const STAGES = { 'google-workspace': 'google_licenses', 'github-copilot': 'github_copilot', 'adobe-enterprise': 'adobe_profiles', 'slack-scim': 'slack_directory', 'atlassian-cloud': 'atlassian_directory', 'gitlab-cloud': 'gitlab_billable' };

class GoogleToken {
  constructor(config, fetchImpl) { this.config = config; this.fetch = fetchImpl; this.key = createPrivateKey(config.privateKey); this.cached = null; }
  clear() { this.cached = null; }
  async get(signal) {
    if (signal.aborted) throw new ProviderError('google_token_unavailable');
    if (this.cached?.until > Date.now()) return this.cached.token;
    const now = Math.floor(Date.now() / 1000);
    const assertion = await new SignJWT({ scope: GOOGLE_SCOPE }).setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
      .setIssuer(this.config.serviceAccountEmail).setSubject(this.config.delegatedSubject).setAudience(GOOGLE_TOKEN_URL).setIssuedAt(now).setExpirationTime(now + 300).sign(this.key);
    const data = await jsonRequest(this.fetch, GOOGLE_TOKEN_URL, { method: 'POST', signal, headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }).toString() }, 'google_token');
    if (typeof data?.token_type !== 'string' || data.token_type.toLowerCase() !== 'bearer' || !bearer(data.access_token)
      || !Number.isInteger(data.expires_in) || data.expires_in < 60 || data.expires_in > 86400 || data.scope !== undefined && data.scope !== GOOGLE_SCOPE) throw new ProviderError('google_token_invalid_response');
    this.cached = { token: data.access_token, until: Date.now() + (data.expires_in - 30) * 1000 }; return data.access_token;
  }
}

function snapshot(data, config) {
  const fail = () => { throw new ProviderError(STAGES[config.provider] + '_invalid_response'); };
  const exact = (object, keys) => object && typeof object === 'object' && !Array.isArray(object) && Object.keys(object).sort().join(',') === [...keys].sort().join(',');
  if (config.provider === 'google-workspace') {
    if (!exact(data, ['customerId', 'productId', 'skuId', 'assignments']) || data.customerId !== config.customerId || data.productId !== config.productId
      || data.skuId !== config.skuId || !Array.isArray(data.assignments) || data.assignments.length > 1000) fail();
    const users = new Set();
    for (const row of data.assignments) {
      if (!exact(row, ['productId', 'skuId', 'userId']) || row.productId !== config.productId || row.skuId !== config.skuId || !email(row.userId) || users.has(row.userId.toLowerCase())) fail();
      users.add(row.userId.toLowerCase());
    }
  } else if (config.provider === 'adobe-enterprise') {
    if (!exact(data, ['organizationId', 'profileId', 'profileName', 'productName', 'members']) || data.organizationId !== config.organizationId || data.profileId !== config.profileId
      || data.profileName !== config.profileName || !text(data.productName, 255) || !Array.isArray(data.members) || data.members.length > 1000) fail();
    const ids = new Set(); const identities = new Set();
    for (const member of data.members) {
      if (!exact(member, ['id', 'email', 'identityType', 'status']) || !email(member.email) || member.id !== null && (!text(member.id, 128) || ids.has(member.id))
        || member.identityType !== null && !['adobeID', 'enterpriseID', 'federatedID', 'unknown'].includes(member.identityType)
        || member.status !== null && !['active', 'disabled', 'locked', 'removed'].includes(member.status)) fail();
      const identity = JSON.stringify([member.email.toLowerCase(), member.identityType]);
      if (identities.has(identity)) fail(); identities.add(identity); if (member.id !== null) ids.add(member.id);
    }
  } else if (config.provider === 'slack-scim') {
    if (!exact(data, ['directoryKind', 'directoryId', 'users']) || data.directoryKind !== config.directoryKind || data.directoryId !== config.directoryId
      || !Array.isArray(data.users) || data.users.length > 1000) fail();
    const ids = new Set();
    for (const user of data.users) {
      if (!exact(user, ['id', 'userName', 'active']) || !slackId(user.id, 'UW') || !text(user.userName, 254) || typeof user.active !== 'boolean' || ids.has(user.id)) fail();
      ids.add(user.id);
    }
  } else if (config.provider === 'atlassian-cloud') {
    if (!exact(data, ['organizationId', 'directoryId', 'users']) || data.organizationId !== config.organizationId || data.directoryId !== config.directoryId
      || !Array.isArray(data.users) || data.users.length > 1000) fail();
    const ids = new Set();
    for (const user of data.users) {
      if (!exact(user, ['accountId', 'accountType', 'accountStatus', 'membershipStatus', 'status']) || typeof user.accountId !== 'string' || !/^[A-Za-z0-9_|:-]{1,128}$/.test(user.accountId)
        || ids.has(user.accountId) || user.accountType !== null && user.accountType !== 'atlassian'
        || user.accountStatus !== null && !['active', 'inactive', 'closed'].includes(user.accountStatus)
        || user.membershipStatus !== null && !['active', 'suspended', 'no_membership'].includes(user.membershipStatus)
        || user.status !== null && !['active', 'suspended', 'not_invited', 'deactivated', 'for_deletion'].includes(user.status)) fail();
      ids.add(user.accountId);
    }
  } else if (config.provider === 'gitlab-cloud') {
    if (!exact(data, ['groupId', 'groupPath', 'billableMembers']) || data.groupId !== config.groupId || data.groupPath !== config.groupPath
      || !Array.isArray(data.billableMembers) || data.billableMembers.length > 1000) fail();
    const ids = new Set();
    for (const member of data.billableMembers) {
      if (!exact(member, ['id', 'username', 'state', 'membershipType']) || !Number.isSafeInteger(member.id) || member.id <= 0 || ids.has(member.id)
        || !text(member.username, 255) || member.state !== null && !text(member.state, 64) || member.membershipType !== null && !text(member.membershipType, 64)) fail();
      ids.add(member.id);
    }
  } else {
    if (!exact(data, ['organization', 'totalSeats', 'seats']) || data.organization !== config.organization.toLowerCase() || !Number.isInteger(data.totalSeats)
      || data.totalSeats < 0 || data.totalSeats > 1000 || !Array.isArray(data.seats) || data.seats.length !== data.totalSeats) fail();
    const ids = new Set(); const logins = new Set();
    const id = value => Number.isSafeInteger(value) && value > 0;
    for (const row of data.seats) {
      if (!exact(row, ['assigneeId', 'login', 'assigningTeamId', 'pendingCancellationDate']) || !id(row.assigneeId) || !userLogin(row.login)
        || ids.has(row.assigneeId) || logins.has(row.login.toLowerCase()) || row.assigningTeamId !== null && !id(row.assigningTeamId)) fail();
      if (row.pendingCancellationDate !== null) {
        const value = row.pendingCancellationDate;
        if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value) || value.startsWith('0000') || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString().slice(0, 10) !== value) fail();
      }
      ids.add(row.assigneeId); logins.add(row.login.toLowerCase());
    }
  }
  return data;
}

class ProviderReadClient {
  constructor(config, { fetchImpl = (...args) => fetch(...args), binary = '/usr/local/bin/opendirectory-connectors', spawnImpl } = {}) {
    this.config = validateConfiguration(config); this.binary = binary; this.spawnImpl = spawnImpl;
    if (this.config.provider === 'google-workspace') this.tokens = new GoogleToken(this.config, fetchImpl);
    else if (this.config.provider === 'adobe-enterprise') this.tokens = new ClientCredentialToken({ url: ADOBE_TOKEN_URL, clientId: this.config.clientId,
      clientSecret: this.config.clientSecret, scope: ADOBE_SCOPE, fetchImpl, stage: 'adobe_token' });
    else this.tokens = { get: async () => this.config.accessToken, clear() {} };
  }
  async inspect(signal) {
    const controller = new AbortController(); const abort = () => controller.abort();
    signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
    const timer = setTimeout(abort, 20000);
    try {
      const config = this.config;
      let request;
      switch (config.provider) {
        case 'google-workspace': request = { operation: 'google.licenseAssignments', customerId: config.customerId, productId: config.productId, skuId: config.skuId }; break;
        case 'github-copilot': request = { operation: 'github.copilotSeats', organization: config.organization }; break;
        case 'adobe-enterprise': request = { operation: 'adobe.profileMembers', clientId: config.clientId, organizationId: config.organizationId, profileId: config.profileId, profileName: config.profileName }; break;
        case 'slack-scim': request = { operation: 'slack.users', directoryKind: config.directoryKind, directoryId: config.directoryId }; break;
        case 'atlassian-cloud': request = { operation: 'atlassian.directoryUsers', organizationId: config.organizationId, directoryId: config.directoryId }; break;
        case 'gitlab-cloud': request = { operation: 'gitlab.billableMembers', groupId: config.groupId, groupPath: config.groupPath }; break;
      }
      request.accessToken = await this.tokens.get(controller.signal);
      return snapshot(await runConnector({ binary: this.binary, spawnImpl: this.spawnImpl, request, signal: controller.signal,
        stage: STAGES[config.provider], field: 'snapshot' }), config);
    } catch (error) { this.tokens.clear(); throw error; }
    finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
  }
}

module.exports = { ProviderReadClient, snapshot, GOOGLE_SCOPE, GOOGLE_TOKEN_URL, ADOBE_TOKEN_URL, ADOBE_SCOPE };
