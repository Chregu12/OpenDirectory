'use strict';

const { createHash } = require('node:crypto');
const { ROLES, MFA_LOCKED_ROLES, PROTECTED } = require('../../../../packages/directory-role-contract');
const { validUuid, validRevision } = require('../../../../packages/identity-authorization-contract');
const { validTenantContext } = require('../../../../packages/tenant-authorization-contract');

function unavailable() { throw Object.assign(new Error('owned_authority_plan_unavailable'), { status: 503, code: 'owned_authority_plan_unavailable' }); }
function canonicalUuid(value) { return validUuid(value) && value === value.toLowerCase(); }
function exact(value, keys) { return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function timestamp(value) {
  if (typeof value !== 'string' || !/T.*(?:Z|[+-][0-9]{2}:[0-9]{2})$/.test(value) || !Number.isFinite(Date.parse(value))) unavailable();
  return Date.parse(value);
}
function integer(value, minimum, maximum) { return Number.isInteger(value) && value >= minimum && value <= maximum; }
function reviewers(value) { return Array.isArray(value) && value.length <= 20 && value.every((id, index) => canonicalUuid(id) && (!index || value[index - 1] < id)); }
function digest(value) { return createHash('sha256').update(JSON.stringify(value)).digest('hex'); }
function sourceKey(source) { return source.kind + ':' + source.id; }
function compare(first, second) { return first < second ? -1 : first > second ? 1 : 0; }

function validateProfile(profile) {
  if (!exact(profile, ['role', 'authentication', 'activation', 'review']) || !ROLES.includes(profile.role)) unavailable();
  const { authentication, activation, review } = profile;
  if (!exact(authentication, ['required', 'maxAgeSeconds']) || typeof authentication.required !== 'boolean' || !integer(authentication.maxAgeSeconds, 300, 86400)
    || MFA_LOCKED_ROLES.includes(profile.role) && (!authentication.required || authentication.maxAgeSeconds !== 300)
    || !exact(activation, ['required', 'maxDurationSeconds', 'reviewerUserIds']) || typeof activation.required !== 'boolean'
    || !integer(activation.maxDurationSeconds, 60, 28800) || !reviewers(activation.reviewerUserIds)
    || activation.reviewerUserIds.length && (!activation.required || !PROTECTED.includes(profile.role))
    || profile.role === 'admin' && activation.required && !activation.reviewerUserIds.length
    || profile.role === 'user' && (activation.required || activation.maxDurationSeconds !== 28800 || review !== null)) unavailable();
  if (review !== null && (!exact(review, ['intervalSeconds', 'windowSeconds', 'reviewerUserIds']) || !integer(review.intervalSeconds, 3600, 31536000)
    || !integer(review.windowSeconds, 60, Math.min(604800, review.intervalSeconds - 1)) || !reviewers(review.reviewerUserIds) || !review.reviewerUserIds.length)) unavailable();
  return profile;
}

function resolveOwnedAuthorityPlan(snapshot, now = Date.now()) {
  if (!Number.isFinite(now) || !exact(snapshot, ['schemaVersion', 'canAuthorize', 'candidateId', 'tenant', 'issuer', 'manifestSha256', 'inventorySha256', 'validUntil', 'manifest', 'inventory'])
    || snapshot.schemaVersion !== 1 || snapshot.canAuthorize !== false || !canonicalUuid(snapshot.candidateId)
    || !exact(snapshot.tenant, ['id', 'version', 'generation', 'enabled'])) unavailable();
  const { manifest, inventory } = snapshot;
  const tenant = { id: snapshot.tenant.id, version: snapshot.tenant.version, generation: snapshot.tenant.generation };
  if (!validTenantContext(tenant) || !canonicalUuid(tenant.id) || snapshot.tenant.enabled !== true || timestamp(snapshot.validUntil) <= now
    || !/^[a-f0-9]{64}$/.test(snapshot.manifestSha256) || !/^[a-f0-9]{64}$/.test(snapshot.inventorySha256)
    || typeof snapshot.issuer !== 'string' || !/^https?:\/\/[^/?#@\s]+(?:[^?#\s]*)$/.test(snapshot.issuer) || snapshot.issuer.length > 2048
    || !exact(manifest, ['schemaVersion', 'tenantId', 'expectedTenantVersion', 'expectedTenantGeneration', 'issuer', 'reviewAnchorUserId', 'inventorySha256', 'policies', 'sources', 'reason'])
    || manifest.schemaVersion !== 1 || manifest.tenantId !== tenant.id || manifest.expectedTenantVersion !== tenant.version || manifest.expectedTenantGeneration !== tenant.generation
    || manifest.issuer !== snapshot.issuer || manifest.inventorySha256 !== snapshot.inventorySha256 || !canonicalUuid(manifest.reviewAnchorUserId)
    || inventory?.schemaVersion !== 1 || inventory.issuer !== snapshot.issuer || inventory.tenant?.id !== tenant.id || inventory.tenant?.version !== tenant.version
    || inventory.tenant?.generation !== tenant.generation || inventory.tenant?.enabled !== true
    || !Array.isArray(manifest.policies) || manifest.policies.length !== ROLES.length || !Array.isArray(manifest.sources) || manifest.sources.length > 1000
    || !Array.isArray(inventory.users) || inventory.users.length > 1000 || !Array.isArray(inventory.sources) || inventory.sources.length !== manifest.sources.length) unavailable();
  const profiles = new Map(manifest.policies.map(profile => [validateProfile(profile).role, profile]));
  if (profiles.size !== ROLES.length || ROLES.some(role => !profiles.has(role))) unavailable();
  const accounts = new Map();
  for (const account of inventory.users) {
    if (!account || !canonicalUuid(account.id) || accounts.has(account.id) || typeof account.enabled !== 'boolean' || typeof account.canonical !== 'boolean'
      || !validRevision(account.authorityRevision) || !validRevision(account.eligibilityRevision) || !validRevision(account.tenantGeneration)
      || !integer(account.linkCount, 0, 1000) || !/^[a-f0-9]{64}$/.test(account.linksSha256)) unavailable();
    accounts.set(account.id, account);
  }
  const anchor = accounts.get(manifest.reviewAnchorUserId);
  if (!anchor?.enabled || !anchor.canonical) unavailable();
  for (const profile of profiles.values()) {
    for (const id of [...profile.activation.reviewerUserIds, ...(profile.review?.reviewerUserIds || [])]) {
      if (id === anchor.id || !accounts.get(id)?.enabled || !accounts.get(id)?.canonical) unavailable();
    }
  }
  const sources = new Map(); const intentions = new Map();
  for (const source of inventory.sources) {
    if (!source || !['assignment', 'eligibility', 'request', 'review'].includes(source.kind) || !canonicalUuid(source.id) || !accounts.has(source.userId) || !profiles.has(source.role)
      || !source.state || source.state.id !== source.id || source.state.user_id !== source.userId || sources.has(sourceKey(source))
      || !/^[a-f0-9]{64}$/.test(source.beforeSha256) || typeof source.live !== 'boolean'
      || !['canonical-home-coherent', 'offline-review-required', 'unresolved', 'foreign'].includes(source.origin)
      || !Array.isArray(source.relatedSources) || source.relatedSources.length > 1000) unavailable();
    sources.set(sourceKey(source), source);
  }
  for (const intention of manifest.sources) {
    if (!intention || !['adopt', 'quarantine'].includes(intention.disposition) || !sources.has(sourceKey(intention)) || intentions.has(sourceKey(intention))
      || Object.keys(intention).some(key => !['kind', 'id', 'disposition', 'acceptOfflineOrigin'].includes(key))) unavailable();
    const source = sources.get(sourceKey(intention));
    if (Object.hasOwn(intention, 'acceptOfflineOrigin') && (intention.acceptOfflineOrigin !== true || intention.disposition !== 'adopt' || source.origin !== 'offline-review-required')) unavailable();
    intentions.set(sourceKey(intention), intention);
  }
  if (intentions.size !== sources.size) unavailable();
  const namespace = { id: snapshot.candidateId, tenant, issuer: snapshot.issuer, manifestSha256: snapshot.manifestSha256, inventorySha256: snapshot.inventorySha256 };
  const assignments = []; const effective = new Map();
  for (const assignment of [...sources.values()].filter(source => source.kind === 'assignment').sort((first, second) => compare(first.id, second.id))) {
    const profile = profiles.get(assignment.role); const component = new Map(); const pending = [assignment]; let issue = null;
    while (pending.length) {
      const source = pending.pop(); if (component.has(sourceKey(source))) continue; component.set(sourceKey(source), source);
      if (source.userId !== assignment.userId || source.role !== assignment.role) { issue = 'incoherent_component'; break; }
      if (intentions.get(sourceKey(source)).disposition !== 'adopt') { issue = 'quarantined_component'; break; }
      if (!source.live || !['canonical-home-coherent', 'offline-review-required'].includes(source.origin)
        || source.origin === 'offline-review-required' && intentions.get(sourceKey(source)).acceptOfflineOrigin !== true) { issue = 'unavailable_component'; break; }
      for (const reference of source.relatedSources) {
        if (!exact(reference, ['kind', 'id']) || !sources.has(sourceKey(reference))) { issue = 'incoherent_component'; break; }
        pending.push(sources.get(sourceKey(reference)));
      }
      if (issue) break;
    }
    const state = assignment.state; const account = accounts.get(assignment.userId);
    if (!issue && (!account.enabled || !account.canonical)) issue = 'recipient_unavailable';
    if (!issue && (state.role !== assignment.role || !validRevision(state.policy_version) || state.revoked_at !== null)) issue = 'assignment_unavailable';
    if (!issue) {
      const created = timestamp(state.created_at); const expires = state.expires_at === null ? Infinity : timestamp(state.expires_at);
      if (expires <= now || created > now || expires <= created) issue = 'assignment_expired';
      else if (assignment.role !== 'user' && (!Number.isFinite(expires) || expires - created > profile.activation.maxDurationSeconds * 1000)) issue = 'duration_requires_new_grant';
    }
    const request = state.activation_request_id === null ? null : sources.get('request:' + state.activation_request_id);
    let eligibility = null;
    if (!issue && profile.activation.required && !request) issue = 'owned_activation_required';
    if (!issue && state.activation_request_id !== null) {
      eligibility = request && sources.get('eligibility:' + request.state.eligibility_id);
      if (!request || !eligibility || !component.has(sourceKey(request)) || !component.has(sourceKey(eligibility))
        || request.state.state !== 'active' || request.state.user_id !== assignment.userId || eligibility.state.user_id !== assignment.userId
        || eligibility.state.role !== assignment.role || eligibility.state.revoked_at !== null || request.state.policy_version !== state.policy_version
        || !integer(request.state.duration_seconds, 60, profile.activation.maxDurationSeconds)
        || !integer(eligibility.state.max_duration_seconds, 60, 28800) || request.state.duration_seconds > eligibility.state.max_duration_seconds) issue = 'owned_activation_unavailable';
      else if (timestamp(eligibility.state.expires_at) <= now || timestamp(state.expires_at) > timestamp(eligibility.state.expires_at)
        || timestamp(state.expires_at) - timestamp(state.created_at) > request.state.duration_seconds * 1000) issue = 'owned_activation_expired';
    }
    if (!issue) {
      for (const target of [assignment, ...(eligibility ? [eligibility] : [])]) {
        const reviews = [...component.values()].filter(source => source.kind === 'review' && source.state.target_kind === target.kind && source.state.target_id === target.id);
        if (reviews.length > 1) { issue = 'incoherent_review'; break; }
        const review = reviews[0];
        if (profile.review && (!review || review.state.state !== 'pending')) { issue = 'owned_review_required'; break; }
        if (review) {
          if (!validRevision(review.state.version) || !validRevision(review.state.cycle) || !canonicalUuid(review.state.policy_id)
            || !['pending', 'exempt'].includes(review.state.state)) { issue = 'owned_review_unavailable'; break; }
          if (review.state.state === 'pending') {
            const due = timestamp(review.state.due_at); const deadline = timestamp(review.state.deadline_at);
            let effectiveDue = due;
            if (profile.review) {
              const previous = inventory.reviewPolicies?.find(policy => policy.id === review.state.policy_id);
              if (!previous || previous.retired !== false || previous.role !== assignment.role || !integer(previous.intervalSeconds, 3600, 31536000)) { issue = 'owned_review_unavailable'; break; }
              const reduction = Math.max(0, previous.intervalSeconds - profile.review.intervalSeconds) * 1000 * Number(BigInt(review.state.cycle) - 1n);
              if (!Number.isSafeInteger(reduction)) { issue = 'owned_review_expired'; break; }
              effectiveDue -= reduction;
            }
            if (deadline <= due || deadline <= now || profile.review && Math.min(deadline, effectiveDue + profile.review.windowSeconds * 1000) <= now) { issue = 'owned_review_expired'; break; }
          } else if (review.state.due_at !== null || review.state.deadline_at !== null) { issue = 'owned_review_unavailable'; break; }
        }
      }
    }
    assignments.push({ id: assignment.id, userId: assignment.userId, role: assignment.role, effectiveInPlan: issue === null, issue });
    if (!issue) {
      if (!effective.has(assignment.userId)) effective.set(assignment.userId, []);
      effective.get(assignment.userId).push({ assignment, component: [...component.values()].sort((first, second) => compare(sourceKey(first), sourceKey(second))) });
    }
  }
  const users = [...accounts.values()].sort((first, second) => compare(first.id, second.id)).map(account => {
    const grants = effective.get(account.id) || []; const proposedRoles = [...new Set(grants.map(grant => grant.assignment.role))].sort();
    const authentication = proposedRoles.map(role => profiles.get(role).authentication).filter(profile => profile.required);
    return { userId: account.id, proposedRoles, authentication: { required: authentication.length > 0, maxAgeSeconds: Math.min(86400, ...authentication.map(profile => profile.maxAgeSeconds)) },
      proposedRolesRevision: digest(['owned-authority-plan-v1', namespace, account.id, account.authorityRevision, account.eligibilityRevision, account.tenantGeneration, account.linksSha256,
        grants.map(grant => grant.component.map(source => [source.kind, source.id, source.beforeSha256])), proposedRoles.map(role => [tenant.id, role, '1', profiles.get(role)])]) };
  });
  return { schemaVersion: 1, canAuthorize: false, namespace, validUntil: snapshot.validUntil, users, assignments };
}

module.exports = { resolveOwnedAuthorityPlan };
