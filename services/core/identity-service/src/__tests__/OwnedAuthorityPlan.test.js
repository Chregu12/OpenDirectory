'use strict';

const { resolveOwnedAuthorityPlan } = require('../OwnedAuthorityPlan');
const { ROLES, MFA_LOCKED_ROLES } = require('../../../../../packages/directory-role-contract');
const ids = ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222', '33333333-3333-4333-8333-333333333333',
  '44444444-4444-4444-8444-444444444444', '55555555-5555-4555-8555-555555555555', '66666666-6666-4666-8666-666666666666', '77777777-7777-4777-8777-777777777777'];
const now = Date.parse('2026-10-19T12:00:00.000Z');
const iso = offset => new Date(now + offset).toISOString();
function fixture() {
  const tenant = { id: ids[0], version: '9007199254740993', generation: '9007199254740995', enabled: true };
  const account = { id: ids[1], enabled: true, canonical: true, authorityRevision: '1', eligibilityRevision: '1', tenantGeneration: '9007199254740997', linkCount: 1, linksSha256: 'a'.repeat(64) };
  const assignment = { kind: 'assignment', id: ids[3], userId: account.id, role: 'license-manager', origin: 'canonical-home-coherent', live: true, beforeSha256: 'b'.repeat(64), relatedSources: [],
    state: { id: ids[3], user_id: account.id, role: 'license-manager', created_at: iso(-30000), expires_at: iso(270000), revoked_at: null, policy_version: '9007199254740999', activation_request_id: null } };
  const inventory = { schemaVersion: 1, tenant, issuer: 'https://owned-source.test', users: [account], sources: [assignment], reviewPolicies: [] };
  const manifest = { schemaVersion: 1, tenantId: tenant.id, expectedTenantVersion: tenant.version, expectedTenantGeneration: tenant.generation, issuer: inventory.issuer, reviewAnchorUserId: account.id,
    inventorySha256: 'c'.repeat(64), policies: ROLES.map(role => ({ role, authentication: { required: MFA_LOCKED_ROLES.includes(role), maxAgeSeconds: MFA_LOCKED_ROLES.includes(role) ? 300 : 3600 },
      activation: { required: false, maxDurationSeconds: 28800, reviewerUserIds: [] }, review: null })), sources: [{ kind: assignment.kind, id: assignment.id, disposition: 'adopt' }], reason: 'Explicit non-authorizing isolated source plan fixture' };
  return { schemaVersion: 1, canAuthorize: false, candidateId: ids[2], tenant, issuer: inventory.issuer, manifestSha256: 'd'.repeat(64), inventorySha256: manifest.inventorySha256, validUntil: iso(270000), manifest, inventory };
}
function addSource(snapshot, source) { snapshot.inventory.sources.push(source); snapshot.manifest.sources.push({ kind: source.kind, id: source.id, disposition: 'adopt' }); }
function pim(snapshot) {
  const assignment = snapshot.inventory.sources[0]; assignment.state.activation_request_id = ids[4]; assignment.relatedSources = [{ kind: 'request', id: ids[4] }];
  addSource(snapshot, { kind: 'request', id: ids[4], userId: ids[1], role: assignment.role, origin: 'canonical-home-coherent', live: true, beforeSha256: 'e'.repeat(64),
    relatedSources: [{ kind: 'assignment', id: ids[3] }, { kind: 'eligibility', id: ids[5] }], state: { id: ids[4], user_id: ids[1], eligibility_id: ids[5], state: 'active', policy_version: assignment.state.policy_version, duration_seconds: 300 } });
  addSource(snapshot, { kind: 'eligibility', id: ids[5], userId: ids[1], role: assignment.role, origin: 'canonical-home-coherent', live: true, beforeSha256: 'f'.repeat(64), relatedSources: [],
    state: { id: ids[5], user_id: ids[1], role: assignment.role, revoked_at: null, expires_at: iso(3600000), max_duration_seconds: 300 } });
}
function review(snapshot) {
  const assignment = snapshot.inventory.sources[0]; assignment.relatedSources.push({ kind: 'review', id: ids[6] });
  snapshot.inventory.users.push({ ...snapshot.inventory.users[0], id: ids[4] });
  snapshot.manifest.policies.find(profile => profile.role === assignment.role).review = { intervalSeconds: 3600, windowSeconds: 60, reviewerUserIds: [ids[4]] };
  snapshot.inventory.reviewPolicies.push({ id: ids[5], role: assignment.role, intervalSeconds: 3600, windowSeconds: 60, retired: false });
  addSource(snapshot, { kind: 'review', id: ids[6], userId: ids[1], role: assignment.role, origin: 'canonical-home-coherent', live: true, beforeSha256: 'e'.repeat(64), relatedSources: [{ kind: 'assignment', id: assignment.id }],
    state: { id: ids[6], user_id: ids[1], policy_id: ids[5], target_kind: 'assignment', target_id: assignment.id, state: 'pending', version: '9007199254740993', cycle: '1', due_at: iso(-30000), deadline_at: iso(30000) } });
}
const plan = snapshot => resolveOwnedAuthorityPlan(snapshot, now);
const role = snapshot => plan(snapshot).users.find(account => account.userId === ids[1]).proposedRoles;
test('owner-bound candidate roles are an explicitly non-authorizing plan with namespace-bound policy/source revisions', () => {
  const snapshot = fixture(); const result = plan(snapshot);
  expect(result.canAuthorize).toBe(false); expect(result.namespace.tenant).toEqual({ id: ids[0], version: '9007199254740993', generation: '9007199254740995' });
  expect(role(snapshot)).toEqual(['license-manager']); expect(result.users[0].proposedRolesRevision).toMatch(/^[a-f0-9]{64}$/);
  expect(result.users[0].authentication).toEqual({ required: false, maxAgeSeconds: 86400 }); expect(result).not.toHaveProperty('context'); expect(result).not.toHaveProperty('active'); expect(result.users[0]).not.toHaveProperty('roles');
});
test.each([snapshot => { snapshot.canAuthorize = true; }, snapshot => { snapshot.schemaVersion = 6; }, snapshot => { delete snapshot.tenant; }, snapshot => { snapshot.tenant.version = 1; },
  snapshot => { snapshot.manifest.expectedTenantGeneration = '1'; }, snapshot => { snapshot.manifest.issuer = 'https://foreign.test'; }, snapshot => { snapshot.inventory = null; },
  snapshot => { snapshot.manifest.policies.pop(); }, snapshot => { snapshot.manifest.policies[0] = snapshot.manifest.policies[1]; }, snapshot => { snapshot.validUntil = iso(0); },
  snapshot => { snapshot.manifest.inventorySha256 = 'other'; }, snapshot => { snapshot.inventory.users[0].authorityRevision = '01'; }, snapshot => { snapshot.inventory.users[0].linksSha256 = 'unknown'; },
  snapshot => { snapshot.manifest.sources.push(snapshot.manifest.sources[0]); }])('malformed, stale or unowned namespace data has no global fallback (%#)', change => {
  const snapshot = fixture(); change(snapshot); expect(() => plan(snapshot)).toThrow('owned_authority_plan_unavailable');
});
test.each(['unresolved', 'foreign', 'offline-review-required'])('a %s source cannot silently become an effective owned plan', origin => {
  const snapshot = fixture(); snapshot.inventory.sources[0].origin = origin; expect(role(snapshot)).toEqual([]);
  if (origin === 'offline-review-required') { snapshot.manifest.sources[0].acceptOfflineOrigin = true; expect(role(snapshot)).toEqual(['license-manager']); }
});
test('quarantine and actual recipient unavailability do not acquire roles from a familiar global catalog name', () => {
  const snapshot = fixture(); snapshot.manifest.sources[0].disposition = 'quarantine'; expect(role(snapshot)).toEqual([]);
  snapshot.manifest.sources[0].disposition = 'adopt'; snapshot.inventory.sources[0].live = false; expect(role(snapshot)).toEqual([]);
  snapshot.inventory.sources[0].live = true; snapshot.inventory.users[0].canonical = false; expect(() => plan(snapshot)).toThrow();
});
test('the exact owned MFA policy is aggregated and fixed protected duties cannot weaken', () => {
  const snapshot = fixture(); snapshot.manifest.policies.find(profile => profile.role === 'license-manager').authentication = { required: true, maxAgeSeconds: 600 };
  expect(plan(snapshot).users[0].authentication).toEqual({ required: true, maxAgeSeconds: 600 });
  snapshot.manifest.policies.find(profile => profile.role === 'license-delegate').authentication.required = false; expect(() => plan(snapshot)).toThrow();
});
test('new mandatory activation and reduced duration do not relabel legacy direct or unbounded grants as compliant', () => {
  const snapshot = fixture(); const profile = snapshot.manifest.policies.find(profile => profile.role === 'license-manager'); profile.activation.required = true;
  expect(plan(snapshot).assignments[0].issue).toBe('owned_activation_required'); profile.activation.required = false; profile.activation.maxDurationSeconds = 60;
  expect(plan(snapshot).assignments[0].issue).toBe('duration_requires_new_grant'); profile.activation.maxDurationSeconds = 28800; snapshot.inventory.sources[0].state.expires_at = null;
  expect(plan(snapshot).assignments[0].issue).toBe('duration_requires_new_grant');
});
test('only the complete coherent already-active PIM component satisfies mandatory owned activation', () => {
  const snapshot = fixture(); pim(snapshot); snapshot.manifest.policies.find(profile => profile.role === 'license-manager').activation.required = true;
  expect(role(snapshot)).toEqual(['license-manager']);
  for (const state of ['pending', 'approved', 'revoked']) { snapshot.inventory.sources[1].state.state = state; expect(role(snapshot)).toEqual([]); }
  snapshot.inventory.sources[1].state.state = 'active'; snapshot.manifest.sources[2].disposition = 'quarantine'; expect(role(snapshot)).toEqual([]);
});
test.each([snapshot => { snapshot.inventory.sources[1].state.eligibility_id = ids[0]; }, snapshot => { snapshot.inventory.sources[1].state.policy_version = '1'; },
  snapshot => { snapshot.inventory.sources[2].state.expires_at = iso(-1); }, snapshot => { snapshot.inventory.sources[2].state.revoked_at = iso(-1); },
  snapshot => { snapshot.inventory.sources[2].userId = ids[4]; snapshot.inventory.users.push({ ...snapshot.inventory.users[0], id: ids[4] }); snapshot.inventory.sources[2].state.user_id = ids[4]; },
  snapshot => { snapshot.inventory.sources[1].relatedSources.pop(); }])('incomplete, expired and coherently foreign PIM branches remain negative (%#)', change => {
  const snapshot = fixture(); pim(snapshot); change(snapshot); expect(role(snapshot)).toEqual([]);
});
test('a new recurring rule requires a real retained lease and never invents first approval or resets its cutoff', () => {
  const snapshot = fixture(); review(snapshot); expect(role(snapshot)).toEqual(['license-manager']);
  snapshot.inventory.sources[1].state.deadline_at = iso(-1); expect(plan(snapshot).assignments[0].issue).toBe('owned_review_expired');
  snapshot.inventory.sources[1].state.deadline_at = iso(30000); snapshot.inventory.sources[0].relatedSources = []; expect(plan(snapshot).assignments[0].issue).toBe('owned_review_required');
});
test('tighter windows and recurrence use the retained original schedule, not the plan observation time', () => {
  const snapshot = fixture(); review(snapshot); const lease = snapshot.inventory.sources[1].state;
  lease.due_at = iso(-70000); lease.deadline_at = iso(30000); expect(plan(snapshot).assignments[0].issue).toBe('owned_review_expired');
  lease.due_at = iso(3600000); lease.deadline_at = iso(3660000); lease.cycle = '3'; snapshot.inventory.reviewPolicies[0].intervalSeconds = 7200;
  expect(plan(snapshot).assignments[0].issue).toBe('owned_review_expired');
  lease.cycle = '9223372036854775807'; expect(plan(snapshot).assignments[0].issue).toBe('owned_review_expired');
});
test('owner, catalog proposal, policy and source incarnation changes fence planned revisions without changing source identifiers', () => {
  const snapshot = fixture(); const original = plan(snapshot).users[0].proposedRolesRevision;
  for (const change of [value => { value.candidateId = ids[6]; }, value => { value.manifestSha256 = 'e'.repeat(64); }, value => { value.inventory.sources[0].beforeSha256 = 'e'.repeat(64); },
    value => { value.manifest.policies.find(profile => profile.role === 'license-manager').authentication.required = true; }]) {
    const changed = structuredClone(snapshot); change(changed); expect(plan(changed).users[0].proposedRolesRevision).not.toBe(original);
  }
  expect(plan(snapshot).assignments[0].id).toBe(ids[3]);
});
test('physical source expiry is checked again even while an immutable candidate and legacy live flag still exist', () => {
  const snapshot = fixture(); snapshot.inventory.sources[0].state.expires_at = iso(-1); expect(plan(snapshot).assignments[0].issue).toBe('assignment_expired');
  snapshot.inventory.sources[0].state.expires_at = '2026-10-19 12:05:00'; expect(() => plan(snapshot)).toThrow();
});
test('an independently anchored disabled or unbound recipient has no projected positive roles', () => {
  const snapshot = fixture(); snapshot.inventory.users.push({ ...snapshot.inventory.users[0], id: ids[4] }); snapshot.manifest.reviewAnchorUserId = ids[4];
  snapshot.inventory.users[0].enabled = false; expect(role(snapshot)).toEqual([]);
  snapshot.inventory.users[0].enabled = true; snapshot.inventory.users[0].canonical = false; expect(role(snapshot)).toEqual([]);
});
test('source, intent and policy array ordering cannot change canonical planned role revisions', () => {
  const snapshot = fixture(); pim(snapshot); const original = plan(snapshot);
  snapshot.inventory.sources.reverse(); snapshot.manifest.sources.reverse(); snapshot.manifest.policies.reverse(); expect(plan(snapshot)).toEqual(original);
});
test.each([snapshot => { snapshot.inventory.users[0] = null; }, snapshot => { snapshot.inventory.sources[0] = null; }])('invalid canonical graph entries return a bounded authority error (%#)', change => {
  const snapshot = fixture(); change(snapshot); expect(() => plan(snapshot)).toThrow('owned_authority_plan_unavailable');
});
