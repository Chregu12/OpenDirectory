'use strict';

const { readRoleState, validPolicy } = require('../RoleState');
const userId = '11111111-1111-4111-8111-111111111111';
const grant = (extra = {}) => ({ id: userId, role: 'license-delegate', policy_version: '1', activation_version: '1', activation_required: false, activation_request_id: null,
  max_duration_seconds: 3600, review_id: null, review_version: null, eligibility_review_id: null, eligibility_review_version: null, ...extra });
const policy = (role = 'license-delegate', extra = {}) => ({ role, version: '1', mfa_required: role === 'license-delegate', max_age_seconds: role === 'license-delegate' ? 300 : 3600, ...extra });
async function state(grants = [grant()], policies = [policy()], options = { delegateEvidence: true }) {
  const client = { query: jest.fn().mockResolvedValue({ rows: [] }).mockResolvedValueOnce({ rows: grants }).mockResolvedValueOnce({ rows: policies }) }; return readRoleState(client,userId,options);
}
test('delegate evidence is explicitly requested and does not change ordinary issuer role-state shape', async () => {
  expect(Object.keys(await state(undefined,undefined,{})).sort()).toEqual(['authentication','roles','rolesRevision']);
  expect((await state()).delegationRevision).toMatch(/^[a-f0-9]{64}$/);
  expect((await state([],[])).delegationRevision).toBeNull();
});
test('an actual active company owner requires fresh MFA without inventing a global role or changing the ordinary catalog', async () => {
  const client = { query: jest.fn().mockResolvedValueOnce({ rows: [] }).mockResolvedValueOnce({ rows: [] }).mockResolvedValueOnce({ rows: [{ id: userId, tenant_id: userId, valid: true, active: true }] }) };
  const owner = await readRoleState(client, userId); expect(owner.roles).toEqual([]); expect(owner.authentication).toEqual({ required: true, maxAgeSeconds: 300 }); expect(owner.rolesRevision).not.toBe((await state([], [], {})).rolesRevision);
});
test('an owner row with missing actual activation evidence fails closed instead of falling back to ordinary authentication', async () => {
  const client = { query: jest.fn().mockResolvedValueOnce({ rows: [] }).mockResolvedValueOnce({ rows: [] }).mockResolvedValueOnce({ rows: [{ id: userId, valid: false, active: false }] }) };
  await expect(readRoleState(client, userId)).rejects.toMatchObject({ status: 503 });
});
test('an unrelated role or its policy invalidates issuer state but not the delegate-source incarnation', async () => {
  const original = await state(); const changed = await state([grant(),grant({ id: 'other',role: 'user' })],[policy(),policy('user')]);
  expect(changed.rolesRevision).not.toBe(original.rolesRevision); expect(changed.delegationRevision).toBe(original.delegationRevision);
  const policyChange = await state([grant(),grant({ id: 'other',role: 'user' })],[policy(),policy('user',{version:'2'})]);
  expect(policyChange.delegationRevision).toBe(original.delegationRevision);
});
test.each([{ id: 'replacement' }, { policy_version: '2', activation_version: '2' }, { review_id: userId, review_version: '2' }, { eligibility_review_id: userId, eligibility_review_version: '3' }])('delegate grant and review generations cannot revive the original resource lease: %j', async change => {
  expect((await state([grant(change)])).delegationRevision).not.toBe((await state()).delegationRevision);
});
test('delegate authentication policy versions participate independently in source evidence', async () => {
  expect((await state([grant()],[policy('license-delegate',{version:'2'})])).delegationRevision).not.toBe((await state()).delegationRevision);
});
test.each(['license-scope-administrator','license-delegate','license-scope-activation-reviewer','license-scope-policy-administrator','license-delegation-review-administrator','license-delegation-reviewer','group-review-administrator','group-reviewer'])('%s cannot weaken fixed privileged MFA', role => {
  expect(()=>validPolicy(policy(role,{mfa_required:false,max_age_seconds:300}))).toThrow();
  expect(()=>validPolicy(policy(role,{mfa_required:true,max_age_seconds:301}))).toThrow();
  expect(validPolicy(policy(role,{mfa_required:true,max_age_seconds:300})).role).toBe(role);
});
test('scope-reviewer evidence binds only its actual role grants and applicable review/policy origins',async()=>{
 const role='license-scope-activation-reviewer';const held=grant({role});const assurance=policy(role,{mfa_required:true,max_age_seconds:300});const options={scopeReviewerEvidence:true};
 const initial=await state([held],[assurance],options);expect(initial.scopeReviewerRevision).toMatch(/^[a-f0-9]{64}$/);
 const unrelated=await state([held,grant({id:'other',role:'user'})],[assurance,policy('user')],options);expect(unrelated.scopeReviewerRevision).toBe(initial.scopeReviewerRevision);
 expect((await state([{...held,id:'replacement'}],[assurance],options)).scopeReviewerRevision).not.toBe(initial.scopeReviewerRevision);
 expect((await state([{...held,review_id:userId,review_version:'2'}],[assurance],options)).scopeReviewerRevision).not.toBe(initial.scopeReviewerRevision);
 expect((await state([],[],options)).scopeReviewerRevision).toBeNull();
});
test('publication approval requires its explicit role incarnation rather than implicit administrator or author powers',async()=>{
 const role='policy-publication-reviewer';const held=grant({role});const assurance=policy(role,{mfa_required:true,max_age_seconds:300});const options={publicationEvidence:true};
 const original=await state([held],[assurance],options);expect(original.publicationReviewRevision).toMatch(/^[a-f0-9]{64}$/);expect(original.publicationRequestRevision).toBeNull();
 const unrelated=await state([held,grant({id:'unrelated',role:'user'})],[assurance,policy('user')],options);expect(unrelated.publicationReviewRevision).toBe(original.publicationReviewRevision);
 for(const change of [{id:'replacement'},{policy_version:'2',activation_version:'2'},{review_id:userId,review_version:'2'}])expect((await state([{...held,...change}],[assurance],options)).publicationReviewRevision).not.toBe(original.publicationReviewRevision);
 for(const author of ['admin','policy-administrator']){const current=await state([grant({role:author})],[policy(author,{mfa_required:true,max_age_seconds:300})],options);expect(current.publicationReviewRevision).toBeNull();expect(current.publicationRequestRevision).toMatch(/^[a-f0-9]{64}$/);}
 expect(()=>validPolicy(policy(role,{mfa_required:false,max_age_seconds:300}))).toThrow();
});
