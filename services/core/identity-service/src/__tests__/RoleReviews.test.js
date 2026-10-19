'use strict';
const { randomUUID }=require('crypto');
const { RoleReviews,reviewTag }=require('../RoleReviews');
const { getIdentityPermissions }=require('../middleware/identityAccess');
const { PROTECTED,MFA_LOCKED_ROLES }=require('../../../../../packages/directory-role-contract');
function actor(role='access-review-administrator') {
  const userId=randomUUID(); const authTime=Math.floor(Date.now()/1000);
  return { iss:'https://issuer.test',sub:'review-operator',actor_type:'user',roles:[role],identity_authorization:{ userId,revision:'1',linkRevision:'1',rolesRevision:'a'.repeat(64) },
    amr:['pwd','otp'],auth_time:authTime,mfa_authorization:{ schemaVersion:1,userId,revision:'1',authTime,methods:['pwd','otp'] } };
}
const input={ role:'license-manager',intervalSeconds:3600,windowSeconds:60,reviewerUserIds:[randomUUID()],reason:'Independent role review governance',acknowledgeDeadlines:true };
let database; let reviews; let user;
beforeEach(()=>{ user=actor(); database={ transaction:jest.fn(async()=>{ throw new Error('offline'); }) }; reviews=new RoleReviews(database); });
test('review governance and voting are protected fixed-MFA duties with no allocation, approval or profile powers',()=>{
  for(const role of ['access-review-administrator','access-reviewer']) { expect(PROTECTED).toContain(role); expect(MFA_LOCKED_ROLES).toContain(role); }
  expect(getIdentityPermissions(user)).toEqual(['reviews.policies.read','reviews.policies.manage','reviews.all.read']);
  expect(getIdentityPermissions(actor('access-reviewer'))).toEqual(['reviews.assigned.read','reviews.decide']);
  expect(getIdentityPermissions(actor('role-administrator'))).not.toContain('reviews.policies.manage');
  expect(getIdentityPermissions(actor('pim-approver'))).not.toContain('reviews.decide');
});
test.each([{ role:'user' },{ role:'__proto__' },{ intervalSeconds:3599 },{ intervalSeconds:31536001 },{ windowSeconds:59 },{ windowSeconds:3600 },
  { reviewerUserIds:[] },{ reviewerUserIds:['guessed-login'] },{ reviewerUserIds:['AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'] },{ reviewerUserIds:[input.reviewerUserIds[0],input.reviewerUserIds[0]] },
  { reason:'short' },{ reason:'invalid\nreason' },{ acknowledgeDeadlines:false },{ actor:'admin' },{ permissions:['reviews.decide'] }])('policy injection cannot reach persistent authority: %j',async patch=>{
  await expect(reviews.create({ ...input,...patch },user)).rejects.toMatchObject({ status:400 }); expect(database.transaction).not.toHaveBeenCalled();
});
test.each([{ actor_type:'application' },{ identity_authorization:undefined },{ amr:['otp'] },{ mfa_authorization:undefined },{ auth_time:Math.floor(Date.now()/1000)-301 }])('canonical fresh actual MFA cannot be substituted: %j',async patch=>{
  await expect(reviews.create(input,{ ...user,...patch })).rejects.toMatchObject({ status:patch.actor_type || Object.hasOwn(patch,'identity_authorization') ? 403 : 428 }); expect(database.transaction).not.toHaveBeenCalled();
});
test('protected role governance requires a current global administrator and storage never falls back to demo data',async()=>{
  await expect(reviews.create({ ...input,role:'admin' },user)).rejects.toMatchObject({ status:403 });
  await expect(reviews.create(input,user)).rejects.toThrow('offline');
  await expect(reviews.policy('license-manager',user)).rejects.toThrow('offline');
});
test('an unprivileged known-ID lookup is uniformly hidden before it can consume source storage',async()=>{
  await expect(reviews.get(randomUUID(),actor('user'))).rejects.toMatchObject({ status:404,code:'review_not_found' });
  expect(database.transaction).not.toHaveBeenCalled();
});
test('review projection is minimal, named, independent and refuses expired/changed effective sources',()=>{
  const reviewer=actor('access-reviewer'); const now=Date.now();
  const row={ id:randomUUID(),policy_id:randomUUID(),role:'license-manager',target_kind:'assignment',target_id:randomUUID(),user_id:randomUUID(),version:'1',review_policy_version:'1',cycle:'1',
    due_at:new Date(now-1000),deadline_at:new Date(now+59000),source_expires_at:null,state:'pending',policy_retired_at:null,reviewer_user_ids:[reviewer.identity_authorization.userId],
    source_exists:true,user_enabled:true,source_current:true,source_revoked_at:null,source_now:new Date(now),observed_at:new Date(now) };
  expect(reviews.view(row,reviewer)).toMatchObject({ state:'pending',canDecide:true,selfReview:false }); expect(Object.keys(reviews.view(row,reviewer))).toHaveLength(17);
  expect(reviewTag(row)).toBe(`"od-role-review:${row.id}:1:1"`);
  expect(reviews.view({ ...row,review_policy_version:'2',policy_retired_at:new Date(now) },reviewer).policyVersion).toBe('2');
  expect(reviews.view({ ...row,user_id:reviewer.identity_authorization.userId },reviewer)).toMatchObject({ selfReview:true,canDecide:false });
  expect(reviews.view({ ...row,observed_at:new Date(now+60000) },reviewer)).toMatchObject({ state:'expired',canDecide:false });
  expect(reviews.view({ ...row,source_current:false },reviewer)).toMatchObject({ state:'obsolete',canDecide:false });
  expect(()=>reviews.view(row,actor('access-reviewer'))).toThrow();
  expect(reviews.view(row,actor('access-review-reader')).canDecide).toBe(false);
});
