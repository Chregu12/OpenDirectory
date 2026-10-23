'use strict';
jest.mock('../AuthorityCheckpoint', () => ({ ...jest.requireActual('../AuthorityCheckpoint'), beginAuthorityCheckpoint: jest.fn(async () => async () => {}) }));

const { randomUUID, createHash } = require('crypto');
const { PrivilegedAccessPolicy, activationEtag, validActivationPolicy } = require('../PrivilegedAccessPolicy');
const { getIdentityPermissions } = require('../middleware/identityAccess');
const { ROLES, PROTECTED } = require('../../../../../packages/directory-role-contract');
const { readRoleState } = require('../RoleState');
let database; let store; let row; let user; let revalidate;
const input = { required:true,maxDurationSeconds:600,reason:'Reviewed mandatory activation policy',acknowledgeInvalidation:true };
beforeEach(() => {
  const userId = randomUUID(); const now = Math.floor(Date.now()/1000);
  const grant = { id:randomUUID(),role:'privileged-access-policy-administrator',policy_version:'1',activation_version:'1',activation_required:false,max_duration_seconds:28800 };
  user = { iss:'https://issuer.test',sub:'policy-operator',actor_type:'user',roles:[grant.role],auth_time:now,amr:['pwd','otp'],
    identity_authorization:{ userId,revision:'1',linkRevision:'1',rolesRevision:createHash('sha256').update(JSON.stringify([[[grant.id,grant.role,'1','1']],[[grant.role,'1']]])).digest('hex') },
    mfa_authorization:{ schemaVersion:1,userId,revision:'1',authTime:now,methods:['pwd','otp'] } };
  row = { role:'license-manager',version:'1',activation_required:false,max_duration_seconds:28800,reviewer_user_ids:[] };
  database = { query:jest.fn(async sql => {
    if (sql.includes('FROM users JOIN')) return { rows:[{ id:userId,enabled:true,revision:'1',link_revision:'1' }] };
    if (sql.includes('FROM identity_role_assignments')) return { rows:[grant] };
    if (sql.includes('role=ANY')) return { rows:[{ role:grant.role,version:'1',mfa_required:true,max_age_seconds:300 }] };
    if (sql.startsWith('SELECT *')) return { rows:[{ ...row }] };
    if (sql.startsWith('UPDATE')) { row = { ...row,version:String(BigInt(row.version)+1n),activation_required:input.required,max_duration_seconds:input.maxDurationSeconds }; return { rows:[row] }; }
    return { rows:[] };
  }),transaction:jest.fn(async operation => operation(database)) };
  revalidate = jest.fn(async () => {}); store = new PrivilegedAccessPolicy(database,{ revalidate });
});
test('policy delegation is protected and does not confer roles, eligibility, approval or license permissions', async () => {
  expect(PROTECTED).toContain(user.roles[0]); expect(ROLES).toContain('privileged-access-policy-reader');
  expect(getIdentityPermissions(user)).toEqual(['pim.policies.read','pim.policies.manage']);
  for (const roles of [['pim-administrator'],['pim-approver'],['role-administrator'],['authentication-policy-administrator']]) expect(getIdentityPermissions({ roles })).not.toContain('pim.policies.manage');
  const result = await store.get(row.role,{ ...user,roles:['privileged-access-policy-reader'] });
  expect(result).toMatchObject({ role:row.role,canManage:false,required:false }); expect(Object.keys(result)).toHaveLength(9);
});
test('versioned changes bind the actor, reason and original bearer before and after transactional evidence', async () => {
  expect(await store.change(row.role,activationEtag(row.role,'1'),input,user,'Bearer original')).toMatchObject({ version:'2',required:true,maxDurationSeconds:600 });
  expect(revalidate).toHaveBeenCalledTimes(2); expect(revalidate).toHaveBeenNthCalledWith(2,user,'Bearer original');
  expect(database.transaction).toHaveBeenCalledWith(expect.any(Function),{ actor:JSON.stringify({ issuer:user.iss,subject:user.sub,userId:user.identity_authorization.userId }) });
  expect(database.query).toHaveBeenCalledWith(expect.stringContaining('set_config'),[input.reason]);
  await expect(store.change(row.role,activationEtag(row.role,'1'),input,user,'Bearer original')).rejects.toMatchObject({ status:412 });
});
test.each([{ required:'true' },{ maxDurationSeconds:59 },{ maxDurationSeconds:28801 },{ maxDurationSeconds:'600' },{ acknowledgeInvalidation:false },{ reason:'short' },{ reason:'control\ncharacters' },{ role:'admin' },{ actor:'admin' }])('unreviewed/injected policy fields fail before persistence: %j', async patch => {
  await expect(store.change(row.role,activationEtag(row.role,'1'),{ ...input,...patch },user)).rejects.toMatchObject({ status:400 });
  expect(database.transaction).not.toHaveBeenCalled();
});
test.each([{ actor_type:'workload' },{ identity_authorization:undefined },{ amr:['otp'] },{ mfa_authorization:undefined },{ auth_time:Math.floor(Date.now()/1000)-301 }])('a weak or fabricated principal cannot change policy: %j', async patch => {
  await expect(store.change(row.role,activationEtag(row.role,'1'),input,{ ...user,...patch })).rejects.toMatchObject({ status:patch.actor_type || Object.hasOwn(patch,'identity_authorization') ? 403 : 428 });
});
test('protected roles need a global administrator and the baseline user role cannot become privileged', async () => {
  row.role = 'role-administrator'; await expect(store.change(row.role,activationEtag(row.role,'1'),input,user)).rejects.toMatchObject({ status:403 });
  row.role = 'user'; expect(await store.get(row.role,user)).toMatchObject({ locked:true,canManage:false });
  await expect(store.change(row.role,activationEtag(row.role,'1'),input,{ ...user,roles:['admin'] })).rejects.toMatchObject({ status:409 });
});
test('missing metadata, versions, storage and live session authority never fall back', async () => {
  await expect(store.get('__proto__',user)).rejects.toMatchObject({ status:400 });
  await expect(store.change(row.role,undefined,input,user)).rejects.toMatchObject({ status:428 });
  expect(() => validActivationPolicy({ ...row,max_duration_seconds:0 })).toThrow();
  revalidate.mockRejectedValue(Object.assign(new Error('revoked'),{ status:401 }));
  await expect(store.change(row.role,activationEtag(row.role,'1'),input,user)).rejects.toMatchObject({ status:401 });
  expect(database.query.mock.calls.some(([sql]) => sql.startsWith('UPDATE'))).toBe(false);
});
test('a post-write authority loss rejects the transaction instead of confirming policy', async () => {
  revalidate.mockResolvedValueOnce().mockRejectedValueOnce(Object.assign(new Error('revoked'),{ status:401 }));
  await expect(store.change(row.role,activationEtag(row.role,'1'),input,user)).rejects.toMatchObject({ status:401 });
  expect(database.query.mock.calls.some(([sql]) => sql.startsWith('UPDATE'))).toBe(true);
});
test.each([null,{},['not-a-uuid'],[null],['AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'],Array(21).fill('11111111-1111-4111-8111-111111111111'),['11111111-1111-4111-8111-111111111111','11111111-1111-4111-8111-111111111111']])('invalid or unreviewed named approvers cannot enter policy evidence: %j',async reviewers=>{
  await expect(store.change(row.role,activationEtag(row.role,'1'),{ ...input,reviewerUserIds:reviewers },user)).rejects.toMatchObject({ status:400 });
  expect(database.transaction).not.toHaveBeenCalled();
});
test('global mandatory activation cannot omit independent named reviewers',async()=>{
  await expect(store.change('admin',activationEtag('admin','1'),input,{ ...user,roles:['admin'] })).rejects.toMatchObject({ status:400 });
  expect(database.transaction).not.toHaveBeenCalled();
});
test('role authority rejects absent or malformed activation origins and filters stale/direct-only claims', async () => {
  const grant = { id:randomUUID(),role:'license-manager',policy_version:'1',activation_version:'2',activation_required:true,max_duration_seconds:600 };
  const client = { query:async sql => ({ rows:(sql.includes('FROM identity_company_activations') || sql.includes('FROM identity_employee_enrollments')) ? [] : sql.includes('FROM identity_role_assignments') ? [grant] : [{ role:grant.role,version:'1',mfa_required:false,max_age_seconds:3600 }] }) };
  expect((await readRoleState(client,randomUUID())).roles).toEqual([]);
  grant.policy_version = '2'; expect((await readRoleState(client,randomUUID())).roles).toEqual([]);
  grant.activation_request_id = randomUUID(); expect((await readRoleState(client,randomUUID())).roles).toEqual(['license-manager']);
  delete grant.activation_required; await expect(readRoleState(client,randomUUID())).rejects.toThrow();
});
