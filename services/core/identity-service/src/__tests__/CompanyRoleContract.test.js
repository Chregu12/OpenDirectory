'use strict';
const C=require('../CompanyRoleContract');const {randomUUID}=require('node:crypto');
const input={name:'Profile operator',description:'Scoped role',permissions:['users.update','users.read'],maxDurationSeconds:3600,reason:'Explicit original company role decision',confirm:true};
test('canonical definitions normalize text and retain only bounded directory actions',()=>{expect(C.definition({...input,name:'  Profile operator  '},true)).toMatchObject({name:'Profile operator',permissions:['users.read','users.update'],enabled:true});});
test.each([{permissions:['identities.roles.manage']},{permissions:['users.read','users.read']},{maxDurationSeconds:36001},{confirm:false},{extra:'override'},{name:'\u0000hidden'}])('invalid or escalating definitions are rejected (%j)',change=>{expect(()=>C.definition({...input,...change},true)).toThrow();});
test('strong role and grant revisions preserve exact PostgreSQL BIGINT values',()=>{const id=randomUUID();const value={id,revision:'9223372036854775807'};expect(C.expected('role',C.etag('role',value),id)).toBe(value.revision);expect(()=>C.expected('grant',C.etag('role',value),id)).toThrow();expect(()=>C.expected('role',undefined,id)).toThrow(expect.objectContaining({status:428}));});
test.each([{targetType:'application'},{scopeType:'tenant',ouId:randomUUID()},{scopeType:'ou',ouId:null},{durationSeconds:36001},{confirm:false},{reason:'short'}])('assignment fields and explicit consent cannot be widened (%j)',change=>{expect(()=>C.assignment({targetType:'user',targetId:randomUUID(),scopeType:'tenant',ouId:null,durationSeconds:3600,reason:input.reason,confirm:true,...change})).toThrow();});
test('protected groups require exact human fields and bounded names',()=>{expect(()=>C.group({name:'g',description:'',reason:input.reason,confirm:true})).toThrow();expect(()=>C.group({name:'Group',description:'',reason:input.reason,confirm:true,roleAssignable:false})).toThrow();});
test('five device duties are explicit additions and do not change the OU action catalog',()=>{expect(C.PERMISSIONS).toHaveLength(19);expect(C.OU_PERMISSIONS).toEqual(['users.read','users.update','users.status.manage']);expect(C.definition({...input,permissions:C.DEVICE_PERMISSIONS},true).permissions).toHaveLength(5);});
test.each(['devices.inventory.create','devices.inventory.assign','devices.compliance.manage'])('device write duty %s needs its separately selected read duty',permission=>{expect(()=>C.definition({...input,permissions:[permission]},true)).toThrow(expect.objectContaining({code:'device_role_read_permission_required'}));});
test('device OU scope is distinct from user OU and excludes tenant policy management',()=>{
 const assignment={targetType:'user',targetId:randomUUID(),scopeType:'device-ou',ouId:randomUUID(),durationSeconds:3600,reason:input.reason,confirm:true};
 expect(C.assignment(assignment).scopeType).toBe('device-ou');
 const {durationSeconds,...fields}=assignment;expect(C.eligibility({...fields,validForSeconds:86400}).scopeType).toBe('device-ou');
 expect(C.DEVICE_OU_PERMISSIONS).toEqual(['devices.inventory.read','devices.inventory.create','devices.inventory.assign','devices.compliance.read']);
});
test.each([null,'','A0000000-0000-4000-8000-000000000000'])('device OU scope requires an exact canonical OU: %j',ouId=>{
 expect(()=>C.assignment({targetType:'user',targetId:randomUUID(),scopeType:'device-ou',ouId,durationSeconds:3600,reason:input.reason,confirm:true})).toThrow();
});
