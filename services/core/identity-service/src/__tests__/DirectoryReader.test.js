'use strict';

const crypto = require('crypto');
let mockState;
jest.mock('../AuthorizationState',()=>({AuthorizationState:jest.fn(()=>({state:jest.fn(async()=>mockState)}))}));
const { DirectoryReader } = require('../DirectoryReader');
const tenant={id:crypto.randomUUID(),version:'1',generation:'2'};
const context={userId:crypto.randomUUID(),revision:'3',linkRevision:'4',rolesRevision:'a'.repeat(64)};
const user={iss:'https://reader.test',sub:'original',actor_type:'user',roles:['admin'],identity_authorization:context,exp:Math.floor(Date.now()/1000)+300};
let database;let verify;let reader;
beforeEach(()=>{
 mockState={active:true,context,tenant,authentication:{required:false,maxAgeSeconds:86400}};
 database={isAvailable:jest.fn(()=>true),query:jest.fn(async sql=>({rows:sql.startsWith('SELECT COUNT')?[{count:'1'}]:[{id:crypto.randomUUID(),username:'Owned profile',email:'owned@test.invalid',record_revision:'1',enabled:true}]})),transaction:jest.fn(operation=>operation(database))};
 verify=jest.fn(async()=>tenant);reader=new DirectoryReader(database,{issuer:user.iss,revalidate:verify});
});
test('SQL counts and pages share one read-only transaction and explicit owner predicates, with fresh original proof on both sides',async()=>{
 const result=await reader.users({search:'literal%'},user,'Bearer original');expect(result.total).toBe(1);expect(result.users[0].username).toBe('Owned profile');
 expect(database.transaction).toHaveBeenCalledWith(expect.any(Function),{readOnly:true});expect(database.query).toHaveBeenCalledWith(expect.stringContaining("identity_tenant_id('user',id)=$3"),['literal%',null,tenant.id]);
 expect(database.query).toHaveBeenCalledWith(expect.stringContaining('LIMIT $4 OFFSET $5'),['literal%',null,tenant.id,25,0]);expect(verify).toHaveBeenCalledTimes(2);for(const call of verify.mock.calls)expect(call).toEqual(['Bearer original',user]);
});
test.each([{actor_type:'application'},{identity_authorization:undefined},{iss:'https://foreign.test'},{roles:['user']}])('a workload, unbound origin or ordinary role cannot select a directory tenant: %j',async change=>{
 await expect(reader.users({}, {...user,...change},'Bearer original')).rejects.toMatchObject({status:403});expect(verify).not.toHaveBeenCalled();expect(database.query).not.toHaveBeenCalled();
});
test.each([{active:false},{context:{...context,revision:'9'}},{tenant:{...tenant,generation:'8'}},{authentication:{required:true,maxAgeSeconds:300}}])('local canonical authority must still match the original signed origin: %j',async change=>{
 mockState={...mockState,...change};await expect(reader.users({},user,'Bearer original')).rejects.toMatchObject({status:401});expect(database.query).not.toHaveBeenCalled();
});
test('durable storage is mandatory and an unavailable source never becomes an unpartitioned memory fallback',async()=>{
 database.isAvailable.mockReturnValue(false);await expect(reader.users({},user,'Bearer original')).rejects.toMatchObject({status:503});expect(verify).not.toHaveBeenCalled();
});
test.each([401,503])('a final original-token rejection or outage (%i) discards a completed SQL result',async status=>{
 verify.mockResolvedValueOnce(tenant).mockRejectedValueOnce(Object.assign(new Error('Original authority lost'),{status}));await expect(reader.users({},user,'Bearer original')).rejects.toMatchObject({status});expect(database.query).toHaveBeenCalledTimes(2);
});
test('a final tenant generation switch cannot be accepted as fresh scope',async()=>{
 verify.mockResolvedValueOnce(tenant).mockResolvedValueOnce({...tenant,generation:'8'});await expect(reader.users({},user,'Bearer original')).rejects.toMatchObject({status:401});
});
test('physical original-token expiry is checked again even if a misbehaving authority fixture repeats an old positive response',async()=>{
 await expect(reader.users({}, {...user,exp:Date.now()/1000-1},'Bearer original')).rejects.toMatchObject({status:401});
});
test('foreign or absent detail rows have no fallback to a globally available identifier',async()=>{
 database.query.mockResolvedValue({rows:[]});for(const method of['user','group','ou','roles'])await expect(reader[method](crypto.randomUUID(),{},user,'Bearer original')).rejects.toMatchObject({status:404});
});
test('oversized collections are rejected rather than silently reported as complete',async()=>{
 database.query.mockResolvedValue({rows:Array.from({length:10001},()=>({id:crypto.randomUUID()}))});await expect(reader.groups({},user,'Bearer original')).rejects.toMatchObject({status:503});
});
test('unsupported tree depth is rejected without overflowing a recursive serializer',async()=>{
 const rows=Array.from({length:257},()=>({id:crypto.randomUUID(),coherent_parent:true,coherent_members:true,member_count:0}));for(let index=1;index<rows.length;index++)rows[index].parent_id=rows[index-1].id;database.query.mockResolvedValue({rows});
 await expect(reader.ous({},user,'Bearer original')).rejects.toMatchObject({status:503});
});
test.each([{tenantId:tenant.id},{filter:'(objectClass=*)'},{scope:'sub'}])('ignored selectors never choose or silently widen a directory view: %j',async query=>{
 await expect(reader.search(query,user,'Bearer original')).rejects.toMatchObject({status:400});expect(verify).not.toHaveBeenCalled();
});
