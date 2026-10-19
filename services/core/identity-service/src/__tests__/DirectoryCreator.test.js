'use strict';

const crypto=require('crypto');let mockState;
jest.mock('../AuthorizationState',()=>({AuthorizationState:jest.fn(()=>({state:jest.fn(async()=>mockState)}))}));
const {DirectoryCreator}=require('../DirectoryCreator');
const issuer='https://creator.test';const tenant={id:crypto.randomUUID(),version:'1',generation:'2'};const identity=crypto.randomUUID();
const context={userId:crypto.randomUUID(),revision:'3',linkRevision:'4',rolesRevision:'a'.repeat(64)};
const user={iss:issuer,sub:'original-creator',actor_type:'user',roles:['admin'],identity_authorization:context,exp:Math.floor(Date.now()/1000)+300};
const profile={username:'new-person',email:'new@test.invalid'};let database;let verify;let creator;
beforeEach(()=>{
 mockState={active:true,context,tenant,authentication:{required:false,maxAgeSeconds:86400}};
 database={isAvailable:jest.fn(()=>true),query:jest.fn(async(sql,values)=>{
  if(sql.startsWith('SELECT id,version,generation'))return{rows:[{id:tenant.id,version:'1',generation:'2'}]};
  if(sql.startsWith('SELECT id FROM users'))return{rows:[{id:context.userId}]};
  if(sql.startsWith('SELECT id FROM ous'))return{rows:[{id:values[0]}]};
  if(sql.startsWith('WITH RECURSIVE ancestors'))return{rows:[{id:values[0],parent_id:null}]};
  if(sql.startsWith('SELECT identity_subject_link_role_state'))return{rows:[{state:{original:'Canonical owned role snapshot'}}]};
  if(sql.startsWith('SELECT ownership.resource_id'))return{rows:[{resource_id:identity}]};
  if(sql.startsWith('INSERT INTO users'))return{rows:[{id:values[0],username:values[1],email:values[2],enabled:false,record_revision:'1',created_at:new Date()}]};
  if(sql.startsWith('INSERT INTO groups'))return{rows:[{id:values[0],name:values[1],description:values[2],revision:'1',created_at:new Date()}]};
  if(sql.startsWith('INSERT INTO ous'))return{rows:[{id:values[0],name:values[1],description:values[2],parent_id:values[3],created_at:new Date()}]};
  return{rows:[]};
 }),transaction:jest.fn(operation=>operation(database))};
 verify=jest.fn(async()=>tenant);creator=new DirectoryCreator(database,{issuer,revalidate:verify,newResourceId:()=>identity});
});
test('a new disabled user uses a server UUID and verified-actor transaction, never a default tenant or offline review marker',async()=>{
 const result=await creator.user(profile,user,'Bearer original');expect(result).toMatchObject({...profile,id:identity,enabled:false,revision:'1'});expect(verify).toHaveBeenCalledTimes(3);expect(database.transaction).toHaveBeenCalledWith(expect.any(Function),{actor:user.sub});
 const proofCall=database.query.mock.calls.find(([sql])=>sql.startsWith("SELECT set_config('opendirectory.directory_creation'"));const proof=JSON.parse(proofCall[1][0]);expect(proof).toMatchObject({tenant,context,resource:{kind:'user',id:identity,values:{...profile,enabled:false}}});expect(JSON.stringify(proof)).not.toContain('Bearer');expect(database.query.mock.calls.some(([sql])=>sql.includes('tenant_review'))).toBe(false);
 expect(database.query).toHaveBeenCalledWith(expect.stringContaining('VALUES($1,$2,$3,$4,$5,$6,false)'),[identity,profile.username,profile.email,null,null,null]);expect(database.query).toHaveBeenCalledWith(expect.stringContaining('JOIN identity_tenant_outbox'),expect.any(Array));
});
test('new groups remain empty and same-tenant canonical OU parents are validated after normalization',async()=>{
 expect((await creator.group({name:'  Owned group  '},user,'Bearer original')).members).toEqual([]);const parent=crypto.randomUUID();const ou=await creator.ou({name:'Owned child',parentId:parent.toUpperCase()},user,'Bearer original');expect(ou.parentId).toBe(parent);
 expect(database.query).toHaveBeenCalledWith(expect.stringContaining("identity_tenant_id('ou',id)=$2 FOR KEY SHARE"),[parent,tenant.id]);
});
test.each([{tenantId:tenant.id},{id:identity},{enabled:true},{password:'not-a-credential-service'},{roles:['admin']}])('caller authority or lifecycle fields cannot become user ownership: %j',async fields=>{
 await expect(creator.user({...profile,...fields},user,'Bearer original')).rejects.toMatchObject({status:400});expect(verify).not.toHaveBeenCalled();
});
test.each([{name:'Group',members:[identity]},{name:'Group',tenantId:tenant.id},{name:''},{name:'bad\nname'},{name:'Group',description:'x'.repeat(2001)}])('strict group input has no ignored authority fields: %j',async body=>{
 await expect(creator.group(body,user,'Bearer original')).rejects.toMatchObject({status:400});expect(verify).not.toHaveBeenCalled();
});
test.each([{actor_type:'application'},{identity_authorization:undefined},{iss:'https://foreign.test'},{roles:['directory-reader']}])('an application, unbound/foreign actor or reader cannot manufacture a creation principal: %j',async changed=>{
 await expect(creator.user(profile,{...user,...changed},'Bearer original')).rejects.toMatchObject({status:403});expect(verify).not.toHaveBeenCalled();
});
test('creation has no in-memory/demo storage fallback',async()=>{
 database.isAvailable.mockReturnValue(false);await expect(creator.user(profile,user,'Bearer original')).rejects.toMatchObject({status:503});expect(verify).not.toHaveBeenCalled();
});
test.each([{active:false},{context:{...context,revision:'9'}},{tenant:{...tenant,generation:'9'}},{authentication:{required:true,maxAgeSeconds:300}}])('canonical local creator authority must still match original admission: %j',async changed=>{
 mockState={...mockState,...changed};await expect(creator.user(profile,user,'Bearer original')).rejects.toMatchObject({status:401});expect(database.query.mock.calls.some(([sql])=>sql.startsWith('INSERT'))).toBe(false);
});
test('foreign or absent OU parents are not fetched by unscoped fallback',async()=>{
 const original=database.query.getMockImplementation();database.query.mockImplementation((sql,values)=>sql.startsWith('SELECT id FROM ous')?Promise.resolve({rows:[]}):original(sql,values));
 await expect(creator.ou({name:'Child',parentId:crypto.randomUUID()},user,'Bearer original')).rejects.toMatchObject({status:404});expect(verify).toHaveBeenCalledTimes(1);
});
test('OU creation rejects incoherent, cyclic and excessive parent chains before any resource DML',async()=>{
 const original=database.query.getMockImplementation();const parent=crypto.randomUUID();
 for(const ancestors of[[],[{id:parent,parent_id:parent}],Array.from({length:256},(_,index)=>({id:index===0?parent:String(index),parent_id:index===255?null:String(index+1)}))]){
  database.query.mockImplementation((sql,values)=>sql.startsWith('WITH RECURSIVE ancestors')?Promise.resolve({rows:ancestors}):original(sql,values));
  await expect(creator.ou({name:'Rejected child',parentId:parent},user,'Bearer original')).rejects.toMatchObject({status:ancestors.length===256?409:503});
 }
 expect(database.query.mock.calls.some(([sql])=>sql.startsWith('INSERT'))).toBe(false);
});
test('late revocation after row DML and receiving evidence cannot be reported as successful creation',async()=>{
 verify.mockResolvedValueOnce(tenant).mockResolvedValueOnce(tenant).mockRejectedValueOnce(Object.assign(new Error('Original revoked'),{status:401}));await expect(creator.user(profile,user,'Bearer original')).rejects.toMatchObject({status:401});expect(database.query.mock.calls.some(([sql])=>sql.startsWith('INSERT INTO users'))).toBe(true);
});
test('a down-level or disabled receiver without actual owned creation evidence fails closed',async()=>{
 const original=database.query.getMockImplementation();database.query.mockImplementation((sql,values)=>sql.startsWith('SELECT ownership.resource_id')?Promise.resolve({rows:[]}):original(sql,values));
 await expect(creator.user(profile,user,'Bearer original')).rejects.toMatchObject({status:503});expect(verify).toHaveBeenCalledTimes(2);
});
test('a suppressed insert is not a successful empty receipt',async()=>{
 const original=database.query.getMockImplementation();database.query.mockImplementation((sql,values)=>sql.startsWith('INSERT INTO users')?Promise.resolve({rows:[]}):original(sql,values));await expect(creator.user(profile,user,'Bearer original')).rejects.toMatchObject({status:409});
});
test('expired original assurance cannot install a creation context',async()=>{
 await expect(creator.user(profile,{...user,exp:Date.now()/1000-1},'Bearer original')).rejects.toMatchObject({status:401});expect(database.query.mock.calls.some(([sql])=>sql.startsWith("SELECT set_config('opendirectory.directory_creation'"))).toBe(false);
});
