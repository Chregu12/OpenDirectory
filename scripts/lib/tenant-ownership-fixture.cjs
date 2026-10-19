'use strict';

const {randomUUID}=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const scripts=path.join(__dirname,'../../services/core/identity-service/scripts');
async function connection(database){return database.getClient?database.getClient():database.pool?database.pool.connect():database.connect();}
async function tenantScript(database,schema,filename,values){
 if(!/^[a-z0-9_]+$/.test(schema))throw new Error('Explicit owned fixture schema required');
 let sql=fs.readFileSync(path.join(scripts,filename),'utf8').replaceAll(':"identity_schema"',`"${schema}"`);
 for(const[key,value]of Object.entries(values))sql=sql.replaceAll(":'"+key+"'","'"+String(value).replaceAll("'","''")+"'");
 const client=await connection(database);try{return await client.query(sql);}catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
}
async function provisionTenant(database,schema,{id=randomUUID(),enabled=false}={}){
 await tenantScript(database,schema,'tenant-provision.sql',{tenant_id:id,external_key:'owned-'+id,display_name:'Explicit owned tenant fixture',reason:'Explicit reviewed isolated canonical tenant fixture'});
 if(enabled)await enableTenant(database,schema,id,true);
 return id;
}
async function enableTenant(database,schema,id,enabled,expectedVersion){
 const current=(await database.query('SELECT version FROM identity_tenants WHERE id=$1',[id])).rows[0];
 await tenantScript(database,schema,'tenant-enablement.sql',{tenant_id:id,expected_version:expectedVersion??current?.version,enabled,reason:'Explicit reviewed tenant lifecycle fixture transition'});
 return(await database.query('SELECT * FROM identity_tenants WHERE id=$1',[id])).rows[0];
}
async function adoptTenant(database,schema,id,manifest,expectedVersion){
 const current=(await database.query('SELECT version FROM identity_tenants WHERE id=$1',[id])).rows[0];
 return tenantScript(database,schema,'tenant-adopt.sql',{tenant_id:id,expected_version:expectedVersion??current?.version,manifest:JSON.stringify(manifest),reason:'Explicit reviewed canonical ownership manifest fixture'});
}
async function installTenantFixture(database,schema,{userTenants={}}={}){
 const defaultTenantId=await provisionTenant(database,schema,{enabled:true});
 for(const tenantId of new Set(Object.values(userTenants)))await provisionTenant(database,schema,{id:tenantId,enabled:true});
 let choices='';for(const[userId,tenantId]of Object.entries(userTenants)){
  if(!/^[a-f0-9-]{36}$/.test(userId)||!/^[a-f0-9-]{36}$/.test(tenantId))throw new Error('Owned canonical fixture UUID required');
  choices+=`WHEN kind='user' AND NEW.id='${userId}'::uuid THEN '${tenantId}'::uuid `;
 }
 const chosen=choices?`CASE ${choices}ELSE '${defaultTenantId}'::uuid END`:`'${defaultTenantId}'::uuid`;
 await database.query(`CREATE FUNCTION owned_fixture_tenant_adoption() RETURNS trigger LANGUAGE plpgsql SET search_path=${schema},pg_catalog,pg_temp AS $$
 DECLARE kind TEXT;tenant UUID;BEGIN
 IF NULLIF(current_setting('opendirectory.directory_creation',true),'') IS NOT NULL OR NULLIF(current_setting('opendirectory.company_registration',true),'') IS NOT NULL THEN RETURN NEW;END IF;
 kind=CASE TG_TABLE_NAME WHEN 'users' THEN 'user' WHEN 'groups' THEN 'group' ELSE 'ou' END;tenant=${chosen};
 IF EXISTS(SELECT 1 FROM identity_tenant_ownership WHERE resource_kind=kind AND resource_id=NEW.id) THEN RETURN NEW;END IF;
 PERFORM set_config('opendirectory.tenant_review','explicit-offline-owner-review',true);PERFORM set_config('opendirectory.tenant_reason','Explicitly reviewed isolated fixture resource allocation',true);
 INSERT INTO identity_tenant_ownership(resource_kind,resource_id,tenant_id,reviewed_version,reason)
 SELECT kind,NEW.id,tenant,version,'Explicitly reviewed isolated fixture resource allocation' FROM identity_tenants WHERE id=tenant;
 RETURN NEW;END;$$;
 CREATE TRIGGER aaa_fixture_tenant_adoption BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION owned_fixture_tenant_adoption();
 CREATE TRIGGER aaa_fixture_tenant_adoption BEFORE INSERT ON groups FOR EACH ROW EXECUTE FUNCTION owned_fixture_tenant_adoption();
 CREATE TRIGGER aaa_fixture_tenant_adoption BEFORE INSERT ON ous FOR EACH ROW EXECUTE FUNCTION owned_fixture_tenant_adoption();`);
 return{defaultTenantId};
}
module.exports={tenantScript,provisionTenant,enableTenant,adoptTenant,installTenantFixture};
