'use strict';

const {randomUUID}=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const {createRequire}=require('node:module');
const {Pool}=createRequire(path.join(__dirname,'../../services/core/policy-service/package.json'))('pg');
const {CapacityObserver,assertCapacityDatabase}=require('../../services/core/policy-service/src/licenses/fulfillment/CapacityObserver');
const {GraphCapacityClient}=require('../../services/core/policy-service/src/licenses/fulfillment/GraphCapacityClient');
const scripts=path.join(__dirname,'../../services/core/policy-service/scripts');
async function reviewCapacityBudget({database,schema,productId,runId,overrides={}}){
 const previous=(await database.query('SELECT id FROM license_capacity_budgets WHERE product_id=$1 ORDER BY generation DESC LIMIT 1',[productId])).rows[0];
 const current=(await database.query('SELECT version FROM license_provider_products WHERE id=$1',[productId])).rows[0];
 let sql=fs.readFileSync(path.join(scripts,'license-capacity-budget.sql'),'utf8').replaceAll(':"license_schema"',`"${schema}"`);
 for(const[key,value]of Object.entries({license_schema:schema,product_id:productId,previous_budget_id:previous?.id||'',run_id:runId,product_version:String(current.version),reason:'Explicit independent review of external usage and all owned attempts',...overrides}))sql=sql.replaceAll(":'"+key+"'","'"+String(value).replaceAll("'","''")+"'");
 const client=await database.getClient();try{await client.query(sql);}catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
 return(await database.query('SELECT * FROM license_capacity_budgets WHERE product_id=$1 ORDER BY generation DESC LIMIT 1',[productId])).rows[0];
}
async function capacityAdmissionFixture({database,admin,connectionString,schema,connector,product,units=100,consumedUnits=0,review=true,fetchImpl}){
 const role='cap_fixture_'+randomUUID().replaceAll('-','');const password='owned-'+randomUUID();const sourceId=randomUUID();const graphClientId=randomUUID();let limited;
 const sku={skuId:product.skuId,skuPartNumber:'OWNED_ADMISSION',appliesTo:'User',capabilityStatus:'Enabled',prepaidUnits:{enabled:units,warning:0,suspended:0,lockedOut:0},consumedUnits};
 const close=async()=>{await limited?.end();await database.query(`DROP OWNED BY ${role}`);await admin.query(`DROP ROLE ${role}`);};
 await admin.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT PASSWORD '${password}'`);
 try{
  await database.query(fs.readFileSync(path.join(scripts,'license-capacity-grants.sql'),'utf8').replaceAll(':"license_schema"',`"${schema}"`).replaceAll(':"collector_role"',`"${role}"`));
  const setup=await database.getClient();try{await setup.query('BEGIN');await setup.query("SELECT set_config('opendirectory.capacity_source_reason','Explicitly reviewed owned capacity fixture source',true)");await setup.query('INSERT INTO license_capacity_sources(id,connector_id,database_role,graph_client_id) VALUES($1,$2,$3,$4)',[sourceId,connector.id,role,graphClientId]);await setup.query('UPDATE license_capacity_sources SET enabled=true,version=version+1 WHERE id=$1',[sourceId]);await setup.query('COMMIT');}catch(error){await setup.query('ROLLBACK');throw error;}finally{setup.release();}
  const address=new URL(connectionString);address.username=role;address.password=password;address.searchParams.set('options',`-c search_path=${schema},public`);limited=new Pool({connectionString:address.toString(),max:2});
  const restricted={query:(...args)=>limited.query(...args),getClient:()=>limited.connect()};await assertCapacityDatabase(restricted);
  const graph=new GraphCapacityClient({tenantId:connector.tenantId,clientId:graphClientId,clientSecret:'owned-capacity-fixture-secret',fetchImpl:fetchImpl||(async(url)=>Response.json(String(url).includes('/token')?{token_type:'Bearer',access_token:'owned-read-only-capacity',expires_in:3600}:{value:[sku]}))});
  const observer=new CapacityObserver(restricted,{sourceId,connectorId:connector.id,tenantId:connector.tenantId,graphClientId},graph);
  const capture=()=>observer.sweep();
  const approve=async(overrides={})=>{
   const run=(await limited.query('SELECT id FROM license_capacity_runs WHERE source_id=$1 ORDER BY run_number DESC LIMIT 1',[sourceId])).rows[0];
   return reviewCapacityBudget({database,schema,productId:product.id,runId:run?.id,overrides});
  };
  if(review){const result=await capture();if(result.status!=='complete')throw new Error('Owned capacity capture failed');await approve();}
  return{sku,sourceId,role,restricted,capture,approve,close};
 }catch(error){await close();throw error;}
}
module.exports={capacityAdmissionFixture,reviewCapacityBudget};
