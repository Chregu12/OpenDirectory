'use strict';

const {randomUUID}=require('node:crypto');
class CapacityObserver {
  constructor(database,config,graph){this.database=database;this.config=config;this.graph=graph;this.busy=false;this.controller=null;this.stopped=false;}
  stop(){this.stopped=true;this.controller?.abort();}
  async source(client){
    const row=(await client.query('SELECT license_capacity_source($1) AS source',[this.config.sourceId])).rows[0]?.source;
    if(!row||row.sourceId!==this.config.sourceId||row.connectorId!==this.config.connectorId||row.tenantId!==this.config.tenantId||row.graphClientId!==this.config.graphClientId)throw new Error('capacity_source_binding_required');
    return row;
  }
  async sweep(){
    if(this.busy||this.stopped)return{status:'idle',delay:60};this.busy=true;let client;let locked=false;let id;this.controller=new AbortController();
    try{
      client=await this.database.getClient();locked=(await client.query("SELECT pg_try_advisory_lock(hashtextextended('license-capacity:'||$1,0)) AS locked",[this.config.connectorId])).rows[0].locked;
      if(!locked||this.stopped)return{status:'idle',delay:60};const source=await this.source(client);
      if(!source.sourceEnabled||!source.connectorEnabled)return{status:'paused',delay:60};
      if(source.retryUntil)return{status:'throttled',delay:Math.min(3600,Math.max(60,Math.ceil((Date.parse(source.retryUntil)-Date.now())/1000)))};
      id=randomUUID();await client.query('INSERT INTO license_capacity_runs(id,source_id,source_version,connector_version) VALUES($1,$2,$3,$4)',[id,source.sourceId,source.sourceVersion,source.connectorVersion]);
      try{
        const payload=await this.graph.inspect(this.controller.signal);if(this.stopped)throw new Error('capacity_observer_stopped');
        await client.query("UPDATE license_capacity_runs SET status='complete',payload=$2 WHERE id=$1",[id,JSON.stringify(payload)]);return{status:'complete',runId:id,delay:60};
      }catch(error){
        const code=typeof error.code==='string'&&/^graph_capacity[a-z0-9_]{0,80}$/.test(error.code)?error.code:this.stopped?'capacity_observer_stopped':'capacity_observation_unconfirmed';
        const delay=Number.isInteger(error.retryAfter)?Math.min(3600,Math.max(60,error.retryAfter)):60;
        await client.query("UPDATE license_capacity_runs SET status='failed',error=$2,retry_after=$3 WHERE id=$1",[id,code,delay]);return{status:'failed',runId:id,error:code,delay};
      }
    }finally{
      if(locked)await client.query("SELECT pg_advisory_unlock(hashtextextended('license-capacity:'||$1,0))",[this.config.connectorId]).catch(()=>{});client?.release();this.controller=null;this.busy=false;
    }
  }
}
async function assertCapacityDatabase(database){
  const state=(await database.query(`SELECT rolsuper,rolcreaterole,rolcreatedb,rolbypassrls,current_user<>session_user AS assumed_role,
    EXISTS(SELECT 1 FROM pg_auth_members WHERE member=pg_roles.oid) AS membership FROM pg_roles WHERE rolname=current_user`)).rows[0];
  if(!state||Object.values(state).some(value=>value!==false))throw new Error('Dedicated nonadministrative capacity collector required');
  if((await database.query("SELECT has_schema_privilege(current_user,current_schema(),'CREATE') OR has_database_privilege(current_user,current_database(),'CREATE') AS privileged")).rows[0]?.privileged)throw new Error('Capacity collector must not own or create authority storage');
  const tables=(await database.query("SELECT oid,relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p')")).rows;
  for(const table of tables){
    if(['license_capacity_sources','license_capacity_runs'].includes(table.relname))continue;
    if((await database.query("SELECT has_table_privilege(current_user,$1::oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE') OR has_any_column_privilege(current_user,$1::oid,'SELECT,INSERT,UPDATE') AS privileged",[table.oid])).rows[0].privileged)throw new Error('Capacity collector must not access other authority, user, fulfillment or evidence tables');
  }
  if((await database.query("SELECT has_table_privilege(current_user,'license_capacity_sources','INSERT,UPDATE,DELETE,TRUNCATE') OR has_any_column_privilege(current_user,'license_capacity_sources','INSERT,UPDATE') OR has_table_privilege(current_user,'license_capacity_runs','DELETE,TRUNCATE') AS privileged")).rows[0].privileged)throw new Error('Capacity source configuration and retained runs are protected');
}
module.exports={CapacityObserver,assertCapacityDatabase};
