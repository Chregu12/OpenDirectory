'use strict';

const { randomUUID }=require('node:crypto');const fs=require('node:fs');const path=require('node:path');
const {createRequire}=require('node:module');const deviceRequire=createRequire(path.join(__dirname,'../../services/core/device-service/package.json'));const {Pool}=deviceRequire('pg');
async function deviceInventoryFixture(connectionString,identityBase){
  const schema='device_inventory_'+randomUUID().replaceAll('-','');const administration=new Pool({connectionString,max:1});await administration.query('CREATE SCHEMA '+schema);
  const pool=new Pool({connectionString,max:5,options:`-c search_path=${schema},public`});
  const migrations=path.join(__dirname,'../../services/core/device-service/migrations');
  for(const filename of fs.readdirSync(migrations).filter(filename=>filename.endsWith('.sql')).sort())await pool.query(fs.readFileSync(path.join(migrations,filename),'utf8'));
  const db={pool,isAvailable:()=>true,query:(...args)=>pool.query(...args),healthCheck:async()=>{await pool.query('SELECT 1');return{status:'healthy'};},transaction:async(operation,options={})=>{
    const client=await pool.connect();try{await client.query(options.readOnly?'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY':'BEGIN');const result=await operation(client);if(options.beforeCommit)await options.beforeCommit(client);await client.query('COMMIT');return result;}
    catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
  }};
  const {InventoryAuthority}=require('../../services/core/device-service/src/InventoryAuthority');const {DeviceInventory}=require('../../services/core/device-service/src/DeviceInventory');
  const inventory=new DeviceInventory(db,{authority:new InventoryAuthority({endpoint:identityBase+'/api/identity/device-inventory'})});
  const server=require('../../services/core/device-service/src/inventoryServer').createInventoryApp({db,inventory}).listen(0,'127.0.0.1');
  await new Promise((resolve,reject)=>{server.once('listening',resolve);server.once('error',reject);});
  return{db,base:'http://127.0.0.1:'+server.address().port,async close(){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));await pool.end();await administration.query('DROP SCHEMA '+schema+' CASCADE');await administration.end();}};
}
module.exports={deviceInventoryFixture};
