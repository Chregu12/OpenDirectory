'use strict';
const fs=require('node:fs');const path=require('node:path');
async function runMigrations(pool,directory=path.join(__dirname,'../migrations')){
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  await client.query("SET LOCAL lock_timeout='5s'");
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended('authentication-migrations:'||current_schema(),0))");
  const files=fs.readdirSync(directory).filter(file=>file.endsWith('.sql')).sort();
  for(const file of files)await client.query(fs.readFileSync(path.join(directory,file),'utf8'));
  await client.query('COMMIT');return files.length;
 }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
 finally{client.release();}
}
module.exports={runMigrations};
