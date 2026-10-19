'use strict';

const database=require('../src/db/postgres');
const {configuration}=require('../src/licenses/fulfillment/CapacityConfiguration');
const {GraphCapacityClient}=require('../src/licenses/fulfillment/GraphCapacityClient');
const {CapacityObserver,assertCapacityDatabase}=require('../src/licenses/fulfillment/CapacityObserver');
async function main(){
  const config=configuration(process.env.LICENSE_CAPACITY_CONFIG_FILE);if(!process.env.DATABASE_URL)throw new Error('Explicit capacity database identity required');
  await assertCapacityDatabase(database);const graph=new GraphCapacityClient({tenantId:config.tenantId,clientId:config.graphClientId,clientSecret:config.graphClientSecret});const observer=new CapacityObserver(database,config,graph);
  let stopped=false;let wake;const stop=()=>{stopped=true;observer.stop();wake?.();};process.once('SIGTERM',stop);process.once('SIGINT',stop);
  const client=await database.getClient();try{await observer.source(client);}finally{client.release();}
  while(!stopped){let delay=60;try{delay=(await observer.sweep()).delay;}catch{process.stderr.write('Capacity observation unavailable; no inventory or allocation success acknowledged.\n');}
    if(!stopped)await new Promise(resolve=>{const timer=setTimeout(resolve,delay*1000);wake=()=>{clearTimeout(timer);resolve();};});}
  await database.shutdown();
}
if(require.main===module)main().catch(async()=>{process.stderr.write('Capacity observer startup rejected. Check protected file, reviewed source and dedicated database grants.\n');await database.shutdown();process.exitCode=1;});
module.exports={main};
