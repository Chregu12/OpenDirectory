'use strict';
const {spawn}=require('node:child_process');const {once}=require('node:events');
const fs=require('node:fs');const os=require('node:os');const path=require('node:path');const net=require('node:net');
const {randomBytes}=require('node:crypto');const {setTimeout:delay}=require('node:timers/promises');
const Redis=require('ioredis');
async function port(){const server=net.createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});const value=server.address().port;await new Promise(resolve=>server.close(resolve));return value;}
async function stop(child){
 if(!child||child.exitCode!==null||child.signalCode!==null)return;
 const exited=once(child,'exit');child.kill('SIGTERM');
 let timer;await Promise.race([exited,new Promise(resolve=>{timer=setTimeout(resolve,2500);})]);clearTimeout(timer);
 if(child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await exited;}
}
async function startAuthenticationService(databaseUrl,useDatabaseUrl=false){
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'auth-runtime-'));const redisPort=await port();const httpPort=await port();const redisUrl='redis://127.0.0.1:'+redisPort+'/9';
 let redisProcess,service,redis;let output='';let startupError;
 const cleanup=async()=>{await stop(service);if(redis)redis.disconnect();await stop(redisProcess);fs.rmSync(directory,{recursive:true,force:true});};
 try{
  redisProcess=spawn(process.env.REDIS_SERVER||'redis-server',['--bind','127.0.0.1','--port',String(redisPort),'--save','','--appendonly','no','--dir',directory],{stdio:'ignore'});redisProcess.on('error',error=>{startupError=error;});
  const redisDeadline=Date.now()+10000;let connected=false;
  while(Date.now()<redisDeadline){
   if(startupError)throw startupError;if(redisProcess.exitCode!==null||redisProcess.signalCode!==null)throw new Error('Disposable Redis exited before readiness');
   redis=new Redis(redisUrl,{lazyConnect:true,retryStrategy:()=>null,connectTimeout:250});redis.on('error',()=>{});
   try{await redis.connect();connected=true;break;}catch{redis.disconnect();await delay(25);}
  }
  if(!connected)throw new Error('Disposable Redis readiness deadline');
  service=spawn(process.execPath,[path.join(__dirname,'../../index.js')],{cwd:directory,stdio:['ignore','pipe','pipe'],env:{...process.env,
   NODE_ENV:'production',PORT:String(httpPort),AUTH_DATABASE_URL:useDatabaseUrl?'':databaseUrl,DATABASE_URL:useDatabaseUrl?databaseUrl:'postgres://[',REDIS_URL:redisUrl,REDIS_PORT:'1',
   JWT_SECRET:randomBytes(32).toString('hex'),SESSION_SECRET:useDatabaseUrl?'':randomBytes(32).toString('hex'),LOG_DIR:path.join(directory,'logs')}});
  service.on('error',error=>{startupError=error;});for(const stream of [service.stdout,service.stderr])stream.on('data',chunk=>{output=(output+chunk.toString()).slice(-32768);});
  const url='http://127.0.0.1:'+httpPort;const deadline=Date.now()+15000;
  while(Date.now()<deadline){
   if(startupError)throw startupError;
   if(service.exitCode!==null||service.signalCode!==null)throw new Error('Actual authentication service exited before readiness: '+output);
   try{const response=await fetch(url+'/health',{signal:AbortSignal.timeout(500)});if(response.status===200)return{url,redis,stop:cleanup,output:()=>output};}catch{}
   await delay(50);
  }
  throw new Error('Actual authentication service readiness deadline: '+output);
 }catch(error){await cleanup();throw error;}
}
module.exports={startAuthenticationService};
