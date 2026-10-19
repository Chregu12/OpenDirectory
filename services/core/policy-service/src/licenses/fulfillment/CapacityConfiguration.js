'use strict';

const fs=require('node:fs');
const {uuid,fields}=require('./contracts');
function configuration(filename){
  if(!filename||typeof process.getuid!=='function')throw new Error('Protected capacity collector file required');const descriptor=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try{
    const state=fs.fstatSync(descriptor);if(!state.isFile()||state.uid!==process.getuid()||(state.mode&0o077)!==0||state.size>16384)throw new Error('Capacity configuration must be an owner-only regular file');
    const data=JSON.parse(fs.readFileSync(descriptor,'utf8'));fields(data,['enabled','readOnlyConsentReviewed','sourceId','connectorId','tenantId','graphClientId','graphClientSecret']);
    if(data.enabled!==true||data.readOnlyConsentReviewed!==true)throw new Error('Explicit collector enablement and separate read-only consent review required');
    for(const key of ['sourceId','connectorId','tenantId','graphClientId'])uuid(data[key]);
    if(typeof data.graphClientSecret!=='string'||data.graphClientSecret.length<12||data.graphClientSecret.length>4096||/[\u0000-\u0020\u007f]/.test(data.graphClientSecret))throw new Error('Protected capacity credential required');return Object.freeze(data);
  }finally{fs.closeSync(descriptor);}
}
module.exports={configuration};
