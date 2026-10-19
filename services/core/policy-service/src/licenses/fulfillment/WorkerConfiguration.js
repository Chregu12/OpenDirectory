'use strict';

const fs=require('fs');
const { uuid,fields }=require('./contracts');
const { ClientCredentialToken }=require('./transport');
const { GroupSnapshotClient }=require('../GroupSnapshotClient');
function secret(value) { if (typeof value!=='string' || value.length<12 || value.length>4096 || /[\u0000-\u0020\u007f]/.test(value)) throw new Error('Invalid protected worker credential'); }
function localEndpoint(value,path) {
  const url=new URL(value); if (!['http:','https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname!==path) throw new Error('Invalid fixed local worker endpoint'); return url.toString();
}
function configuration(filename) {
  if (!filename || typeof process.getuid!=='function') throw new Error('A protected worker configuration file is required');
  const descriptor=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try {
    const state=fs.fstatSync(descriptor);
    if (!state.isFile() || state.uid!==process.getuid() || (state.mode&0o077)!==0 || state.size>16384) throw new Error('Worker configuration must be an owner-only regular file');
    const data=JSON.parse(fs.readFileSync(descriptor,'utf8'));
    fields(data,['enabled','connectorId','tenantId','graphClientId','graphClientSecret','sourceClientId','sourceClientSecret','sourceTokenUrl','identityUrl']);
    if (data.enabled!==true) throw new Error('Worker configuration must explicitly enable fulfillment');
    uuid(data.connectorId); uuid(data.tenantId); uuid(data.graphClientId); secret(data.graphClientSecret); secret(data.sourceClientSecret);
    if (typeof data.sourceClientId!=='string' || !/^[A-Za-z0-9._~-]{1,255}$/.test(data.sourceClientId)) throw new Error('Invalid local source client');
    localEndpoint(data.sourceTokenUrl,'/oauth/token'); localEndpoint(data.identityUrl,'/');
    return Object.freeze(data);
  } finally { fs.closeSync(descriptor); }
}
class WorkerIdentity {
  constructor(config,{ fetchImpl=(...args)=>fetch(...args) }={}) {
    this.tokens=new ClientCredentialToken({ url:config.sourceTokenUrl,clientId:config.sourceClientId,clientSecret:config.sourceClientSecret,scope:'licenses.users.read',fetchImpl,stage:'source_token' });
    this.source=new GroupSnapshotClient({ baseUrl:config.identityUrl,fetchImpl });
  }
  async user(userId) {
    try { return await this.source.user(userId,'Bearer '+await this.tokens.get()); }
    catch (error) { this.tokens.clear(); throw error; }
  }
}
module.exports = { configuration,WorkerIdentity };
