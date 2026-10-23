'use strict';
const contract=require('../../../../../packages/company-automation-change-contract');
const {workload}=require('../../../../../packages/company-automation-contract');
class CompanyAutomationWatchAuthority{
 constructor({endpoint=(process.env.IDENTITY_SERVICE_URL||'http://identity-service:3001')+contract.WATCH_PATH,fetchImpl=(...args)=>fetch(...args)}={}){this.endpoint=endpoint;this.fetchImpl=fetchImpl;}
 async read(context,authorization,user){
  contract.input(context);workload(user,user?.iss);
  return contract.watch(await contract.exchange(this.endpoint,contract.WATCH_PATH,context,authorization,this.fetchImpl),context,user);
 }
}
module.exports={CompanyAutomationWatchAuthority};
