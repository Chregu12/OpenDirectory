'use strict';
jest.mock('../config/logger',()=>({info:jest.fn(),warn:jest.fn(),error:jest.fn()}));
const routes=require('../middleware/routing');const {gatewayAccess}=require('../middleware/gatewayAccess');
test('the actual automation prefix resolves to canonical identity, not the legacy automation service',()=>{
 const route=routes.getAllRoutes().filter(row=>'/api/identity/automation/run'.startsWith(row.path)).sort((a,b)=>b.path.length-a.path.length)[0];
 expect(route.service).toBe('identity-service');expect(route.port).toBe(3001);
});
test('gateway delegates an exact app request without inventing global rights; the identity receiver enforces the independent grant',()=>{
 const next=jest.fn();const response={status:jest.fn().mockReturnThis(),json:jest.fn()};
 gatewayAccess(()=>({name:'identity-service'}))({path:'/api/identity/automation/run',method:'POST',user:{actor_type:'application',scope:'company.automation',permissions:['company.automation']}},response,next);
 expect(next).toHaveBeenCalledTimes(1);expect(response.status).not.toHaveBeenCalled();
});
