'use strict';
jest.mock('../config/logger',()=>({info:jest.fn(),warn:jest.fn(),error:jest.fn()}));
const routing=require('../middleware/routing');const {gatewayAccess}=require('../middleware/gatewayAccess');
test.each(['GET','POST','PUT','DELETE'])('delegates only the own-company %s namespace without inventing a global application role',method=>{
 const next=jest.fn();const response={status:jest.fn().mockReturnThis(),json:jest.fn()};gatewayAccess(()=>({name:'company-apps'}))({method,path:'/api/clients/company/00000000-0000-4000-8000-000000000001',user:{roles:[],permissions:[]}},response,next);expect(next).toHaveBeenCalledTimes(1);expect(routing.getServiceRoutes('oauth-provider')).toContainEqual(expect.objectContaining({path:'/api/clients/company',port:3010}));
});
test.each(['/api/clients','/api/clients/company-forged','/api/clients/foreign-client'])('does not admit the near-match or global registry %s',path=>{const next=jest.fn();const response={status:jest.fn().mockReturnThis(),json:jest.fn()};gatewayAccess(()=>null)({method:'POST',path,user:{roles:[],permissions:[]}},response,next);expect(next).not.toHaveBeenCalled();expect(response.status).toHaveBeenCalledWith(403);});
