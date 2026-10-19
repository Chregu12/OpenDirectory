'use strict';
jest.mock('../config/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn() }));
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const routes = require('../middleware/routing');
const { gatewayAccess } = require('../middleware/gatewayAccess');
test.each(['policies', 'blueprints', 'company-blueprints', 'gpo', 'update-rings'])('canonical %s preserves its receiver namespace and does not require global gateway administration', name => {
  expect(routes.getServiceRoutes('policy-service')).toContainEqual(expect.objectContaining({ path: '/api/' + name, port: 3004 }));
  const next = jest.fn(); const response = { status: jest.fn().mockReturnThis(), json: jest.fn() };
  gatewayAccess(() => ({ name }))({ method: 'GET', path: '/api/' + name, user: { roles: ['policy-reader'] } }, response, next);
  expect(next).toHaveBeenCalledTimes(1); expect(response.status).not.toHaveBeenCalled();
});
test('known source consents have an explicit non-rewriting identity route rather than a generic administrative proxy',()=>{expect(routes.getServiceRoutes('identity-service')).toContainEqual(expect.objectContaining({path:'/api/identity/license-sources',port:3001}));const next=jest.fn();const response={status:jest.fn().mockReturnThis(),json:jest.fn()};gatewayAccess(()=>({name:'license-source-grants'}))({method:'POST',path:'/api/identity/license-sources',user:{roles:['license-scope-administrator']}},response,next);expect(next).toHaveBeenCalledTimes(1);expect(response.status).not.toHaveBeenCalled();});
test('delegated orchestration has its own canonical path and port', () => {
  expect(routes.getServiceRoutes('quick-actions')).toContainEqual(expect.objectContaining({ path: '/api/quick', port: 3950 }));
});
test('canonical membership review paths retain their identity namespace and receiving service port',()=>{
 expect(routes.getServiceRoutes('identity-service')).toContainEqual(expect.objectContaining({path:'/api/identity/membership-reviews',port:3001}));const next=jest.fn();const response={status:jest.fn().mockReturnThis(),json:jest.fn()};gatewayAccess(()=>({name:'membership-reviews'}))({method:'POST',path:'/api/identity/membership-reviews/policies',user:{roles:['group-review-administrator']}},response,next);expect(next).toHaveBeenCalledTimes(1);expect(response.status).not.toHaveBeenCalled();
});
test('quick-actions operator grants are evaluated by the receiving service rather than requiring global gateway administration', () => {
  const next = jest.fn(); const response = { status: jest.fn().mockReturnThis(), json: jest.fn() };
  gatewayAccess(() => ({ name: 'quick-actions' }))({ method: 'POST', path: '/api/quick/service-principals', user: { roles: ['application-administrator'] } }, response, next);
  expect(next).toHaveBeenCalled(); expect(response.status).not.toHaveBeenCalled();
});
test.each(['docker-compose.yml', 'docker-compose.lite.yml'])('%s packages a disabled-by-default nonroot delegation service without ambient credentials or signing-key mounts', file => {
  const root = path.resolve(__dirname, '../../../../..'); const service = yaml.load(fs.readFileSync(path.join(root, file), 'utf8')).services['quick-actions'];
  expect(service.profiles).toEqual(['delegated-orchestration']); expect(service.read_only).toBe(true); expect(service.cap_drop).toEqual(['ALL']);
  const environment = service.environment.join('\n'); expect(environment).toContain('OIDC_ACCESS_STATE_URL=http://oauth-provider:3010/oauth/access-state');
  expect(environment).not.toMatch(/QA_CLIENT_SECRET|SERVICE_TOKEN=|TOKEN_ENDPOINT|OAUTH_SIGNING_KEY_FILE/); expect(service.volumes).toBeUndefined();
  const dockerfile = fs.readFileSync(path.join(root, service.build.dockerfile), 'utf8'); expect(dockerfile).toContain('USER node');
  expect(dockerfile).toContain('COPY packages/oidc-access-state.js /app/packages/oidc-access-state.js');
});
test.each(['docker-compose.yml', 'docker-compose.lite.yml'])('%s does not provision an ambient issuer-administration token into policy delivery', file => {
  const root = path.resolve(__dirname, '../../../../..'); const service = yaml.load(fs.readFileSync(path.join(root, file), 'utf8')).services['policy-service'];
  const environment = service.environment.join('\n'); expect(environment).toContain('OAUTH_PROVIDER_URL=http://oauth-provider:3010');
  expect(environment).not.toMatch(/OAUTH_PROVIDER_INTERNAL_TOKEN|OAUTH_SIGNING_KEY_FILE/);
  const dockerfile = fs.readFileSync(path.join(root, service.build.dockerfile), 'utf8');
  expect(dockerfile).toContain('COPY packages/policy-authorization-contract.js /packages/policy-authorization-contract.js');
  expect(dockerfile).toContain('COPY packages/role-authentication-contract.js /packages/role-authentication-contract.js');
});
