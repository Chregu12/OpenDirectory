'use strict';

process.env.OIDC_ISSUER = 'https://gateway.test';
process.env.OIDC_AUDIENCE = 'opendirectory-api';
process.env.JWT_SECRET = 'a-legacy-shared-secret-must-not-be-trusted';
jest.mock('../../../../../packages/oidc-access-state', () => ({ createAccessStateClient: jest.fn(() => jest.fn(async () => {})) }));

jest.mock('../config/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn(), security: jest.fn(), performance: jest.fn() }));
jest.mock('pg', () => ({ Pool: jest.fn(() => ({ query: jest.fn(async () => { throw new Error('Database unavailable'); }), end: jest.fn() })) }), { virtual: true });
jest.mock('@opendirectory/grpc-event-bus', () => ({ EventBusClient: jest.fn(() => ({ connect: jest.fn(async () => {}), publish: jest.fn(async () => {}) })) }), { virtual: true });
jest.mock('../discovery/serviceDiscovery', () => ({ start: jest.fn(), stop: jest.fn() }));
jest.mock('../middleware/health', () => jest.fn((_req, res) => res.json({ status: 'healthy', internalDetails: true })));
jest.mock('../config/configManager', () => ({
  getConfig: jest.fn(() => ({})), getEnabledModules: jest.fn(() => ['device-management', 'policy-service', 'identity-service', 'license-management']),
  getModuleConfiguration: jest.fn(() => ({ fixture: { enabled: true, port: 3004, features: {}, config: { password: 'must-not-be-projected' } } })),
  updateModuleConfiguration: jest.fn(async () => {}),
}));
jest.mock('jose', () => {
  const actual = jest.requireActual('jose');
  return { ...actual, jwtVerify: jest.fn(actual.jwtVerify), createRemoteJWKSet: jest.fn(() => actual.createLocalJWKSet({ keys: [require('./fixtures/oidc.cjs').publicJwk] })) };
});
jest.mock('http-proxy-middleware', () => ({ createProxyMiddleware: jest.fn(options => (req, res) => res.json({ target: options.target, authorization: req.headers.authorization,originalUrl:req.originalUrl,ifMatch:req.headers['if-match'] })) }));

const request = require('supertest');
const jwt = require('jsonwebtoken');
const { jwtVerify } = require('jose');
const { issuer, audience, privateKey } = require('./fixtures/oidc.cjs');
const APIGateway = require('../index');
const { OPERATIONS, getGatewayPermissions } = require('../middleware/gatewayAccess');
const config = require('../config/configManager');
const { createProxyMiddleware } = require('http-proxy-middleware');
let gateway;

beforeAll(() => { gateway = new APIGateway({ discover: false }); });
afterAll(() => { gateway.stop(); });
beforeEach(() => { jest.clearAllMocks(); });

function token(claims = {}, options = {}) {
  return jwt.sign({ sub: 'verified-operator', jti: require('crypto').randomUUID(), token_use: 'access', roles: ['user'], ...claims }, privateKey,
    { algorithm: 'RS256', keyid: 'gateway-tests', issuer, audience, expiresIn: '5m', ...options });
}
function asAdmin() { return token({ roles: ['admin'] }); }
const protectedOperations = [
  ['get', '/health/detailed', 'gateway.status.read'], ['get', '/api/gateway/info', 'gateway.status.read'],
  ['get', '/api/gateway/routes', 'gateway.status.read'], ['get', '/api/services', 'gateway.status.read'],
  ['get', '/api/config/modules', 'gateway.config.read'], ['post', '/api/config/modules/fixture', 'gateway.config.manage'],
  ['get', '/api/admin/keys', 'gateway.keys.read'], ['post', '/api/admin/keys', 'gateway.keys.manage'], ['delete', '/api/admin/keys/fixture', 'gateway.keys.manage'],
  ['get', '/api/gateway/api-keys', 'gateway.keys.read'], ['post', '/api/gateway/api-keys', 'gateway.keys.manage'], ['delete', '/api/gateway/api-keys/fixture', 'gateway.keys.manage'],
  ['get', '/api/gateway/webhooks', 'gateway.webhooks.read'], ['post', '/api/gateway/webhooks', 'gateway.webhooks.manage'],
  ['put', '/api/gateway/webhooks/fixture', 'gateway.webhooks.manage'], ['delete', '/api/gateway/webhooks/fixture', 'gateway.webhooks.manage'],
  ['post', '/api/gateway/webhooks/fixture/test', 'gateway.webhooks.manage'], ['get', '/api/gateway/webhooks/fixture/deliveries', 'gateway.webhooks.read'],
];

test.each(['/health', '/health/live'])('liveness %s is minimal and does not expose internal service/process data', async path => {
  const result = await request(gateway.app).get(path);
  expect(result.status).toBe(200); expect(result.body).toEqual({ status: 'ok', service: 'api-gateway' }); expect(jwtVerify).not.toHaveBeenCalled();
});
test.each(protectedOperations)('%s %s requires a real token and the exact permission %s', async (method, path, permission) => {
  expect((await request(gateway.app)[method](path).send({ roles: ['admin'] })).status).toBe(401);
  const result = await request(gateway.app)[method](path).set('Authorization', 'Bearer ' + token({ scope: permission })).set('X-User-Roles', 'admin').send({ permissions: [permission], isAdmin: true });
  expect(result.status).toBe(403);
  expect(config.updateModuleConfiguration).not.toHaveBeenCalled();
});
test.each(protectedOperations)('%s %s accepts only the server-issued narrow grant %s', async (method, path, permission) => {
  const result = await request(gateway.app)[method](path).set('Authorization', 'Bearer ' + token({ permissions: [permission] })).send({ enabled: false });
  expect(result.status).not.toBe(401); expect(result.status).not.toBe(403);
});
test.each(['Bearer forged', 'Basic secret', '', 'Bearer '])('rejects malformed or unsigned authorization: %s', async authorization => {
  expect((await request(gateway.app).get('/api/gateway/access').set('Authorization', authorization)).status).toBe(401);
});
test.each(['id', 'refresh', 'device', undefined])('requires an explicit access-token purpose, not %s', async token_use => {
  expect((await request(gateway.app).get('/api/gateway/access').set('Authorization', 'Bearer ' + token({ token_use }))).status).toBe(401);
});
test('rejects legacy HMAC master-secret tokens instead of falling back from failed JWKS verification', async () => {
  const legacy = jwt.sign({ sub: 'forged-admin', roles: ['admin'] }, process.env.JWT_SECRET);
  expect((await request(gateway.app).get('/api/gateway/access').set('Authorization', 'Bearer ' + legacy)).status).toBe(401);
});
test.each([{ issuer: 'https://wrong.test' }, { audience: 'browser-client' }, { expiresIn: '-1s' }, { notBefore: '5m' }])('rejects a genuinely signed token outside the trust contract: %j', async options => {
  expect((await request(gateway.app).get('/api/gateway/access').set('Authorization', 'Bearer ' + token({}, options))).status).toBe(401);
});
test.each([{ sub: '' }, { sub: 42 }, { sub: undefined }, { roles: 'admin', permissions: '*' }])('invalid identity/claim shapes cannot authorize administration: %j', async claims => {
  const result = await request(gateway.app).get('/api/gateway/api-keys').set('Authorization', 'Bearer ' + token(claims));
  expect([401, 403]).toContain(result.status);
});
test('cookie, query and environment API-key credentials never authorize requests or promote a bearer', async () => {
  const credential = token({ roles: ['admin'] }); process.env.API_KEY_ADMIN = 'environment-admin';
  try {
    expect((await request(gateway.app).get('/api/gateway/access?token=' + credential)).status).toBe(401);
    expect((await request(gateway.app).get('/api/gateway/access').set('Cookie', 'token=' + credential)).status).toBe(401);
    expect((await request(gateway.app).get('/api/gateway/access').set('X-API-Key', 'environment-admin')).status).toBe(401);
    expect((await request(gateway.app).get('/api/gateway/access').set('Authorization', 'Bearer ' + credential).set('X-API-Key', 'environment-admin')).status).toBe(401);
  } finally { delete process.env.API_KEY_ADMIN; }
});
test('revalidates the same token on every request rather than caching an expired administrative principal', async () => {
  const credential = token({ roles: ['admin'] });
  await request(gateway.app).get('/api/gateway/access').set('Authorization', 'Bearer ' + credential);
  await request(gateway.app).get('/api/gateway/access').set('Authorization', 'Bearer ' + credential);
  expect(jwtVerify).toHaveBeenCalledTimes(2);
});
test('issued gateway grants are task-specific, never scope/wildcard/admin-flag guesses', () => {
  expect(getGatewayPermissions({ scope: 'gateway.config.manage', permissions: ['*'], isAdmin: true })).toEqual([]);
  expect(getGatewayPermissions({ roles: ['gateway-key-administrator'] })).toEqual(['gateway.keys.read', 'gateway.keys.manage']);
  expect(getGatewayPermissions({ realm_access: { roles: ['gateway-webhook-administrator'] } })).toEqual(['gateway.webhooks.read', 'gateway.webhooks.manage']);
  expect(OPERATIONS.every(operation => operation[2] === null || typeof operation[2] === 'string')).toBe(true);
});
test('ordinary users see their own capabilities but neither body-supplied authority nor administrative controls', async () => {
  const result = await request(gateway.app).get('/api/gateway/access').set('Authorization', 'Bearer ' + token());
  expect(result.status).toBe(200); expect(result.body.permissions).toEqual([]); expect(result.body.keyIssuanceEnabled).toBe(false);
});
test('legacy credential issuance is explicitly retired, and offline storage cannot fake registration or revocation', async () => {
  for (const path of ['/api/admin/keys', '/api/gateway/api-keys']) {
    expect((await request(gateway.app).post(path).set('Authorization', 'Bearer ' + asAdmin()).send({ name: 'Forged root', permissions: ['*'] })).status).toBe(410);
    expect((await request(gateway.app).get(path).set('Authorization', 'Bearer ' + asAdmin())).status).toBe(503);
    expect((await request(gateway.app).delete(path + '/fixture').set('Authorization', 'Bearer ' + asAdmin())).status).toBe(503);
  }
});
test('module projection hides secret configuration values and write requires a separate grant', async () => {
  const result = await request(gateway.app).get('/api/config/modules').set('Authorization', 'Bearer ' + token({ roles: ['gateway-reader'] }));
  expect(result.status).toBe(200); expect(result.body.fixture.config).toBeUndefined(); expect(JSON.stringify(result.body)).not.toContain('must-not-be-projected');
  expect((await request(gateway.app).post('/api/config/modules/fixture').set('Authorization', 'Bearer ' + token({ roles: ['gateway-reader'] })).send({ enabled: true })).status).toBe(403);
});
test('protected backend paths retain the original operator token and old gateway grants cannot bypass canonical inventory receiving', async () => {
  const credential = token({ roles: ['license-manager'] });
  for (const path of ['/api/licenses', '/api/license/licenses', '/api/identity/subject']) {
    const result = await request(gateway.app).get(path).set('Authorization', 'Bearer ' + credential);
    expect(result.status).toBe(200); expect(result.body.authorization).toBe('Bearer ' + credential);
  }
  expect((await request(gateway.app).get('/api/devices').set('Authorization', 'Bearer ' + token())).status).toBe(403);
  expect((await request(gateway.app).get('/api/devices').set('Authorization', 'Bearer ' + token({ permissions: ['gateway.proxies.devices.access'] }))).status).toBe(403);
});
test('a local gateway administrator is not a global downstream administrator and unknown control operations stay denied', async () => {
  const credential = token({ roles: ['gateway-administrator'] });
  expect((await request(gateway.app).get('/api/devices').set('Authorization', 'Bearer ' + credential)).status).toBe(403);
  expect((await request(gateway.app).post('/api/gateway/unregistered').set('Authorization', 'Bearer ' + credential)).status).toBe(404);
  expect((await request(gateway.app).patch('/api/config/modules/fixture').set('Authorization', 'Bearer ' + credential)).status).toBe(404);
});
test('canonical and compatibility licensing preserve ports/paths and cannot overwrite the canonical registry', () => {
  const calls = createProxyMiddleware.mock.calls;
  gateway.setupDynamicProxies();
  expect(calls.find(([options]) => options.target === 'http://policy-service:3004')[0].pathRewrite).toBeUndefined();
  expect(calls.find(([options]) => options.target === 'http://license-management:3018')[0].pathRewrite).toBeUndefined();
  expect(gateway.services.get('licenses').target).toBe('http://policy-service:3004');
  expect(gateway.services.get('license').target).toBe('http://license-management:3018');
});

test('canonical directory namespaces retain the configured identity URL and are never rewritten to a generic api path',()=>{
 const previous=process.env.IDENTITY_SERVICE_URL;process.env.IDENTITY_SERVICE_URL='http://127.0.0.1:48917';let configured;
 try{configured=new APIGateway({discover:false,enabledModules:['identity-service']});
  for(const[name,pathPrefix]of[['identity','/api/identity'],['users','/api/users'],['groups','/api/groups'],['ous','/api/ous']])expect(configured.services.get(name)).toMatchObject({target:process.env.IDENTITY_SERVICE_URL,pathPrefix});
  const options=createProxyMiddleware.mock.calls.map(([value])=>value).filter(value=>value.target===process.env.IDENTITY_SERVICE_URL);expect(options.length).toBeGreaterThanOrEqual(4);for(const value of options)expect(value.pathRewrite).toBeUndefined();
 }finally{configured?.stop();if(previous===undefined)delete process.env.IDENTITY_SERVICE_URL;else process.env.IDENTITY_SERVICE_URL=previous;}
});
test.each([['put','/api/users/11111111-1111-4111-8111-111111111111'],['delete','/api/users/11111111-1111-4111-8111-111111111111'],['post','/api/users/11111111-1111-4111-8111-111111111111/authorization/invalidate']])('canonical %s forwards the original namespace, bearer and strong precondition',async(method,route)=>{
 const credential=token({roles:['user-lifecycle-operator']});const version='"user-11111111-1111-4111-8111-111111111111-7"';const result=await request(gateway.app)[method](route).set('Authorization','Bearer '+credential).set('If-Match',version);
 expect(result.status).toBe(200);expect(result.body).toMatchObject({target:'http://identity-service:3001',originalUrl:route,authorization:'Bearer '+credential,ifMatch:version});
});
test('allowed browser origins can send strong user preconditions and read returned ETags',async()=>{
 const preflight=await request(gateway.app).options('/api/users/11111111-1111-4111-8111-111111111111').set('Origin','http://localhost:3000').set('Access-Control-Request-Method','PUT').set('Access-Control-Request-Headers','authorization,content-type,if-match');expect(preflight.status).toBe(204);expect(preflight.headers['access-control-allow-headers'].toLowerCase()).toContain('if-match');
 const response=await request(gateway.app).get('/api/users').set('Origin','http://localhost:3000').set('Authorization','Bearer '+token());expect(response.status).toBe(200);expect(response.headers['access-control-expose-headers'].toLowerCase()).toContain('etag');
});

describe('production CORS is transport policy, never authentication',()=>{
 let production;let previousMode;let previousOrigins;
 beforeAll(()=>{previousMode=process.env.NODE_ENV;previousOrigins=process.env.CORS_ORIGIN;process.env.NODE_ENV='production';process.env.CORS_ORIGIN='https://console.opendirectory.test, null, ';production=new APIGateway({discover:false});});
 afterAll(()=>{production.stop();if(previousMode===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=previousMode;if(previousOrigins===undefined)delete process.env.CORS_ORIGIN;else process.env.CORS_ORIGIN=previousOrigins;});
 test('originless authorized callers reach normal verification without browser access headers',async()=>{
  const response=await request(production.app).get('/api/gateway/access').set('Authorization','Bearer '+token());expect(response.status).toBe(200);expect(jwtVerify).toHaveBeenCalledTimes(1);expect(response.headers['access-control-allow-origin']).toBeUndefined();expect(response.headers['access-control-allow-credentials']).toBeUndefined();
 });
 test.each(['','null','https://console.opendirectory.test.evil.test','http://console.opendirectory.test'])('rejects a non-allowed browser origin before forwarding: %s',async origin=>{
  const response=await request(production.app).get('/api/users').set('Origin',origin).set('Authorization','Bearer '+asAdmin());expect(response.status).toBe(403);expect(response.headers['access-control-allow-origin']).toBeUndefined();expect(jwtVerify).not.toHaveBeenCalled();
 });
 test('allowed origins retain precise preflights, version response exposure and mandatory bearer admission',async()=>{
  const preflight=await request(production.app).options('/api/groups/11111111-1111-4111-8111-111111111111').set('Origin','https://console.opendirectory.test').set('Access-Control-Request-Method','PUT').set('Access-Control-Request-Headers','authorization,content-type,if-match');expect(preflight.status).toBe(204);expect(preflight.headers['access-control-allow-origin']).toBe('https://console.opendirectory.test');expect(preflight.headers['access-control-allow-headers'].toLowerCase()).toContain('if-match');expect(jwtVerify).not.toHaveBeenCalled();
  const absent=await request(production.app).get('/api/gateway/access').set('Origin','https://console.opendirectory.test');expect(absent.status).toBe(401);
  const allowed=await request(production.app).get('/api/gateway/access').set('Origin','https://console.opendirectory.test').set('Authorization','Bearer '+token());expect(allowed.status).toBe(200);expect(allowed.headers['access-control-expose-headers'].toLowerCase()).toContain('etag');expect(allowed.headers.vary).toContain('Origin');
 });
 test('an originless client-type or service/API-key header cannot replace a bearer',async()=>{
  for(const headers of[{}, {'X-Client-Type':'frontend','X-User-Roles':'admin'},{'X-Service-Auth':'legacy','X-Service-Name':'identity-service'},{'X-API-Key':'legacy'}])expect((await request(production.app).get('/api/gateway/access').set(headers)).status).toBe(401);
  expect((await request(production.app).get('/api/gateway/access').set('Authorization','Bearer '+asAdmin()).set('X-API-Key','legacy')).status).toBe(401);
 });
 test('public originless documentation advertises actual bearer-only authentication and limiter tiers',async()=>{
  const response=await request(production.app).get('/docs');expect(response.status).toBe(200);expect(response.body.authentication.types).toEqual(['OIDC Bearer access token']);expect(response.body.authentication['api-key-example']).toBeUndefined();expect(response.body['rate-limits']).toEqual({'all-client-ingress':'5000 requests per 15 minutes',authenticated:'1000 requests per 15 minutes',public:'100 requests per 15 minutes'});
  expect(response.body.endpoints.public.services).toBeUndefined();expect(response.body.endpoints.protected.services).toBe('/api/services');
  const spec=await request(production.app).get('/docs/openapi.json');expect(spec.status).toBe(200);expect(spec.body.components.securitySchemes).toEqual({BearerAuth:{type:'http',scheme:'bearer'}});expect(spec.body.security).toEqual([{BearerAuth:[]}]);expect(spec.body.paths['/health'].get.security).toEqual([]);
  const routes=await request(production.app).get('/api/gateway/routes').set('Authorization','Bearer '+token({roles:['gateway-reader']}));expect(routes.status).toBe(200);expect(routes.body.find(route=>route.path==='/api/services')).toMatchObject({auth:'required',permission:'gateway.status.read'});
 });
});

test('both Compose topologies use the same explicit API audience and issuer for protected license and identity operations', () => {
  const fs = require('fs'); const path = require('path'); const yaml = require('yaml');
  for (const filename of ['docker-compose.yml', 'docker-compose.lite.yml']) {
    const { services } = yaml.parse(fs.readFileSync(path.join(__dirname, '../../../../../', filename), 'utf8'));
    const settings = name => services[name].environment;
    expect(services['oauth-provider'].build.context).toBe('.');
    expect(services['oauth-provider'].user).toBe('${OAUTH_SERVICE_UID:-1000}:${OAUTH_SERVICE_GID:-1000}');
    expect(settings('oauth-provider')).toContain('OAUTH_API_AUDIENCE=${OAUTH_API_AUDIENCE:-opendirectory-api}');
    expect(settings('oauth-provider')).toContain('OAUTH_SIGNING_KEY_FILE=/run/opendirectory/oauth-signing.pem');
    expect(settings('oauth-provider')).toContain('OAUTH_EPHEMERAL_SIGNING_KEYS=false');
    const mounts = services['oauth-provider'].volumes.filter(volume => typeof volume === 'object');
    for (const target of ['/run/opendirectory/oauth-signing.pem', '/run/opendirectory/oauth-verification.jwks.json']) {
      expect(mounts.find(volume => volume.target === target)).toMatchObject({ type: 'bind', read_only: true, bind: { create_host_path: false } });
      for (const [name, service] of Object.entries(services)) {
        if (name !== 'oauth-provider') expect((service.volumes || []).some(volume => typeof volume === 'object' && volume.target === target)).toBe(false);
      }
    }
    for (const name of ['identity-service', 'policy-service']) {
      expect(services[name].build.context).toBe('.');
      const dockerfile = fs.readFileSync(path.join(__dirname, '../../../../../', services[name].build.dockerfile), 'utf8');
      expect(dockerfile).toContain('COPY packages/oidc-access-state.js /packages/oidc-access-state.js');
      expect(settings(name)).toContain('OIDC_ISSUER=${OAUTH_ISSUER:-https://opendirectory.local}');
      expect(settings(name)).toContain('OIDC_AUDIENCE=${OAUTH_API_AUDIENCE:-opendirectory-api}');
      expect(settings(name)).toContain('JWKS_URI=http://oauth-provider:3010/.well-known/jwks.json');
      expect(settings(name)).toContain('OIDC_ACCESS_STATE_URL=http://oauth-provider:3010/oauth/access-state');
    }
  }
});
