jest.mock('jose', () => ({ createRemoteJWKSet: jest.fn(() => 'registration-jwks'), jwtVerify: jest.fn() }));
const { randomUUID } = require('node:crypto');
const { jwtVerify } = require('jose');
const { registrationRequest } = require('../CompanyRegistrations');
const { BASE_PATH, PURPOSE, TYPE, AUDIENCE } = require('../../../../../packages/company-registration-contract');
const { requestDigest } = require('../../../../../packages/company-registration-contract/digest');
const issuer = 'https://issuer.test';
const body = { registrationId: randomUUID(), subject: 'verified-credential' };
function claims() { const now = Math.floor(Date.now() / 1000); return { iss: issuer, sub: 'oauth-provider', aud: AUDIENCE, token_use: PURPOSE, actor_type: 'workload', htm: 'POST', htu: BASE_PATH + '/status',
  body_sha256: requestDigest('status', body), registration_subject: body.subject, jti: randomUUID(), iat: now, exp: now + 30 }; }
async function invoke(payload = claims(), protectedHeader = { typ: TYPE }, requestBody = body) {
  jwtVerify.mockResolvedValueOnce({ payload, protectedHeader }); const next = jest.fn(); const res = { set: jest.fn().mockReturnThis(), status: jest.fn().mockReturnThis(), json: jest.fn() };
  const req = { headers: { authorization: 'Bearer original-purpose-proof' }, query: {}, body: requestBody };
  await registrationRequest({ issuer, jwksUri: 'https://issuer.test/jwks' })('status')(req, res, next); return { next, res, req };
}
beforeEach(() => jest.clearAllMocks());
test('only the exact issuer-verified method/purpose/body/subject proof reaches registration storage', async () => {
  const { next, req } = await invoke(); expect(next).toHaveBeenCalledTimes(1); expect(req.registrationInput).toEqual(body); expect(req.authorityIssuer).toBe(issuer);
  expect(jwtVerify).toHaveBeenCalledWith('original-purpose-proof', 'registration-jwks', expect.objectContaining({ issuer, audience: AUDIENCE, algorithms: ['RS256'], maxTokenAge: '30s' }));
});
test.each([{ token_use: 'access' }, { actor_type: 'user' }, { htm: 'GET' }, { htu: BASE_PATH + '/submit' }, { registration_subject: 'other-credential' },
  { body_sha256: 'a'.repeat(64) }, { jti: 'not-a-nonce' }, { roles: ['admin'] }])('valid signatures do not excuse wrong receiving claims %#', async change => {
  const { next, res } = await invoke({ ...claims(), ...change }); expect(next).not.toHaveBeenCalled(); expect(res.status).toHaveBeenCalledWith(401);
});
test('the old human/API token type and a modified credential body cannot borrow a registration proof', async () => {
  const typed = await invoke(claims(), { typ: 'JWT' }); expect(typed.res.status).toHaveBeenCalledWith(401);
  const changed = await invoke(claims(), { typ: TYPE }, { ...body, subject: 'other-credential' }); expect(changed.next).not.toHaveBeenCalled(); expect(changed.res.status).toHaveBeenCalledWith(401);
});
test('signature expiry and issuer/JWKS outages are denied without touching registration storage', async () => {
  const next = jest.fn(); const res = { set: jest.fn().mockReturnThis(), status: jest.fn().mockReturnThis(), json: jest.fn() };
  const receive = registrationRequest({ issuer, jwksUri: 'https://issuer.test/jwks' })('status'); const req = { headers: { authorization: 'Bearer expired-or-unavailable' }, query: {}, body };
  jwtVerify.mockRejectedValueOnce(Object.assign(new Error('expired'), { code: 'ERR_JWT_EXPIRED' })); await receive(req, res, next); expect(res.status).toHaveBeenLastCalledWith(401);
  jwtVerify.mockRejectedValueOnce(Object.assign(new Error('jwks timeout'), { code: 'ERR_JWKS_TIMEOUT' })); await receive(req, res, next); expect(res.status).toHaveBeenLastCalledWith(503); expect(next).not.toHaveBeenCalled();
});
