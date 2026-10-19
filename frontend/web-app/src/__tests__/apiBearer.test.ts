import { api } from '../lib/api';
import { ensureSession } from '../lib/auth';

jest.mock('../lib/auth', () => ({ getAccessToken: () => 'verified-memory-token', ensureSession: jest.fn() }));

const authorize = (api.interceptors.request.use as jest.Mock).mock.calls[0][0];
const denied = (api.interceptors.response.use as jest.Mock).mock.calls[0][1];
beforeEach(() => jest.clearAllMocks());

test('API bearers are confined to the same-origin proxy', async () => {
  const config = { url: '/api/licenses', headers: { set: jest.fn() } };
  expect(await authorize(config)).toBe(config);
  expect(config.headers.set).toHaveBeenCalledWith('Authorization', 'Bearer verified-memory-token');
});
test('external and protocol-relative URLs cannot receive user bearers or consume refresh', async () => {
  for (const target of [{ url: 'https://attacker.test/api/licenses' }, { url: '//attacker.test/api/licenses' }, { url: '/api/licenses', baseURL: 'https://attacker.test' }]) {
    const config = { ...target, headers: { set: jest.fn() } };
    await expect(authorize(config)).rejects.toThrow('same-origin'); expect(config.headers.set).not.toHaveBeenCalled();
  }
  expect(ensureSession).not.toHaveBeenCalled();
});
test('a receiving-service denial rejects without replaying mutations or treating it as global logout', async () => {
  const error = { response: { status: 401 } }; await expect(denied(error)).rejects.toBe(error);
  expect(ensureSession).not.toHaveBeenCalled();
});
