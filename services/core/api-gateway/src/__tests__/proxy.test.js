'use strict';

jest.mock('http-proxy-middleware', () => ({ createProxyMiddleware: jest.fn(options => options) }));
const createProxy = require('../middleware/proxy');
const { createProxyMiddleware } = require('http-proxy-middleware');

beforeEach(() => jest.clearAllMocks());

test('all proxy responses keep gateway CORS authoritative without rewriting receiving status, ETag or other headers', () => {
  const response = { statusCode: 412, headers: { 'access-control-allow-origin': '*', 'Access-Control-Allow-Credentials': 'true',
    'access-control-expose-headers': '*', 'access-control-allow-private-network': 'true', etag: '"group-version-7"', 'cache-control': 'no-store', vary: 'Accept-Encoding' } };
  const outgoing = { getHeader: jest.fn(() => 'Origin') };
  const request = { headers: { authorization: 'Bearer original' } };
  const options = createProxy({ target: 'http://identity-service:3001', changeOrigin: true });
  options.onProxyRes(response, request, outgoing);
  expect(response).toEqual({ statusCode: 412, headers: { etag: '"group-version-7"', 'cache-control': 'no-store', vary: 'Origin, Accept-Encoding' } });
  expect(request.headers.authorization).toBe('Bearer original');
  expect(createProxyMiddleware).toHaveBeenCalledWith(expect.objectContaining({ target: 'http://identity-service:3001', changeOrigin: true }));
});

test('existing response hooks run but cannot restore backend CORS or erase gateway Vary', () => {
  const hook = jest.fn(response => { response.headers['access-control-allow-origin'] = 'https://unreviewed.test'; response.headers.vary = 'Accept-Encoding, origin'; });
  const response = { headers: {} }; const request = {}; const outgoing = { getHeader: () => ['Origin', 'Accept-Language'] };
  createProxy({ target: 'http://backend', onProxyRes: hook }).onProxyRes(response, request, outgoing);
  expect(hook).toHaveBeenCalledWith(response, request, outgoing); expect(response.headers).toEqual({ vary: 'origin, Accept-Language, Accept-Encoding' });
});

test.each([[undefined, undefined, undefined], ['Origin', '*', '*'], ['Origin', 'origin, Accept-Encoding', 'origin, Accept-Encoding']])('Vary merges safely without inventing cache equivalence: %j, %j', (local, remote, expected) => {
  const response = { headers: { ...(remote ? { vary: remote } : {}) } };
  createProxy({ target: 'http://backend' }).onProxyRes(response, {}, { getHeader: () => local });
  expect(response.headers.vary).toBe(expected);
});
