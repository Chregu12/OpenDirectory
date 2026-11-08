'use strict';

const { configuredUpstreams } = require('../config/upstreams');
const upstream = { name: 'identity', target: 'http://opendirectory-identity-service:3001', pathPrefix: '/api/users' };

test('Kubernetes upstreams keep their actual DNS names and explicit health paths', () => {
  const configured = [{ ...upstream, healthPath: '/api/health' }];
  expect(configuredUpstreams(JSON.stringify(configured))).toEqual(configured);
  expect(configuredUpstreams(undefined)).toBeNull();
});

test.each([
  [], {}, [upstream, upstream],
  [{ ...upstream, target: 'file:///etc/passwd' }],
  [{ ...upstream, target: 'http://user:password@identity:3001' }],
  [{ ...upstream, target: 'http://identity:3001/api/users' }],
  [{ ...upstream, target: 'http://identity:3001?token=secret' }],
  [{ ...upstream, pathPrefix: '/api/../admin' }],
  [{ ...upstream, healthPath: '//other-server/health' }],
])('invalid or ambiguous configured routes fail at startup: %j', configured => {
  expect(() => configuredUpstreams(JSON.stringify(configured))).toThrow();
});
