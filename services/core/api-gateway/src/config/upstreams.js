'use strict';

function configuredUpstreams(raw) {
  if (raw === undefined) return null;
  const upstreams = JSON.parse(raw);
  if (!Array.isArray(upstreams) || upstreams.length === 0 || upstreams.length > 64) throw new Error('GATEWAY_UPSTREAMS must be a non-empty array');
  const names = new Set();
  const paths = new Set();
  for (const upstream of upstreams) {
    if (!upstream || typeof upstream.name !== 'string' || !/^[a-z][a-z0-9-]*$/.test(upstream.name)
      || names.has(upstream.name) || typeof upstream.pathPrefix !== 'string'
      || !/^\/api\/[a-z][a-z0-9/-]*$/.test(upstream.pathPrefix) || paths.has(upstream.pathPrefix)) throw new Error('Invalid or duplicate gateway upstream');
    const target = new URL(upstream.target);
    if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password || target.pathname !== '/'
      || target.search || target.hash || !/^\/[a-zA-Z0-9-]+(?:\/[a-zA-Z0-9-]+)*$/.test(upstream.healthPath || '/health')) throw new Error('Invalid gateway upstream URL or health path');
    names.add(upstream.name);
    paths.add(upstream.pathPrefix);
  }
  return upstreams;
}

module.exports = { configuredUpstreams };
