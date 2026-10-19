'use strict';

const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = options => createProxyMiddleware({
  ...options,
  onProxyRes(response, request, outgoing) {
    options.onProxyRes?.(response, request, outgoing);
    for (const header of Object.keys(response.headers)) {
      if (header.toLowerCase().startsWith('access-control-')) delete response.headers[header];
    }
    const vary = new Map();
    for (const source of [outgoing.getHeader('Vary'), response.headers.vary]) {
      for (const header of (Array.isArray(source) ? source.join(',') : String(source || '')).split(',')) {
        const value = header.trim();
        if (value) vary.set(value.toLowerCase(), value);
      }
    }
    if (vary.size) response.headers.vary = vary.has('*') ? '*' : [...vary.values()].join(', ');
  },
});
